"""Client ID Metadata Document (CIMD) support for OAuth.

This module implements CIMD (Client ID Metadata Documents) per the IETF
draft-ietf-oauth-client-id-metadata-document specification. CIMD allows OAuth
clients to use HTTPS URLs as their client_id, with the URL pointing to a JSON
document describing the client's metadata.

CIMD provides a simpler alternative to Dynamic Client Registration (DCR):
- No registration endpoint needed
- No client secrets to manage
- Domain ownership verification via HTTPS hosting
- Static JSON file hosted on client's domain

Security considerations:
- HTTPS-only URLs (no HTTP for security)
- SSRF protection (blocks private/loopback addresses)
- HTTP cache header respect with 24hr maximum per spec
- Domain validation and blocklist support
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Final
from urllib.parse import urlparse

import httpx
from pydantic import AnyHttpUrl, BaseModel, Field, field_validator

from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)

# CIMD specification constants
CIMD_CACHE_MAX_AGE_SECONDS: Final[int] = 24 * 60 * 60  # 24 hours per spec
CIMD_FETCH_TIMEOUT_SECONDS: Final[int] = 10

# Private IP ranges for SSRF protection (RFC 1918 + loopback + link-local)
PRIVATE_IP_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),  # Private class A
    ipaddress.ip_network("172.16.0.0/12"),  # Private class B
    ipaddress.ip_network("192.168.0.0/16"),  # Private class C
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]

# Reserved/private DNS patterns
PRIVATE_DNS_PATTERNS = [
    r"localhost",
    r".*\.local$",
    r".*\.internal$",
    r".*\.lan$",
]


class CIMDDocument(BaseModel):
    """Client ID Metadata Document per IETF draft-ietf-oauth-client-id-metadata-document.

    This model represents the OAuth client metadata that can be hosted at an
    HTTPS URL. The URL itself serves as the client_id.

    Required fields per spec:
    - redirect_uris: List of authorized redirect URIs

    Common optional fields:
    - client_name: Human-readable client name
    - client_uri: Client's homepage URL
    - logo_uri: URL to client logo
    - scope: Space-separated list of requested scopes
    - grant_types: Authorized grant types
    - response_types: Authorized response types
    - contacts: Administrative contact emails

    Example CIMD document:
    ```json
    {
        "redirect_uris": ["https://app.example.com/callback"],
        "client_name": "My Application",
        "client_uri": "https://app.example.com",
        "logo_uri": "https://app.example.com/logo.png",
        "scope": "read write",
        "contacts": ["admin@example.com"]
    }
    ```
    """

    # Required fields
    redirect_uris: list[AnyHttpUrl] = Field(
        ...,
        description="List of authorized redirect URIs for this client",
        min_length=1,
    )

    # Common optional fields per OAuth 2.0 Dynamic Client Registration spec
    client_name: str | None = Field(
        default=None,
        description="Human-readable name of the client",
        max_length=200,
    )
    client_uri: AnyHttpUrl | None = Field(
        default=None,
        description="URL of the client's homepage",
    )
    logo_uri: AnyHttpUrl | None = Field(
        default=None,
        description="URL to the client's logo image",
    )
    scope: str | None = Field(
        default=None,
        description="Space-separated list of OAuth scopes the client will use",
    )
    grant_types: list[str] | None = Field(
        default=None,
        description="OAuth grant types the client will use",
    )
    response_types: list[str] | None = Field(
        default=None,
        description="OAuth response types the client will use",
    )
    contacts: list[str] | None = Field(
        default=None,
        description="Contact email addresses for the client administrators",
    )
    tos_uri: AnyHttpUrl | None = Field(
        default=None,
        description="URL to the client's terms of service",
    )
    policy_uri: AnyHttpUrl | None = Field(
        default=None,
        description="URL to the client's privacy policy",
    )

    @field_validator("contacts")
    @classmethod
    def validate_contacts(cls, v: list[str] | None) -> list[str] | None:
        """Validate that contacts are valid email addresses."""
        if v is not None:
            email_pattern = re.compile(
                r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            )
            for contact in v:
                if not email_pattern.match(contact):
                    raise ValueError(f"Invalid email address in contacts: {contact}")
        return v


class CachedCIMDDocument(BaseModel):
    """Cached CIMD document with metadata."""

    document: CIMDDocument
    fetched_at: float  # Unix timestamp
    expires_at: float  # Unix timestamp
    client_id: str  # The URL used as client_id


class CIMDTrustPolicy(BaseModel):
    """Trust policy for CIMD clients.

    Allows server operators to configure which CIMD clients should be
    automatically trusted, enabling features like auto-approval of consent.

    Examples:
        # Trust specific domains
        policy = CIMDTrustPolicy(
            trusted_domains=["claude.ai", "cursor.com"],
            auto_approve_trusted=True,
        )

        # Trust with domain blocklist
        policy = CIMDTrustPolicy(
            trusted_domains=["*.example.com"],
            blocked_domains=["malicious.com"],
        )
    """

    trusted_domains: list[str] = Field(
        default_factory=list,
        description="List of trusted domain patterns (supports wildcards like *.example.com)",
    )
    auto_approve_trusted: bool = Field(
        default=False,
        description="Whether to automatically approve consent for trusted CIMD clients",
    )
    blocked_domains: list[str] = Field(
        default_factory=list,
        description="List of blocked domain patterns (takes precedence over trusted_domains)",
    )

    def is_trusted(self, client_id: str) -> bool:
        """Check if a client_id URL is from a trusted domain.

        Args:
            client_id: The HTTPS URL used as client_id

        Returns:
            True if the domain is trusted and not blocked
        """
        try:
            parsed = urlparse(client_id)
            domain = parsed.hostname or ""

            # Check if blocked first
            if self._matches_patterns(domain, self.blocked_domains):
                return False

            # Check if trusted
            return self._matches_patterns(domain, self.trusted_domains)
        except Exception:
            return False

    def _matches_patterns(self, domain: str, patterns: list[str]) -> bool:
        """Check if domain matches any pattern in the list.

        Supports wildcards like *.example.com
        """
        for pattern in patterns:
            # Convert wildcard pattern to regex
            regex_pattern = pattern.replace(".", r"\.").replace("*", ".*")
            if re.match(f"^{regex_pattern}$", domain, re.IGNORECASE):
                return True
        return False


class CIMDFetcher:
    """Fetches and caches CIMD documents with security protections.

    This class handles:
    - HTTPS-only fetching (no HTTP)
    - SSRF protection (blocks private/loopback IPs)
    - HTTP cache header respect (max 24hr per spec)
    - Document validation
    - In-memory caching

    Example:
        fetcher = CIMDFetcher()
        doc = await fetcher.fetch("https://client.example.com/cimd.json")
        print(f"Client: {doc.client_name}")
        print(f"Redirects to: {doc.redirect_uris}")
    """

    def __init__(
        self,
        trust_policy: CIMDTrustPolicy | None = None,
        blocked_domains: list[str] | None = None,
    ):
        """Initialize CIMD fetcher.

        Args:
            trust_policy: Optional trust policy for domain-based decisions
            blocked_domains: Additional domains to block (merged with trust policy blocklist)
        """
        self._cache: dict[str, CachedCIMDDocument] = {}
        self._trust_policy = trust_policy or CIMDTrustPolicy()

        # Merge blocked domains
        if blocked_domains:
            self._trust_policy.blocked_domains.extend(blocked_domains)

    async def fetch(self, client_id: str) -> CIMDDocument:
        """Fetch and validate a CIMD document from the given URL.

        Args:
            client_id: HTTPS URL pointing to the CIMD document

        Returns:
            Validated CIMD document

        Raises:
            ValueError: If URL is invalid, not HTTPS, or points to private IP
            httpx.HTTPError: If fetching fails
            ValidationError: If document is invalid
        """
        # Check cache first
        cached = self._get_cached(client_id)
        if cached is not None:
            logger.debug("Using cached CIMD document for %s", client_id)
            return cached.document

        # Validate URL format
        self._validate_url(client_id)

        # Fetch document with timeout
        async with httpx.AsyncClient(timeout=CIMD_FETCH_TIMEOUT_SECONDS) as client:
            logger.debug("Fetching CIMD document from %s", client_id)
            response = await client.get(client_id, follow_redirects=True)
            response.raise_for_status()

            # Parse and validate document
            doc_data = response.json()
            document = CIMDDocument.model_validate(doc_data)

            # Calculate cache expiry from HTTP headers
            expires_at = self._calculate_expiry(response)

            # Cache the document
            cached_doc = CachedCIMDDocument(
                document=document,
                fetched_at=time.time(),
                expires_at=expires_at,
                client_id=client_id,
            )
            self._cache[client_id] = cached_doc

            logger.info(
                "Fetched and cached CIMD document for %s (expires at %s)",
                client_id,
                time.ctime(expires_at),
            )
            return document

    def _validate_url(self, url: str) -> None:
        """Validate that URL is HTTPS and doesn't point to private networks.

        Args:
            url: URL to validate

        Raises:
            ValueError: If URL is invalid or points to private/loopback address
        """
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {url}") from e

        # Must be HTTPS for security
        if parsed.scheme != "https":
            raise ValueError(
                f"CIMD client_id must use HTTPS, got {parsed.scheme}: {url}"
            )

        # Get hostname
        hostname = parsed.hostname
        if not hostname:
            raise ValueError(f"Invalid hostname in URL: {url}")

        # Check domain blocklist
        if self._trust_policy._matches_patterns(
            hostname, self._trust_policy.blocked_domains
        ):
            raise ValueError(f"Domain is blocked: {hostname}")

        # SSRF protection: block private DNS patterns
        for pattern in PRIVATE_DNS_PATTERNS:
            if re.match(pattern, hostname, re.IGNORECASE):
                raise ValueError(
                    f"CIMD client_id cannot use private DNS name: {hostname}"
                )

        # SSRF protection: block private IP ranges
        try:
            # Resolve hostname to IP (this will fail for invalid domains)
            # Note: In production, you might want to use a proper DNS resolver
            # with timeout to avoid DNS rebinding attacks
            ip = ipaddress.ip_address(hostname)
            for private_range in PRIVATE_IP_RANGES:
                if ip in private_range:
                    raise ValueError(
                        f"CIMD client_id cannot point to private IP address: {ip}"
                    )
        except ValueError as e:
            # If hostname is not an IP address, that's fine - it's a domain name
            # We rely on the DNS patterns check above for domain-based SSRF protection
            if "does not appear to be" not in str(e):
                raise

    def _calculate_expiry(self, response: httpx.Response) -> float:
        """Calculate cache expiry time from HTTP headers.

        Per CIMD spec, caches MUST NOT cache for longer than 24 hours.

        Args:
            response: HTTP response with cache headers

        Returns:
            Unix timestamp when cache should expire
        """
        max_age = CIMD_CACHE_MAX_AGE_SECONDS
        current_time = time.time()

        # Check Cache-Control header
        cache_control = response.headers.get("cache-control", "")
        if "max-age=" in cache_control:
            try:
                # Extract max-age value
                max_age_match = re.search(r"max-age=(\d+)", cache_control)
                if max_age_match:
                    header_max_age = int(max_age_match.group(1))
                    # Respect header but cap at 24 hours per spec
                    max_age = min(header_max_age, CIMD_CACHE_MAX_AGE_SECONDS)
            except (ValueError, AttributeError):
                pass

        return current_time + max_age

    def _get_cached(self, client_id: str) -> CachedCIMDDocument | None:
        """Get cached document if available and not expired.

        Args:
            client_id: CIMD URL

        Returns:
            Cached document or None if not cached or expired
        """
        cached = self._cache.get(client_id)
        if cached is None:
            return None

        # Check if expired
        if time.time() > cached.expires_at:
            logger.debug("Cached CIMD document expired for %s", client_id)
            del self._cache[client_id]
            return None

        return cached

    def is_cimd_client_id(self, client_id: str) -> bool:
        """Check if a client_id appears to be a CIMD URL.

        Args:
            client_id: Potential CIMD URL

        Returns:
            True if client_id looks like an HTTPS URL
        """
        try:
            parsed = urlparse(client_id)
            return parsed.scheme == "https" and bool(parsed.netloc)
        except Exception:
            return False

    def is_trusted(self, client_id: str) -> bool:
        """Check if a CIMD client is trusted per the trust policy.

        Args:
            client_id: CIMD URL

        Returns:
            True if the client's domain is trusted
        """
        return self._trust_policy.is_trusted(client_id)

    def clear_cache(self, client_id: str | None = None) -> None:
        """Clear cached CIMD documents.

        Args:
            client_id: Specific URL to clear, or None to clear all
        """
        if client_id is not None:
            self._cache.pop(client_id, None)
        else:
            self._cache.clear()


def create_cimd_document(
    redirect_uris: list[str],
    client_name: str | None = None,
    client_uri: str | None = None,
    logo_uri: str | None = None,
    scope: str | None = None,
    grant_types: list[str] | None = None,
    response_types: list[str] | None = None,
    contacts: list[str] | None = None,
    tos_uri: str | None = None,
    policy_uri: str | None = None,
) -> dict[str, Any]:
    """Create a CIMD document as a dictionary.

    This is a helper function for generating valid CIMD documents that can be
    serialized to JSON and hosted at an HTTPS URL.

    Args:
        redirect_uris: List of authorized redirect URIs (required)
        client_name: Human-readable client name
        client_uri: Client homepage URL
        logo_uri: URL to client logo
        scope: Space-separated OAuth scopes
        grant_types: List of authorized grant types
        response_types: List of authorized response types
        contacts: List of admin contact emails
        tos_uri: URL to terms of service
        policy_uri: URL to privacy policy

    Returns:
        Dictionary representing a valid CIMD document

    Example:
        doc = create_cimd_document(
            redirect_uris=["https://app.example.com/callback"],
            client_name="My Application",
            client_uri="https://app.example.com",
            scope="read write",
        )
        # Save as JSON and host at https://app.example.com/cimd.json
    """
    # Build document with only non-None fields
    doc: dict[str, Any] = {"redirect_uris": redirect_uris}

    if client_name is not None:
        doc["client_name"] = client_name
    if client_uri is not None:
        doc["client_uri"] = client_uri
    if logo_uri is not None:
        doc["logo_uri"] = logo_uri
    if scope is not None:
        doc["scope"] = scope
    if grant_types is not None:
        doc["grant_types"] = grant_types
    if response_types is not None:
        doc["response_types"] = response_types
    if contacts is not None:
        doc["contacts"] = contacts
    if tos_uri is not None:
        doc["tos_uri"] = tos_uri
    if policy_uri is not None:
        doc["policy_uri"] = policy_uri

    # Validate by creating a CIMDDocument instance
    CIMDDocument.model_validate(doc)

    return doc
