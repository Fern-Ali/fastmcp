"""Tests for CIMD (Client ID Metadata Documents) support."""

import time

import httpx
import pytest
from pydantic import ValidationError

from fastmcp.server.auth.cimd import (
    CIMD_CACHE_MAX_AGE_SECONDS,
    CIMDDocument,
    CIMDFetcher,
    CIMDTrustPolicy,
    create_cimd_document,
)


class TestCIMDDocument:
    """Tests for CIMDDocument model."""

    def test_minimal_valid_document(self):
        """Test minimal valid CIMD document with only required fields."""
        doc = CIMDDocument(redirect_uris=["https://example.com/callback"])
        assert len(doc.redirect_uris) == 1
        assert str(doc.redirect_uris[0]) == "https://example.com/callback"
        assert doc.client_name is None

    def test_full_valid_document(self):
        """Test CIMD document with all optional fields."""
        doc = CIMDDocument(
            redirect_uris=["https://example.com/callback"],
            client_name="Test Client",
            client_uri="https://example.com",
            logo_uri="https://example.com/logo.png",
            scope="read write",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            contacts=["admin@example.com"],
            tos_uri="https://example.com/tos",
            policy_uri="https://example.com/privacy",
        )
        assert doc.client_name == "Test Client"
        assert doc.scope == "read write"
        assert "admin@example.com" in doc.contacts

    def test_empty_redirect_uris_invalid(self):
        """Test that empty redirect_uris list is invalid."""
        with pytest.raises(ValidationError):
            CIMDDocument(redirect_uris=[])

    def test_invalid_email_in_contacts(self):
        """Test that invalid email addresses in contacts are rejected."""
        with pytest.raises(ValidationError, match="Invalid email address"):
            CIMDDocument(
                redirect_uris=["https://example.com/callback"],
                contacts=["not-an-email"],
            )

    def test_valid_multiple_contacts(self):
        """Test that multiple valid email contacts are accepted."""
        doc = CIMDDocument(
            redirect_uris=["https://example.com/callback"],
            contacts=["admin@example.com", "support@example.com"],
        )
        assert len(doc.contacts) == 2


class TestCIMDTrustPolicy:
    """Tests for CIMDTrustPolicy."""

    def test_empty_policy_trusts_nothing(self):
        """Test that empty policy doesn't trust any domain."""
        policy = CIMDTrustPolicy()
        assert not policy.is_trusted("https://example.com/cimd.json")
        assert not policy.is_trusted("https://claude.ai/cimd.json")

    def test_exact_domain_match(self):
        """Test exact domain matching."""
        policy = CIMDTrustPolicy(trusted_domains=["claude.ai", "cursor.com"])
        assert policy.is_trusted("https://claude.ai/cimd.json")
        assert policy.is_trusted("https://cursor.com/auth/cimd.json")
        assert not policy.is_trusted("https://example.com/cimd.json")

    def test_wildcard_subdomain_match(self):
        """Test wildcard subdomain matching."""
        policy = CIMDTrustPolicy(trusted_domains=["*.example.com"])
        assert policy.is_trusted("https://app.example.com/cimd.json")
        assert policy.is_trusted("https://auth.example.com/cimd.json")
        assert not policy.is_trusted("https://example.com/cimd.json")  # No subdomain
        assert not policy.is_trusted("https://other.com/cimd.json")

    def test_wildcard_full_domain(self):
        """Test wildcard matching entire domain."""
        policy = CIMDTrustPolicy(trusted_domains=["*"])
        assert policy.is_trusted("https://anything.com/cimd.json")
        assert policy.is_trusted("https://example.org/cimd.json")

    def test_blocked_domain_overrides_trusted(self):
        """Test that blocked domains take precedence over trusted."""
        policy = CIMDTrustPolicy(
            trusted_domains=["*.example.com"],
            blocked_domains=["malicious.example.com"],
        )
        assert policy.is_trusted("https://app.example.com/cimd.json")
        assert not policy.is_trusted("https://malicious.example.com/cimd.json")

    def test_case_insensitive_matching(self):
        """Test that domain matching is case-insensitive."""
        policy = CIMDTrustPolicy(trusted_domains=["Example.COM"])
        assert policy.is_trusted("https://example.com/cimd.json")
        assert policy.is_trusted("https://EXAMPLE.COM/cimd.json")


class TestCIMDFetcher:
    """Tests for CIMDFetcher."""

    def test_is_cimd_client_id_valid_https(self):
        """Test detection of valid CIMD URLs."""
        fetcher = CIMDFetcher()
        assert fetcher.is_cimd_client_id("https://example.com/cimd.json")
        assert fetcher.is_cimd_client_id("https://app.example.com/auth/client.json")

    def test_is_cimd_client_id_invalid(self):
        """Test rejection of invalid CIMD URLs."""
        fetcher = CIMDFetcher()
        assert not fetcher.is_cimd_client_id("http://example.com/cimd.json")  # HTTP
        assert not fetcher.is_cimd_client_id("just-a-string")
        assert not fetcher.is_cimd_client_id("")

    def test_validate_url_requires_https(self):
        """Test that only HTTPS URLs are accepted."""
        fetcher = CIMDFetcher()
        with pytest.raises(ValueError, match="must use HTTPS"):
            fetcher._validate_url("http://example.com/cimd.json")

    def test_validate_url_blocks_localhost(self):
        """Test SSRF protection for localhost."""
        fetcher = CIMDFetcher()
        with pytest.raises(ValueError, match="private DNS name"):
            fetcher._validate_url("https://localhost/cimd.json")

    def test_validate_url_blocks_local_tld(self):
        """Test SSRF protection for .local domains."""
        fetcher = CIMDFetcher()
        with pytest.raises(ValueError, match="private DNS name"):
            fetcher._validate_url("https://myapp.local/cimd.json")

    def test_validate_url_blocks_internal_domains(self):
        """Test SSRF protection for internal domains."""
        fetcher = CIMDFetcher()
        with pytest.raises(ValueError, match="private DNS name"):
            fetcher._validate_url("https://app.internal/cimd.json")

    def test_validate_url_blocks_private_ips(self):
        """Test SSRF protection for private IP addresses."""
        fetcher = CIMDFetcher()
        
        # IPv4 private ranges
        with pytest.raises(ValueError, match="private IP address"):
            fetcher._validate_url("https://192.168.1.1/cimd.json")
        
        with pytest.raises(ValueError, match="private IP address"):
            fetcher._validate_url("https://10.0.0.1/cimd.json")
        
        with pytest.raises(ValueError, match="private IP address"):
            fetcher._validate_url("https://172.16.0.1/cimd.json")
        
        with pytest.raises(ValueError, match="private IP address"):
            fetcher._validate_url("https://127.0.0.1/cimd.json")

    def test_validate_url_blocks_ipv6_loopback(self):
        """Test SSRF protection for IPv6 loopback."""
        fetcher = CIMDFetcher()
        with pytest.raises(ValueError, match="private IP address"):
            fetcher._validate_url("https://[::1]/cimd.json")

    def test_validate_url_allows_public_domain(self):
        """Test that public domains are allowed."""
        fetcher = CIMDFetcher()
        # Should not raise
        fetcher._validate_url("https://example.com/cimd.json")
        fetcher._validate_url("https://app.example.com/auth/client.json")

    def test_validate_url_respects_blocklist(self):
        """Test that blocked domains are rejected."""
        policy = CIMDTrustPolicy(blocked_domains=["malicious.com"])
        fetcher = CIMDFetcher(trust_policy=policy)
        
        with pytest.raises(ValueError, match="Domain is blocked"):
            fetcher._validate_url("https://malicious.com/cimd.json")

    @pytest.mark.asyncio
    async def test_fetch_valid_document(self, httpx_mock):
        """Test successful fetch of valid CIMD document."""
        cimd_url = "https://example.com/cimd.json"
        doc_data = {
            "redirect_uris": ["https://example.com/callback"],
            "client_name": "Test Client",
        }
        
        httpx_mock.add_response(url=cimd_url, json=doc_data)
        
        fetcher = CIMDFetcher()
        doc = await fetcher.fetch(cimd_url)
        
        assert doc.client_name == "Test Client"
        assert len(doc.redirect_uris) == 1

    @pytest.mark.asyncio
    async def test_fetch_caching(self, httpx_mock):
        """Test that fetched documents are cached."""
        cimd_url = "https://example.com/cimd.json"
        doc_data = {
            "redirect_uris": ["https://example.com/callback"],
            "client_name": "Test Client",
        }
        
        httpx_mock.add_response(url=cimd_url, json=doc_data)
        
        fetcher = CIMDFetcher()
        
        # First fetch
        doc1 = await fetcher.fetch(cimd_url)
        assert len(httpx_mock.get_requests()) == 1
        
        # Second fetch should use cache
        doc2 = await fetcher.fetch(cimd_url)
        assert len(httpx_mock.get_requests()) == 1  # No additional HTTP call
        
        assert doc1.client_name == doc2.client_name

    @pytest.mark.asyncio
    async def test_fetch_cache_expiry(self, httpx_mock):
        """Test that cache respects expiry time."""
        cimd_url = "https://example.com/cimd.json"
        doc_data = {
            "redirect_uris": ["https://example.com/callback"],
            "client_name": "Test Client",
        }
        
        # Return with short cache time
        httpx_mock.add_response(
            url=cimd_url,
            json=doc_data,
            headers={"Cache-Control": "max-age=1"}
        )
        
        fetcher = CIMDFetcher()
        
        # First fetch
        await fetcher.fetch(cimd_url)
        assert len(httpx_mock.get_requests()) == 1
        
        # Wait for cache to expire
        time.sleep(1.1)
        
        # Add second response for the re-fetch
        httpx_mock.add_response(url=cimd_url, json=doc_data)
        
        # Should fetch again
        await fetcher.fetch(cimd_url)
        assert len(httpx_mock.get_requests()) == 2

    @pytest.mark.asyncio
    async def test_fetch_respects_max_cache_time(self, httpx_mock):
        """Test that cache never exceeds 24hr per spec."""
        cimd_url = "https://example.com/cimd.json"
        doc_data = {
            "redirect_uris": ["https://example.com/callback"],
        }
        
        # Try to set very long cache time
        httpx_mock.add_response(
            url=cimd_url,
            json=doc_data,
            headers={"Cache-Control": "max-age=999999999"}
        )
        
        fetcher = CIMDFetcher()
        await fetcher.fetch(cimd_url)
        
        # Check that cached entry doesn't exceed 24hr
        cached = fetcher._get_cached(cimd_url)
        assert cached is not None
        max_allowed_expiry = time.time() + CIMD_CACHE_MAX_AGE_SECONDS + 1
        assert cached.expires_at <= max_allowed_expiry

    @pytest.mark.asyncio
    async def test_fetch_invalid_document(self, httpx_mock):
        """Test that invalid documents are rejected."""
        cimd_url = "https://example.com/cimd.json"
        
        # Missing required redirect_uris field
        httpx_mock.add_response(url=cimd_url, json={"client_name": "Test"})
        
        fetcher = CIMDFetcher()
        with pytest.raises(ValidationError):
            await fetcher.fetch(cimd_url)

    @pytest.mark.asyncio
    async def test_fetch_http_error(self, httpx_mock):
        """Test handling of HTTP errors."""
        cimd_url = "https://example.com/cimd.json"
        
        httpx_mock.add_response(url=cimd_url, status_code=404)
        
        fetcher = CIMDFetcher()
        with pytest.raises(httpx.HTTPStatusError):
            await fetcher.fetch(cimd_url)

    def test_clear_cache_specific(self):
        """Test clearing specific cached document."""
        fetcher = CIMDFetcher()
        fetcher._cache["https://example.com/cimd.json"] = None  # type: ignore
        fetcher._cache["https://other.com/cimd.json"] = None  # type: ignore
        
        fetcher.clear_cache("https://example.com/cimd.json")
        
        assert "https://example.com/cimd.json" not in fetcher._cache
        assert "https://other.com/cimd.json" in fetcher._cache

    def test_clear_cache_all(self):
        """Test clearing all cached documents."""
        fetcher = CIMDFetcher()
        fetcher._cache["https://example.com/cimd.json"] = None  # type: ignore
        fetcher._cache["https://other.com/cimd.json"] = None  # type: ignore
        
        fetcher.clear_cache()
        
        assert len(fetcher._cache) == 0

    def test_is_trusted_with_policy(self):
        """Test trust checking with policy."""
        policy = CIMDTrustPolicy(trusted_domains=["claude.ai"])
        fetcher = CIMDFetcher(trust_policy=policy)
        
        assert fetcher.is_trusted("https://claude.ai/cimd.json")
        assert not fetcher.is_trusted("https://example.com/cimd.json")


class TestCreateCIMDDocument:
    """Tests for create_cimd_document helper."""

    def test_minimal_document(self):
        """Test creating minimal document."""
        doc = create_cimd_document(
            redirect_uris=["https://example.com/callback"]
        )
        
        assert "redirect_uris" in doc
        assert doc["redirect_uris"] == ["https://example.com/callback"]
        assert "client_name" not in doc

    def test_full_document(self):
        """Test creating document with all fields."""
        doc = create_cimd_document(
            redirect_uris=["https://example.com/callback"],
            client_name="Test Client",
            client_uri="https://example.com",
            logo_uri="https://example.com/logo.png",
            scope="read write",
            grant_types=["authorization_code"],
            response_types=["code"],
            contacts=["admin@example.com"],
            tos_uri="https://example.com/tos",
            policy_uri="https://example.com/privacy",
        )
        
        assert doc["client_name"] == "Test Client"
        assert doc["scope"] == "read write"
        assert doc["contacts"] == ["admin@example.com"]

    def test_document_validation(self):
        """Test that created documents are validated."""
        with pytest.raises(ValidationError):
            # Invalid: empty redirect_uris
            create_cimd_document(redirect_uris=[])

    def test_document_serializable(self):
        """Test that created document can be JSON serialized."""
        import json
        
        doc = create_cimd_document(
            redirect_uris=["https://example.com/callback"],
            client_name="Test Client",
        )
        
        # Should not raise
        json_str = json.dumps(doc)
        assert "redirect_uris" in json_str
