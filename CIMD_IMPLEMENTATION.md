# CIMD Implementation Summary

## Overview
This PR implements complete support for CIMD (Client ID Metadata Documents) in FastMCP, providing a simpler alternative to Dynamic Client Registration (DCR) for OAuth authentication.

## What is CIMD?
CIMD allows OAuth clients to use HTTPS URLs as their `client_id`, with the URL pointing to a JSON document describing the client's metadata. This eliminates the need for:
- Manual client registration
- Client secrets management
- Registration endpoint implementations

The client simply hosts a static JSON file at an HTTPS URL and uses that URL as their `client_id`.

## Implementation Details

### 1. Core Models (`src/fastmcp/server/auth/cimd.py`)

**CIMDDocument**
- Pydantic model per IETF draft-ietf-oauth-client-id-metadata-document
- Required fields: `redirect_uris`
- Optional fields: `client_name`, `client_uri`, `logo_uri`, `scope`, `grant_types`, `contacts`, etc.
- Full validation including email validation for contacts

**CIMDFetcher**
- HTTP/HTTPS fetching with timeout (10s)
- Caching with HTTP cache header respect (max 24hr per spec)
- SSRF protection:
  - Blocks private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)
  - Blocks loopback addresses (127.0.0.1, ::1)
  - Blocks private DNS patterns (localhost, *.local, *.internal, *.lan)
  - Blocks IPv6 private ranges
- Domain validation (HTTPS-only)
- In-memory caching with expiry

**CIMDTrustPolicy**
- Domain-based trust configuration
- Wildcard pattern matching (e.g., `*.example.com`)
- Blocked domains list (takes precedence over trusted)
- Auto-approval flag for trusted clients
- Case-insensitive domain matching

### 2. OAuthProxy Integration (`src/fastmcp/server/auth/oauth_proxy.py`)

**New Constructor Parameter**
```python
cimd_trust_policy: CIMDTrustPolicy | None = None
```

**Modified Methods**
- `get_client()`: Detects URL-formatted client_ids and fetches CIMD documents
  - Traditional DCR clients loaded from storage
  - CIMD clients loaded dynamically via HTTP
  - Both work seamlessly side-by-side

**Enhanced Consent Screen**
- Verified domain badge for CIMD clients (green badge with domain)
- Visual distinction between CIMD and DCR clients
- Domain displayed prominently for verification

**Auto-Approval Logic**
- Trusted CIMD clients can skip consent screen
- Configurable via `CIMDTrustPolicy.auto_approve_trusted`
- Domain-based trust decisions

### 3. CLI Tools (`src/fastmcp/cli/cimd.py`)

**`fastmcp cimd create`**
- Generate valid CIMD documents
- Validates all fields
- Outputs to file or stdout
- Syntax highlighting for console output

**`fastmcp cimd validate`**
- Validate existing CIMD documents
- Detailed error messages
- Verbose mode for full document inspection

### 4. Helper Functions

**`create_cimd_document()`**
- Programmatic CIMD document generation
- Full validation
- Returns dict ready for JSON serialization

## Security Features

### SSRF Protection
- ✅ Blocks localhost and loopback addresses
- ✅ Blocks private IP ranges (RFC 1918)
- ✅ Blocks private DNS patterns (.local, .internal, .lan)
- ✅ Blocks link-local addresses
- ✅ HTTPS-only requirement

### Caching
- ✅ Respects HTTP cache headers
- ✅ Maximum 24-hour cache per spec
- ✅ In-memory caching with expiry
- ✅ Per-document cache clearing

### Domain Validation
- ✅ HTTPS URLs only
- ✅ Valid hostname required
- ✅ Blocklist support
- ✅ Trust policy integration

## Test Coverage

### Unit Tests (34 tests)
- CIMDDocument validation (5 tests)
- CIMDTrustPolicy behavior (6 tests)
- CIMDFetcher functionality (13 tests)
  - URL validation
  - SSRF protection
  - HTTP fetching
  - Caching behavior
  - Error handling
- Helper functions (4 tests)
- Security validations (6 tests)

### Integration Tests (5 tests)
- CIMD client registration via OAuthProxy
- Trust policy auto-approval
- CIMD vs DCR client coexistence
- Invalid URL handling
- Caching across multiple requests

### Regression Tests
- All 41 existing OAuth proxy tests pass
- No breaking changes to existing functionality

## Usage Examples

### Server-Side
```python
from fastmcp.server.auth import OAuthProxy, CIMDTrustPolicy

proxy = OAuthProxy(
    upstream_authorization_endpoint="https://idp.example.com/authorize",
    upstream_token_endpoint="https://idp.example.com/token",
    upstream_client_id="my-upstream-client",
    upstream_client_secret="my-secret",
    token_verifier=verifier,
    base_url="https://server.example.com",
    cimd_trust_policy=CIMDTrustPolicy(
        trusted_domains=["claude.ai", "cursor.com"],
        auto_approve_trusted=True,
        blocked_domains=["malicious.com"],
    ),
)
```

### Client-Side
```bash
# Create a CIMD document
fastmcp cimd create \
  --name "My Application" \
  --redirect-uri "https://app.example.com/callback" \
  --client-uri "https://app.example.com" \
  --contact "admin@example.com" \
  --output cimd.json

# Validate it
fastmcp cimd validate cimd.json --verbose

# Host it at https://app.example.com/cimd.json
# Use that URL as your client_id - no registration needed!
```

### Programmatic Document Creation
```python
from fastmcp.server.auth import create_cimd_document
import json

doc = create_cimd_document(
    redirect_uris=["https://app.example.com/callback"],
    client_name="My Application",
    client_uri="https://app.example.com",
    scope="read write",
    contacts=["admin@example.com"],
)

# Save to file
with open("cimd.json", "w") as f:
    json.dump(doc, f, indent=2)
```

## Benefits

### For Server Operators
- No manual client registration required
- Verified domain badges increase trust
- Configure trust policies for known clients
- Auto-approve trusted domains
- Reduce support burden

### For Client Developers
- Skip DCR entirely
- No secrets to manage or rotate
- Simple JSON file hosting
- Domain ownership verification
- Easier multi-server support

## Spec Compliance
- ✅ IETF draft-ietf-oauth-client-id-metadata-document
- ✅ MCP SEP-991
- ✅ OAuth 2.1 compatible
- ✅ 24-hour maximum cache per spec

## Files Changed
- `src/fastmcp/server/auth/cimd.py` (new, 600+ lines)
- `src/fastmcp/server/auth/oauth_proxy.py` (120 lines modified)
- `src/fastmcp/server/auth/__init__.py` (exports added)
- `src/fastmcp/cli/cimd.py` (new, 220+ lines)
- `src/fastmcp/cli/cli.py` (CIMD CLI integration)
- `tests/server/auth/test_cimd.py` (new, 550+ lines, 39 tests)

## Test Results
```
============================== 80 passed in 7.45s ==============================
```
- 39 CIMD tests (34 unit + 5 integration)
- 41 OAuth proxy tests (regression)
- 100% pass rate
- Type checking clean
