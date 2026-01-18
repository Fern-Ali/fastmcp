# CIMD (Client ID Metadata Documents) Example

Demonstrates FastMCP server with CIMD support for OAuth authentication.

## Overview

CIMD allows OAuth clients to use HTTPS URLs as their `client_id`, eliminating the need for manual client registration. The client simply hosts a JSON document at an HTTPS URL and uses that URL as their identifier.

## What You'll Learn

- How to create CIMD documents using the CLI
- How to configure a server with CIMD trust policies
- How to use CIMD documents as client identifiers
- How domain verification and trust policies work

## Setup

### 1. Create a CIMD Document

Use the FastMCP CLI to create a CIMD document:

```bash
# Create with basic info
fastmcp cimd create \
  --name "My Application" \
  --redirect-uri "http://localhost:8080/callback" \
  --redirect-uri "http://localhost:3000/callback" \
  --client-uri "https://myapp.com" \
  --contact "admin@myapp.com" \
  -o cimd.json

# Validate it
fastmcp cimd validate cimd.json -v
```

### 2. Host Your CIMD Document

In production, you would host this file at an HTTPS URL:
- `https://myapp.com/cimd.json`
- `https://myapp.com/.well-known/cimd.json`
- Any HTTPS URL you control

For this example, we'll use a local file path for demonstration purposes.

### 3. Set Environment Variables

```bash
# Your OAuth provider credentials (GitHub, Google, etc.)
export FASTMCP_SERVER_AUTH_UPSTREAM_CLIENT_ID="your-provider-client-id"
export FASTMCP_SERVER_AUTH_UPSTREAM_CLIENT_SECRET="your-provider-secret"

# Provider endpoints
export FASTMCP_SERVER_AUTH_AUTHORIZATION_ENDPOINT="https://github.com/login/oauth/authorize"
export FASTMCP_SERVER_AUTH_TOKEN_ENDPOINT="https://github.com/login/oauth/access_token"
```

### 4. Run the Server

```bash
python server.py
```

### 5. Test with the Client

```bash
python client.py
```

## How It Works

### Server Side

The server (`server.py`) uses `OAuthProxy` with a `CIMDTrustPolicy`:

```python
auth = OAuthProxy(
    upstream_authorization_endpoint="...",
    upstream_token_endpoint="...",
    upstream_client_id="your-upstream-client",
    upstream_client_secret="your-secret",
    token_verifier=verifier,
    base_url="http://localhost:8000",
    cimd_trust_policy=CIMDTrustPolicy(
        # Auto-approve these trusted domains
        trusted_domains=["claude.ai", "cursor.com", "*.mycompany.com"],
        auto_approve_trusted=True,
        # Block malicious domains
        blocked_domains=["evil.com"],
    ),
)
```

### Client Side

Instead of registering with DCR, the client uses a URL as its `client_id`:

```python
# Traditional way (with registration):
# client_id = "abc123-random-id"

# CIMD way (no registration needed):
client_id = "https://myapp.com/cimd.json"
```

The server fetches the CIMD document from that URL to verify:
- The domain is legitimate (HTTPS required)
- The redirect URIs are authorized
- The client metadata is valid

### Trust Policies

Servers can configure trust policies to:
- **Auto-approve** known clients (like `claude.ai`, `cursor.com`)
- **Block** malicious domains
- **Use wildcards** for patterns like `*.mycompany.com`

## Security Features

CIMD includes built-in protections:

- **SSRF Protection**: Blocks private IPs, localhost, internal domains
- **HTTPS Only**: HTTP URLs are rejected
- **Caching**: Respects HTTP headers, max 24-hour cache
- **Validation**: Full JSON validation per IETF spec

## Files

- `README.md` - This file
- `server.py` - FastMCP server with CIMD support
- `client.py` - Example client using CIMD
- `create_cimd.py` - Helper to programmatically create CIMD documents
- `example_cimd.json` - Sample CIMD document

## Learn More

- [CIMD Documentation](/servers/auth/cimd)
- [OAuth Proxy Documentation](/servers/auth/oauth-proxy)
- [MCP SEP-991](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/991)
- [IETF Draft Spec](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)
