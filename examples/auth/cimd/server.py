"""CIMD OAuth server example for FastMCP.

This example demonstrates how to configure a FastMCP server with CIMD support
for OAuth authentication. CIMD allows clients to use HTTPS URLs as their
client_id, eliminating manual registration.

Required environment variables:
- FASTMCP_SERVER_AUTH_UPSTREAM_CLIENT_ID: Your OAuth provider's client ID
- FASTMCP_SERVER_AUTH_UPSTREAM_CLIENT_SECRET: Your OAuth provider's client secret
- FASTMCP_SERVER_AUTH_AUTHORIZATION_ENDPOINT: Provider's authorization endpoint
- FASTMCP_SERVER_AUTH_TOKEN_ENDPOINT: Provider's token endpoint

To run:
    python server.py
"""

import os

from fastmcp import FastMCP
from fastmcp.server.auth import CIMDTrustPolicy, OAuthProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier

# Configure token verification for your OAuth provider
# This example uses a generic JWT verifier - adjust for your provider
token_verifier = JWTVerifier(
    jwks_uri=os.getenv("FASTMCP_SERVER_AUTH_JWKS_URI")
    or "https://github.com/.well-known/jwks.json",
    issuer=os.getenv("FASTMCP_SERVER_AUTH_ISSUER") or "https://github.com",
    audience=os.getenv("FASTMCP_SERVER_AUTH_AUDIENCE") or "your-app-id",
)

# Create OAuth proxy with CIMD support
auth = OAuthProxy(
    # Your OAuth provider's endpoints
    upstream_authorization_endpoint=os.getenv("FASTMCP_SERVER_AUTH_AUTHORIZATION_ENDPOINT")
    or "https://github.com/login/oauth/authorize",
    upstream_token_endpoint=os.getenv("FASTMCP_SERVER_AUTH_TOKEN_ENDPOINT")
    or "https://github.com/login/oauth/access_token",
    # Your registered app credentials with the provider
    upstream_client_id=os.getenv("FASTMCP_SERVER_AUTH_UPSTREAM_CLIENT_ID") or "",
    upstream_client_secret=os.getenv("FASTMCP_SERVER_AUTH_UPSTREAM_CLIENT_SECRET") or "",
    # Token verification
    token_verifier=token_verifier,
    # Server's public URL
    base_url="http://localhost:8000",
    # CIMD trust policy - configure which domains to trust
    cimd_trust_policy=CIMDTrustPolicy(
        # Automatically approve these trusted domains
        trusted_domains=[
            "claude.ai",
            "cursor.com",
            "*.example.com",  # Wildcards supported
        ],
        auto_approve_trusted=True,  # Skip consent screen for trusted domains
        # Block these domains even if they match a pattern
        blocked_domains=["malicious.com"],
    ),
)

mcp = FastMCP("CIMD OAuth Example Server", auth=auth)


@mcp.tool
def echo(message: str) -> str:
    """Echo the provided message.

    This tool requires authentication via CIMD or traditional DCR.
    """
    return f"Echo: {message}"


@mcp.tool
def get_weather(city: str) -> str:
    """Get weather information for a city.

    This tool requires authentication via CIMD or traditional DCR.
    """
    return f"Weather in {city}: Sunny, 72°F"


if __name__ == "__main__":
    print("🚀 Starting CIMD OAuth Example Server")
    print("=" * 50)
    print("Server supports both CIMD and traditional DCR clients")
    print("\nCIMD clients can use HTTPS URLs as their client_id:")
    print("  • https://myapp.com/cimd.json")
    print("  • https://myapp.com/.well-known/cimd.json")
    print("\nTrusted domains will be auto-approved:")
    print("  • claude.ai")
    print("  • cursor.com")
    print("  • *.example.com")
    print("=" * 50)

    mcp.run(transport="http", port=8000)
