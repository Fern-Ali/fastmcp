"""Example client demonstrating CIMD usage with FastMCP.

This example shows how a client can use a CIMD document (hosted at an HTTPS URL)
as its client_id, eliminating the need for manual registration.

To run:
    python client.py
"""

from fastmcp import FastMCP

# In production, you would use a real HTTPS URL where your CIMD document is hosted
# For example: "https://myapp.com/cimd.json"
#
# For this demo, we'll show the concept. In a real scenario:
# 1. Create your CIMD document: fastmcp cimd create --name "My App" --redirect-uri "https://myapp.com/callback" -o cimd.json
# 2. Host it at an HTTPS URL (e.g., https://myapp.com/cimd.json)
# 3. Use that URL as your client_id

# Example CIMD URL (would be your actual hosted document in production)
CIMD_CLIENT_ID = "https://myapp.example.com/cimd.json"

# Create a client
# In a real implementation, you would connect to a remote server that supports CIMD
mcp = FastMCP("CIMD Example Client")


@mcp.tool
async def connect_to_server():
    """Connect to a CIMD-enabled server.

    This demonstrates the concept of using a CIMD document as client_id.
    In production, you would use the MCP client SDK to connect.
    """
    print("=" * 60)
    print("🔗 Connecting to MCP server with CIMD authentication")
    print("=" * 60)
    print(f"\nClient ID (CIMD URL): {CIMD_CLIENT_ID}")
    print("\nHow CIMD works:")
    print("1. Client provides URL as client_id (not a random string)")
    print("2. Server fetches the CIMD document from that URL")
    print("3. Server validates the document and checks trust policy")
    print("4. If trusted, server may auto-approve (skip consent)")
    print("5. OAuth flow proceeds normally with verified metadata")
    print("\nBenefits:")
    print("✓ No manual registration needed")
    print("✓ No client secrets to manage")
    print("✓ Domain ownership verification")
    print("✓ Easy multi-server support")
    print("=" * 60)

    return "Connected successfully!"


if __name__ == "__main__":
    print("\n📱 CIMD Client Example")
    print("-" * 60)
    print("This example demonstrates the CIMD (Client ID Metadata")
    print("Documents) approach to OAuth authentication.")
    print("-" * 60)
    print("\n💡 Key Concept:")
    print("Instead of:")
    print("  client_id = 'random-uuid-abc-123'")
    print("  client_secret = 'super-secret-value'")
    print("\nUse:")
    print("  client_id = 'https://myapp.com/cimd.json'")
    print("  # No secret needed!")
    print("-" * 60)
    print("\n🔨 To create your own CIMD document:")
    print("  fastmcp cimd create \\")
    print("    --name 'My Application' \\")
    print("    --redirect-uri 'https://myapp.com/callback' \\")
    print("    --client-uri 'https://myapp.com' \\")
    print("    -o cimd.json")
    print("\n📤 Then host it at an HTTPS URL and use that URL as client_id")
    print("-" * 60)
    print("\nRun the connection demo:\n")

    import asyncio

    asyncio.run(connect_to_server())
