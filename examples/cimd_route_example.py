"""
Example demonstrating CIMDRoute for self-hosting CIMD documents.

This example shows how to use CIMDRoute to self-host a Client Identity
Metadata Document (CIMD) when your FastMCP server needs to act as a client
to upstream MCP servers that require CIMD authentication.

Run with: fastmcp run cimd_route_example.py
"""

from fastmcp import FastMCP
from fastmcp.client.auth import CIMDRoute

# Create a FastMCP server
mcp = FastMCP("CIMD Example Server")


# Add a simple tool to demonstrate the server is working
@mcp.tool()
def greet(name: str) -> str:
    """Greet someone by name."""
    return f"Hello, {name}!"


# Self-host CIMD document for this server
# This allows the server to act as an MCP client to upstream servers
cimd = CIMDRoute(
    client_name="CIMD Example Server",
    redirect_uris=[
        "http://localhost:*/callback",  # Wildcard port for dynamic allocation
        "http://127.0.0.1:*/callback",
    ],
    client_uri="http://localhost:8000",
    scope="read write",
)

# Add the CIMD route to the server
# The document will be available at: /.well-known/mcp-client.json
mcp._additional_http_routes.append(cimd.route)

if __name__ == "__main__":
    # When running with `fastmcp run`, the server starts automatically
    # You can then access the CIMD document at:
    # http://localhost:8000/.well-known/mcp-client.json
    import uvicorn

    # Create HTTP app
    app = mcp.http_app()

    # Run the server
    uvicorn.run(app, host="0.0.0.0", port=8000)
