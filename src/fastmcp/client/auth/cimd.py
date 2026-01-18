"""CIMD (Client Identity Metadata Document) route helper for FastMCP servers."""

from __future__ import annotations

from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

__all__ = ["CIMDRoute"]


class CIMDRoute:
    """
    Helper to self-host a CIMD (Client Identity Metadata Document) on a FastMCP server.

    When a FastMCP server acts as an MCP client to upstream servers requiring CIMD
    authentication, it needs to host its own CIMD document. This helper makes it easy
    to serve the required `/.well-known/mcp-client.json` endpoint.

    The CIMD document follows the MCP OAuth specification and includes client metadata
    like client name, redirect URIs, and other OAuth client information.

    Example:
        ```python
        from fastmcp import FastMCP
        from fastmcp.client.auth import CIMDRoute

        mcp = FastMCP("My Aggregator")

        # Self-host CIMD document
        cimd_route = CIMDRoute(
            client_name="My Aggregator",
            redirect_uris=["http://localhost:*/callback"],
            client_uri="https://my-aggregator.com",
        )
        mcp._additional_http_routes.append(cimd_route.route)

        # Now use that URL as your client identity when connecting to upstream servers
        ```
    """

    def __init__(
        self,
        client_name: str,
        redirect_uris: list[str],
        client_uri: str | None = None,
        grant_types: list[str] | None = None,
        response_types: list[str] | None = None,
        scope: str | None = None,
        path: str = "/.well-known/mcp-client.json",
        **additional_metadata: Any,
    ):
        """
        Initialize CIMD route configuration.

        Args:
            client_name: Name of the client application
            redirect_uris: List of allowed redirect URIs. Supports wildcards like
                "http://localhost:*/callback" for dynamic ports.
            client_uri: Optional URI for the client's home page
            grant_types: OAuth grant types supported. Defaults to
                ["authorization_code", "refresh_token"]
            response_types: OAuth response types supported. Defaults to ["code"]
            scope: Space-separated OAuth scopes. Optional.
            path: Path to serve the CIMD document. Defaults to
                "/.well-known/mcp-client.json"
            **additional_metadata: Additional fields to include in the CIMD document
        """
        self.path = path

        # Set defaults for OAuth fields
        if grant_types is None:
            grant_types = ["authorization_code", "refresh_token"]
        if response_types is None:
            response_types = ["code"]

        # Build client metadata document
        # Store as dict to support wildcards in redirect_uris like "http://localhost:*/callback"
        # which are valid in MCP OAuth but not parseable by URL validators
        self.client_metadata: dict[str, Any] = {
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
        }

        if client_uri is not None:
            self.client_metadata["client_uri"] = client_uri

        if scope is not None:
            self.client_metadata["scope"] = scope

        # Add any additional metadata
        self.client_metadata.update(additional_metadata)

        # Create the route
        self.route = Route(
            self.path,
            endpoint=self._handle_request,
            methods=["GET"],
            name="cimd",
            include_in_schema=True,
        )

    async def _handle_request(self, request: Request) -> Response:
        """Handle CIMD document request."""
        # Return the metadata as JSON, filtering out None values
        filtered_metadata = {k: v for k, v in self.client_metadata.items() if v is not None}
        return JSONResponse(filtered_metadata)
