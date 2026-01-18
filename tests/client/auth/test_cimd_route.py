"""Tests for CIMD (Client Identity Metadata Document) route."""

import json

import httpx
import pytest
from starlette.requests import Request
from starlette.routing import Route

from fastmcp import FastMCP
from fastmcp.client.auth import CIMDRoute
from fastmcp.utilities.http import find_available_port
from fastmcp.utilities.tests import run_server_async


class TestCIMDRoute:
    """Test suite for CIMDRoute helper."""

    def test_cimd_route_creation(self):
        """Test that CIMDRoute creates a valid route."""
        cimd = CIMDRoute(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            client_uri="https://example.com",
        )

        assert cimd.path == "/.well-known/mcp-client.json"
        assert isinstance(cimd.route, Route)
        assert cimd.route.path == "/.well-known/mcp-client.json"
        assert "GET" in cimd.route.methods

    def test_cimd_metadata_fields(self):
        """Test that client metadata is correctly stored."""
        cimd = CIMDRoute(
            client_name="My Client",
            redirect_uris=["http://localhost:*/callback", "https://app.com/callback"],
            client_uri="https://example.com",
            scope="read write",
        )

        metadata = cimd.client_metadata
        assert metadata["client_name"] == "My Client"
        assert len(metadata["redirect_uris"]) == 2
        assert metadata["grant_types"] == ["authorization_code", "refresh_token"]
        assert metadata["response_types"] == ["code"]
        assert metadata["scope"] == "read write"

    def test_cimd_custom_grant_types(self):
        """Test custom grant types and response types."""
        cimd = CIMDRoute(
            client_name="Custom Client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=["implicit"],
            response_types=["token"],
        )

        metadata = cimd.client_metadata
        assert metadata["grant_types"] == ["implicit"]
        assert metadata["response_types"] == ["token"]

    def test_cimd_custom_path(self):
        """Test custom path for CIMD document."""
        cimd = CIMDRoute(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            path="/custom/client-metadata.json",
        )

        assert cimd.path == "/custom/client-metadata.json"
        assert cimd.route.path == "/custom/client-metadata.json"

    def test_cimd_additional_metadata(self):
        """Test additional metadata fields."""
        cimd = CIMDRoute(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            logo_uri="https://example.com/logo.png",
            contacts=["admin@example.com"],
        )

        # Additional fields should be in the metadata dict
        assert "logo_uri" in cimd.client_metadata
        assert "contacts" in cimd.client_metadata

    async def test_cimd_endpoint_response(self):
        """Test that the CIMD endpoint returns valid JSON."""
        cimd = CIMDRoute(
            client_name="Test Client",
            redirect_uris=["http://localhost:8080/callback"],
            client_uri="https://example.com",
            scope="read write",
        )

        # Create a mock request
        from starlette.datastructures import Headers

        scope = {
            "type": "http",
            "method": "GET",
            "path": cimd.path,
            "query_string": b"",
            "headers": [],
        }
        request = Request(scope)

        # Call the handler
        response = await cimd._handle_request(request)

        # Check response
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"

        # Parse JSON body
        body = response.body.decode("utf-8")
        data = json.loads(body)

        # Verify structure
        assert data["client_name"] == "Test Client"
        assert len(data["redirect_uris"]) == 1
        assert data["redirect_uris"][0] == "http://localhost:8080/callback"
        assert data["grant_types"] == ["authorization_code", "refresh_token"]
        assert data["response_types"] == ["code"]
        assert data["scope"] == "read write"
        assert data["client_uri"] == "https://example.com"

    async def test_cimd_integration_with_fastmcp(self):
        """Test integration of CIMDRoute with FastMCP server."""
        port = find_available_port()
        server = FastMCP("Test Server")

        # Add CIMD route
        cimd = CIMDRoute(
            client_name="Test Aggregator",
            redirect_uris=[f"http://localhost:{port}/callback"],
            client_uri=f"http://localhost:{port}",
        )
        server._additional_http_routes.append(cimd.route)

        # Start server and test endpoint
        async with run_server_async(server, port=port, transport="http") as base_url:
            async with httpx.AsyncClient() as client:
                # CIMD document is served at root level, not under /mcp mount
                # Extract the scheme and host:port from base_url
                # base_url is something like "http://127.0.0.1:56537/mcp"
                parts = base_url.split("/")
                root_url = f"{parts[0]}//{parts[2]}"
                
                # Request CIMD document at root level
                response = await client.get(
                    f"{root_url}/.well-known/mcp-client.json"
                )

                assert response.status_code == 200
                data = response.json()

                # Verify content
                assert data["client_name"] == "Test Aggregator"
                assert len(data["redirect_uris"]) == 1
                assert f"http://localhost:{port}/callback" in data["redirect_uris"][0]

    async def test_cimd_excludes_none_values(self):
        """Test that None values are excluded from the JSON response."""
        cimd = CIMDRoute(
            client_name="Minimal Client",
            redirect_uris=["http://localhost:8080/callback"],
            # Don't provide client_uri or scope
        )

        # Create a mock request
        from starlette.datastructures import Headers

        scope = {
            "type": "http",
            "method": "GET",
            "path": cimd.path,
            "query_string": b"",
            "headers": [],
        }
        request = Request(scope)

        response = await cimd._handle_request(request)
        body = response.body.decode("utf-8")
        data = json.loads(body)

        # client_uri and scope should not be in the response
        assert "client_uri" not in data
        assert "scope" not in data or data["scope"] is None

    def test_cimd_wildcard_redirect_uris(self):
        """Test that wildcard redirect URIs are accepted."""
        cimd = CIMDRoute(
            client_name="Test Client",
            redirect_uris=[
                "http://localhost:*/callback",
                "http://127.0.0.1:*/callback",
            ],
        )

        assert len(cimd.client_metadata["redirect_uris"]) == 2

    async def test_cimd_multiple_routes_same_server(self):
        """Test that multiple FastMCP servers can each have their own CIMD route."""
        port = find_available_port()
        server1 = FastMCP("Server 1")
        server2 = FastMCP("Server 2")

        # Add different CIMD routes
        cimd1 = CIMDRoute(
            client_name="Client 1",
            redirect_uris=["http://localhost:8080/callback"],
        )
        cimd2 = CIMDRoute(
            client_name="Client 2",
            redirect_uris=["http://localhost:9090/callback"],
        )

        server1._additional_http_routes.append(cimd1.route)
        server2._additional_http_routes.append(cimd2.route)

        # Test first server
        async with run_server_async(server1, port=port, transport="http") as base_url:
            async with httpx.AsyncClient() as client:
                # Extract root URL
                parts = base_url.split("/")
                root_url = f"{parts[0]}//{parts[2]}"
                
                response = await client.get(
                    f"{root_url}/.well-known/mcp-client.json"
                )
                data = response.json()
                assert data["client_name"] == "Client 1"
