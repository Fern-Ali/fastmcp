"""FastMCP CIMD CLI for creating and validating Client ID Metadata Documents."""

import json
import sys
from pathlib import Path
from typing import Annotated

import cyclopts
from pydantic import ValidationError
from rich.console import Console
from rich.syntax import Syntax

from fastmcp.server.auth.cimd import CIMDDocument, create_cimd_document
from fastmcp.utilities.logging import get_logger

logger = get_logger("cli.cimd")
console = Console()

cimd_app = cyclopts.App(
    name="cimd",
    help="Create and validate CIMD (Client ID Metadata Documents) for OAuth",
)


@cimd_app.command
def create(
    name: Annotated[
        str | None,
        cyclopts.Parameter(
            help="Human-readable name of the client application",
        ),
    ] = None,
    redirect_uri: Annotated[
        list[str],
        cyclopts.Parameter(
            help="Authorized redirect URI (can be used multiple times). Supports wildcards like http://localhost:*/callback",
        ),
    ] = [],
    client_uri: Annotated[
        str | None,
        cyclopts.Parameter(
            help="URL of the client application's homepage",
        ),
    ] = None,
    logo_uri: Annotated[
        str | None,
        cyclopts.Parameter(
            help="URL to the client application's logo image",
        ),
    ] = None,
    scope: Annotated[
        str | None,
        cyclopts.Parameter(
            help="Space-separated list of OAuth scopes the client will use",
        ),
    ] = None,
    contact: Annotated[
        list[str] | None,
        cyclopts.Parameter(
            help="Contact email address (can be used multiple times)",
        ),
    ] = None,
    output: Annotated[
        str | None,
        cyclopts.Parameter(
            name=["--output", "-o"],
            help="Output file path. If not specified, prints to stdout",
        ),
    ] = None,
) -> None:
    """Create a new CIMD document.

    CIMD (Client ID Metadata Documents) allows OAuth clients to use HTTPS URLs
    as their client_id, with the URL pointing to a JSON document describing
    the client's metadata. This is a simpler alternative to Dynamic Client
    Registration (DCR).

    Example:
        fastmcp cimd create \\
            --name "My Application" \\
            --redirect-uri "https://app.example.com/callback" \\
            --redirect-uri "http://localhost:*/callback" \\
            --client-uri "https://app.example.com" \\
            --output cimd.json

        # Then host the file at https://app.example.com/cimd.json
        # and use that URL as your client_id when connecting to MCP servers
    """
    # Validate that at least one redirect URI is provided
    if not redirect_uri:
        console.print(
            "[bold red]Error:[/bold red] At least one --redirect-uri is required"
        )
        console.print("\nExample:")
        console.print(
            "  fastmcp cimd create --redirect-uri https://app.example.com/callback"
        )
        sys.exit(1)

    try:
        # Create the CIMD document
        doc = create_cimd_document(
            redirect_uris=redirect_uri,
            client_name=name,
            client_uri=client_uri,
            logo_uri=logo_uri,
            scope=scope,
            contacts=contact,
        )

        # Format as pretty JSON
        json_str = json.dumps(doc, indent=2, sort_keys=False)

        if output:
            # Write to file
            output_path = Path(output)
            output_path.write_text(json_str)
            console.print(f"[bold green]✓[/bold green] CIMD document created: {output}")
            console.print("\n[bold]Next steps:[/bold]")
            console.print(
                "1. Host this file at an HTTPS URL (e.g., https://example.com/cimd.json)"
            )
            console.print(
                "2. Use that URL as your client_id when connecting to MCP servers"
            )
            console.print(
                "\n[dim]The URL becomes your client_id - no registration needed![/dim]"
            )
        else:
            # Print to stdout with syntax highlighting
            syntax = Syntax(json_str, "json", theme="monokai", line_numbers=False)
            console.print(syntax)
            console.print("\n[dim]Tip: Use -o/--output to save to a file[/dim]")

    except ValidationError as e:
        console.print("[bold red]Error:[/bold red] Invalid CIMD document")
        console.print(str(e))
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)


@cimd_app.command
def validate(
    file: Annotated[
        str,
        cyclopts.Parameter(
            help="Path to CIMD document file to validate",
        ),
    ],
    verbose: Annotated[
        bool,
        cyclopts.Parameter(
            name=["--verbose", "-v"],
            help="Show detailed validation information",
        ),
    ] = False,
) -> None:
    """Validate an existing CIMD document.

    Checks that a CIMD JSON file is valid according to the IETF specification
    and reports any errors or warnings.

    Example:
        fastmcp cimd validate cimd.json
        fastmcp cimd validate --verbose cimd.json
    """
    file_path = Path(file)

    if not file_path.exists():
        console.print(f"[bold red]Error:[/bold red] File not found: {file}")
        sys.exit(1)

    try:
        # Read and parse JSON
        content = file_path.read_text()
        data = json.loads(content)

        # Validate against CIMD model
        doc = CIMDDocument.model_validate(data)

        # Success!
        console.print(f"[bold green]✓[/bold green] Valid CIMD document: {file}")

        if verbose:
            console.print("\n[bold]Document details:[/bold]")

            if doc.client_name:
                console.print(f"  Client name: {doc.client_name}")

            console.print(f"  Redirect URIs ({len(doc.redirect_uris)}):")
            for uri in doc.redirect_uris:
                console.print(f"    • {uri}")

            if doc.client_uri:
                console.print(f"  Homepage: {doc.client_uri}")

            if doc.logo_uri:
                console.print(f"  Logo: {doc.logo_uri}")

            if doc.scope:
                console.print(f"  Scopes: {doc.scope}")

            if doc.grant_types:
                console.print(f"  Grant types: {', '.join(doc.grant_types)}")

            if doc.contacts:
                console.print(f"  Contacts: {', '.join(doc.contacts)}")

        console.print("\n[bold]Next steps:[/bold]")
        console.print(
            "1. Host this file at an HTTPS URL (e.g., https://example.com/cimd.json)"
        )
        console.print(
            "2. Use that URL as your client_id when connecting to MCP servers"
        )
        console.print(
            "\n[dim]The file should be served with Content-Type: application/json[/dim]"
        )

    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid JSON: {e}")
        sys.exit(1)
    except ValidationError as e:
        console.print("[bold red]Error:[/bold red] Invalid CIMD document")
        console.print("\n[bold]Validation errors:[/bold]")
        for error in e.errors():
            field = " -> ".join(str(x) for x in error["loc"])
            console.print(f"  • {field}: {error['msg']}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        sys.exit(1)
