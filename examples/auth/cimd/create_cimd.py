"""Helper script to create CIMD documents programmatically.

This demonstrates the Python API for creating CIMD documents without using the CLI.

To run:
    python create_cimd.py
"""

import json

from fastmcp.server.auth import create_cimd_document

# Create a CIMD document using the helper function
print("Creating CIMD document...")
print("=" * 60)

cimd_doc = create_cimd_document(
    redirect_uris=[
        "https://myapp.example.com/callback",
        "http://localhost:8080/callback",  # Specific port for local development
    ],
    client_name="My Example Application",
    client_uri="https://myapp.example.com",
    logo_uri="https://myapp.example.com/logo.png",
    scope="read write delete",
    contacts=["admin@myapp.example.com", "support@myapp.example.com"],
)

# Convert to pretty JSON
json_str = json.dumps(cimd_doc, indent=2)

print("Generated CIMD document:\n")
print(json_str)
print("\n" + "=" * 60)

# Save to file
output_file = "example_cimd.json"
with open(output_file, "w") as f:
    f.write(json_str)

print(f"\n✓ Saved to {output_file}")
print("\nNext steps:")
print("1. Host this file at an HTTPS URL (e.g., https://myapp.example.com/cimd.json)")
print("2. Use that URL as your client_id when connecting to MCP servers")
print("3. No registration or secrets needed!")
print("\nValidate with:")
print(f"  fastmcp cimd validate {output_file} -v")
print("=" * 60)
