import asyncio
from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl
import mcp.types as types
import mcp.server.stdio
import httpx
import json

# ORKL API Base Configuration
ORKL_BASE_URL = "https://orkl.eu/api/v1"

# Initialize the MCP server
server = Server("orkl")

# Cache for threat reports and threat actors
cache = {
    "threat_reports": {},  # {id: details}
    "threat_actors": {},   # {id: details}
    "sources": {}          # {id: details}
}


@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """
    List all available resources, including threat reports, threat actors, and sources.
    """
    resources = []

    # Add threat reports
    resources.extend([
        types.Resource(
            uri=AnyUrl(f"threat://report/{report_id}"),
            name=f"Threat Report: {details['title']}",
            description=f"Threat report titled {details['title']}",
            mimeType="application/json",
        )
        for report_id, details in cache["threat_reports"].items()
    ])

    # Add threat actors
    resources.extend([
        types.Resource(
            uri=AnyUrl(f"threat://actor/{actor_id}"),
            name=f"Threat Actor: {details['main_name']}",
            description=f"Threat actor known as {details['main_name']}",
            mimeType="application/json",
        )
        for actor_id, details in cache["threat_actors"].items()
    ])

    # Add sources
    resources.extend([
        types.Resource(
            uri=AnyUrl(f"threat://source/{source_id}"),
            name=f"Source: {details['name']}",
            description=f"Source {details['name']}",
            mimeType="application/json",
        )
        for source_id, details in cache["sources"].items()
    ])

    return resources


@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    """
    Read a specific resource's content by its URI.
    """
    if uri.scheme != "threat":
        raise ValueError(f"Unsupported URI scheme: {uri.scheme}")

    path_parts = uri.path.strip("/").split("/")
    resource_type, resource_id = path_parts[0], path_parts[1]

    if resource_type == "report":
        return json.dumps(cache["threat_reports"].get(resource_id, {}), indent=2)
    elif resource_type == "actor":
        return json.dumps(cache["threat_actors"].get(resource_id, {}), indent=2)
    elif resource_type == "source":
        return json.dumps(cache["sources"].get(resource_id, {}), indent=2)
    else:
        raise ValueError(f"Unknown resource type: {resource_type}")


@server.list_tools()
async def list_tools() -> list[types.Tool]:
    """
    List tools to interact with ORKL API.
    """
    return [
        types.Tool(
            name="fetch_latest_threat_reports",
            description="Fetch the latest threat reports from ORKL.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="fetch_threat_report_details",
            description="Fetch detailed information for a specific threat report by ID.",
            inputSchema={
                "type": "object",
                "properties": {"report_id": {"type": "string", "description": "The ID of the threat report to fetch."}},
                "required": ["report_id"],
            },
        ),
        types.Tool(
            name="fetch_threat_actors",
            description="Fetch the list of threat actors.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="fetch_threat_actor_details",
            description="Fetch detailed information for a specific threat actor by ID.",
            inputSchema={
                "type": "object",
                "properties": {"actor_id": {"type": "string", "description": "The ID of the threat actor to fetch."}},
                "required": ["actor_id"],
            },
        ),
        types.Tool(
            name="fetch_sources",
            description="Fetch the list of sources.",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="fetch_source_details",
            description="Fetch detailed information for a specific source by ID.",
            inputSchema={
                "type": "object",
                "properties": {"source_id": {"type": "string", "description": "The ID of the source to fetch."}},
                "required": ["source_id"],
            },
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict[str, str] | None) -> list[types.TextContent]:
    """
    Handle tool execution requests for interacting with the ORKL API.
    """
    async with httpx.AsyncClient() as client:
        if name == "fetch_latest_threat_reports":
            response = await client.get(f"{ORKL_BASE_URL}/library/entries?limit=5&order_by=created_at&order=desc")
            if response.status_code == 200:
                reports = response.json().get("data", [])
                for report in reports:
                    cache["threat_reports"][report["id"]] = report
                return [
                    types.TextContent(
                        type="text",
                        text="\n".join([f"ID: {report['id']}, Title: {report['title']}" for report in reports]),
                    )
                ]
            return [types.TextContent(type="text", text=f"Error: {response.status_code} {response.text}")]

        elif name == "fetch_threat_report_details":
            report_id = arguments.get("report_id")
            if not report_id:
                raise ValueError("report_id is required.")
            response = await client.get(f"{ORKL_BASE_URL}/library/entry/{report_id}")
            if response.status_code == 200:
                report_details = response.json().get("data", {})
                cache["threat_reports"][report_id] = report_details
                return [
                    types.TextContent(type="text", text=json.dumps(report_details, indent=2))
                ]
            return [types.TextContent(type="text", text=f"Error: {response.status_code} {response.text}")]

        elif name == "fetch_threat_actors":
            response = await client.get(f"{ORKL_BASE_URL}/ta/entries")
            if response.status_code == 200:
                actors = response.json().get("data", [])
                for actor in actors:
                    cache["threat_actors"][actor["id"]] = actor
                return [
                    types.TextContent(
                        type="text",
                        text="\n".join([f"ID: {actor['id']}, Name: {actor['main_name']}" for actor in actors]),
                    )
                ]
            return [types.TextContent(type="text", text=f"Error: {response.status_code} {response.text}")]

        elif name == "fetch_threat_actor_details":
            actor_id = arguments.get("actor_id")
            if not actor_id:
                raise ValueError("actor_id is required.")
            response = await client.get(f"{ORKL_BASE_URL}/ta/entry/{actor_id}")
            if response.status_code == 200:
                actor_details = response.json().get("data", {})
                cache["threat_actors"][actor_id] = actor_details
                return [
                    types.TextContent(type="text", text=json.dumps(actor_details, indent=2))
                ]
            return [types.TextContent(type="text", text=f"Error: {response.status_code} {response.text}")]

        elif name == "fetch_sources":
            response = await client.get(f"{ORKL_BASE_URL}/source/entries")
            if response.status_code == 200:
                sources = response.json().get("data", [])
                for source in sources:
                    cache["sources"][source["id"]] = source
                return [
                    types.TextContent(
                        type="text",
                        text="\n".join([f"ID: {source['id']}, Name: {source['name']}" for source in sources]),
                    )
                ]
            return [types.TextContent(type="text", text=f"Error: {response.status_code} {response.text}")]

        elif name == "fetch_source_details":
            source_id = arguments.get("source_id")
            if not source_id:
                raise ValueError("source_id is required.")
            response = await client.get(f"{ORKL_BASE_URL}/source/entry/{source_id}")
            if response.status_code == 200:
                source_details = response.json().get("data", {})
                cache["sources"][source_id] = source_details
                return [
                    types.TextContent(type="text", text=json.dumps(source_details, indent=2))
                ]
            return [types.TextContent(type="text", text=f"Error: {response.status_code} {response.text}")]

        raise ValueError(f"Unknown tool: {name}")


async def main():
    """Start the MCP server."""
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="orkl",
                server_version="0.2",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

