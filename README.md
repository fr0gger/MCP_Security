# ORKL MCP Server

![MIT License](https://img.shields.io/badge/license-MIT-green)

A full write-up can be found here: https://blog.securitybreak.io/building-a-threat-intelligence-genai-reporter-with-orkl-and-claude-a0ae2e969693

A Model Context Protocol (MCP) server for querying the ORKL API. This server provides tools for fetching and analyzing threat reports, threat actors, and sources. It integrates smoothly with MCP-compatible applications.

---
# Quick Install
Edit or create the file /Users/user/Library/Application Support/Claude/claude_desktop_config.json
```
{
  "mcpServers": {
    "orkl": {
      "command": "uv",
      "args": [
      "--directory",
      "/MyMCP/mcptest/orkl",
      "run",
      "orkl"
      ]
    }
  }
}
```
---

# Tools

## Report Tools

### Fetch Latest Threat Reports
- **Name**: `fetch_latest_threat_reports`
- **Description**: Fetch recent threat reports with their titles and IDs.
- **Parameters**: None

### Fetch Threat Report Details
- **Name**: `fetch_threat_report_details`
- **Description**: Retrieve detailed information for a specific threat report by ID.
- **Parameters**:
  - `report_id` (required): The ID of the threat report.

## Threat Actor Tools

### Fetch Threat Actors
- **Name**: `fetch_threat_actors`
- **Description**: Fetch a list of known threat actors with their IDs and names.
- **Parameters**: None

### Fetch Threat Actor Details
- **Name**: `fetch_threat_actor_details`
- **Description**: Retrieve detailed information for a specific threat actor by ID.
- **Parameters**:
  - `actor_id` (required): The ID of the threat actor.

## Source Tools

### Fetch Sources
- **Name**: `fetch_sources`
- **Description**: Fetch a list of sources used in threat intelligence.
- **Parameters**: None

### Fetch Source Details
- **Name**: `fetch_source_details`
- **Description**: Retrieve detailed metadata for a specific source by ID.
- **Parameters**:
  - `source_id` (required): The ID of the source.


