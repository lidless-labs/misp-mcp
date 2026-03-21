# misp-mcp

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green.svg)](https://nodejs.org/)
[![MCP SDK](https://img.shields.io/badge/MCP%20SDK-1.x-purple.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An MCP (Model Context Protocol) server for [MISP](https://www.misp-project.org/) (Malware Information Sharing Platform & Threat Intelligence Sharing). Enables LLMs to perform IOC lookups, manage events, discover correlations, and export threat intelligence directly from your MISP instance.

## Features

- **36 MCP Tools** covering events, attributes, correlations, tags, exports, sightings, warninglists, objects, galaxies, feeds, organisations, and server management
- **3 MCP Resources** for browsing attribute types, instance statistics, and available taxonomies
- **3 MCP Prompts** for guided IOC investigation, incident event creation, and threat reporting
- **SSL Flexibility** for self-signed certificates common in MISP deployments
- **Export Formats** including CSV, STIX, Suricata, Snort, text, RPZ, and hash lists
- **MITRE ATT&CK Integration** via galaxy cluster search and attachment
- **Bulk Operations** for adding multiple IOCs to events in a single call
- **Correlation Engine** for discovering cross-event relationships through shared indicators

## Prerequisites

- Node.js 20 or later
- A running MISP instance with API access
- MISP API key (generated from MISP UI: Administration > List Auth Keys)

## Installation

```bash
git clone https://github.com/solomonneas/misp-mcp.git
cd misp-mcp
npm install
npm run build
```

## Configuration

Set the following environment variables:

```bash
export MISP_URL=https://misp.example.com
export MISP_API_KEY=your-api-key-here
export MISP_VERIFY_SSL=true  # Set to 'false' for self-signed certificates
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MISP_URL` | Yes | - | MISP instance base URL |
| `MISP_API_KEY` | Yes | - | API authentication key |
| `MISP_VERIFY_SSL` | No | `true` | Set `false` for self-signed certs |
| `MISP_TIMEOUT` | No | `30` | Request timeout in seconds |

## Usage

### Claude Desktop

Add to your Claude Desktop MCP config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "misp": {
      "command": "node",
      "args": ["/path/to/misp-mcp/dist/index.js"],
      "env": {
        "MISP_URL": "https://misp.example.com",
        "MISP_API_KEY": "your-api-key-here",
        "MISP_VERIFY_SSL": "false"
      }
    }
  }
}
```

### OpenClaw

Add to your `openclaw.json` MCP servers:

```json
{
  "mcp": {
    "servers": {
      "misp": {
        "command": "node",
        "args": ["/path/to/misp-mcp/dist/index.js"],
        "env": {
          "MISP_URL": "https://misp.example.com",
          "MISP_API_KEY": "your-api-key-here",
          "MISP_VERIFY_SSL": "false"
        }
      }
    }
  }
}
```

### Standalone

```bash
MISP_URL=https://misp.example.com MISP_API_KEY=your-key node dist/index.js
```

### Docker

```bash
docker build -t misp-mcp .
docker run -e MISP_URL=https://misp.example.com -e MISP_API_KEY=your-key -e MISP_VERIFY_SSL=false misp-mcp
```

### Development

```bash
MISP_URL=https://misp.example.com MISP_API_KEY=your-key npm run dev
```

## Tools Reference

### Event Tools (6)

| Tool | Description |
|------|-------------|
| `misp_search_events` | Search events by IOC value, type, tags, date range, organization |
| `misp_get_event` | Get full event details including attributes, objects, galaxies, related events |
| `misp_create_event` | Create a new event with threat level, distribution, and analysis status |
| `misp_update_event` | Update event metadata (info, threat level, analysis, publish state) |
| `misp_publish_event` | Publish an event to trigger alerts to sharing partners |
| `misp_tag_event` | Add or remove tags (TLP, MITRE ATT&CK, custom) from an event |

### Attribute Tools (4)

| Tool | Description |
|------|-------------|
| `misp_search_attributes` | Search IOCs across all events with type, category, and correlation filters |
| `misp_add_attribute` | Add a single IOC to an event |
| `misp_add_attributes_bulk` | Add multiple IOCs to an event in one operation |
| `misp_delete_attribute` | Soft or hard delete an attribute |

### Correlation & Intelligence Tools (3)

| Tool | Description |
|------|-------------|
| `misp_correlate` | Find all events and attributes matching a value, with cross-event correlations |
| `misp_get_related_events` | Discover events related through shared IOCs |
| `misp_describe_types` | Get all available attribute types and category mappings |

### Tag & Taxonomy Tools (2)

| Tool | Description |
|------|-------------|
| `misp_list_tags` | List available tags with usage statistics |
| `misp_search_by_tag` | Find events or attributes by tag |

### Export Tools (2)

| Tool | Description |
|------|-------------|
| `misp_export_iocs` | Export IOCs in CSV, STIX, Suricata, Snort, text, or RPZ format |
| `misp_export_hashes` | Export file hashes (MD5, SHA1, SHA256) for HIDS integration |

### Sighting & Warninglist Tools (2)

| Tool | Description |
|------|-------------|
| `misp_add_sighting` | Report a sighting, false positive, or expiration for an IOC |
| `misp_check_warninglists` | Check if a value appears on known benign/false positive lists |

### Object Tools (4)

| Tool | Description |
|------|-------------|
| `misp_list_object_templates` | List available MISP object templates (file, domain-ip, email, etc.) |
| `misp_get_object_template` | Get template details with required/optional attributes |
| `misp_add_object` | Add a structured object (grouped attributes) to an event |
| `misp_delete_object` | Delete an object from an event |

### Galaxy Tools (4)

| Tool | Description |
|------|-------------|
| `misp_list_galaxies` | List galaxies (MITRE ATT&CK, threat actors, malware, tools, etc.) |
| `misp_get_galaxy` | Get galaxy details with all clusters |
| `misp_search_galaxy_clusters` | Search clusters by keyword (find ATT&CK techniques, threat actors) |
| `misp_attach_galaxy_cluster` | Attach a cluster (ATT&CK technique, etc.) to an event or attribute |

### Feed Tools (4)

| Tool | Description |
|------|-------------|
| `misp_list_feeds` | List configured threat intel feeds |
| `misp_toggle_feed` | Enable or disable a feed |
| `misp_fetch_feed` | Trigger a fetch/pull from a feed |
| `misp_cache_feed` | Cache feed data locally for correlation |

### Organisation Tools (2)

| Tool | Description |
|------|-------------|
| `misp_list_organisations` | List local and remote sharing partner organisations |
| `misp_get_organisation` | Get organisation details |

### Server & Admin Tools (3)

| Tool | Description |
|------|-------------|
| `misp_server_status` | Get MISP version, permissions, and diagnostics |
| `misp_list_sharing_groups` | List sharing groups for controlled distribution |
| `misp_delete_event` | Delete a MISP event |

## Resources

| Resource URI | Description |
|-------------|-------------|
| `misp://types` | All supported attribute types, categories, and their mappings |
| `misp://statistics` | MISP instance statistics |
| `misp://taxonomies` | Available taxonomies (TLP, MITRE ATT&CK, etc.) |

## Prompts

| Prompt | Description |
|--------|-------------|
| `investigate-ioc` | Deep IOC investigation: search, correlate, check warninglists, summarize threat context |
| `create-incident-event` | Guided event creation from an incident description with IOC ingestion |
| `threat-report` | Generate a threat intelligence report from MISP data |

## Usage Examples

### Search for an IOC

> "Search MISP for the IP address 203.0.113.50"

Uses `misp_search_events` and `misp_search_attributes` to find all events and attributes referencing this IP.

### Investigate a suspicious domain

> "Investigate evil-domain.com in MISP"

Triggers the `investigate-ioc` prompt workflow: searches for the domain, checks correlations, queries warninglists, and provides a structured threat assessment.

### Create an incident event

> "Create a MISP event for a phishing campaign targeting our finance team. The phishing emails came from attacker@evil.com and linked to https://evil-login.com/harvest"

Uses `misp_create_event` followed by `misp_add_attributes_bulk` to create a fully populated event.

### Export Suricata rules

> "Export all IOCs from the last 7 days as Suricata rules"

Uses `misp_export_iocs` with format "suricata" and last "7d".

### Check for false positives

> "Is 8.8.8.8 on any MISP warninglists?"

Uses `misp_check_warninglists` to verify if the value is a known benign indicator.

### Find MITRE ATT&CK techniques

> "Search for phishing techniques in MITRE ATT&CK"

Uses `misp_search_galaxy_clusters` to find relevant ATT&CK techniques, then `misp_attach_galaxy_cluster` to link them to events.

### Add structured objects

> "Add a file object to event 1 with filename encrypt.exe, SHA256 hash, and file size"

Uses `misp_add_object` with the "file" template to create a structured group of related attributes.

## Supported Attribute Types

| Type | Category | Example |
|------|----------|---------|
| `ip-src` | Network activity | Source IP address |
| `ip-dst` | Network activity | Destination IP address |
| `domain` | Network activity | Domain name |
| `hostname` | Network activity | Hostname |
| `url` | Network activity | Full URL |
| `email-src` | Payload delivery | Sender email address |
| `md5` | Payload delivery | MD5 file hash |
| `sha1` | Payload delivery | SHA1 file hash |
| `sha256` | Payload delivery | SHA256 file hash |
| `filename` | Payload delivery | File name |

Use `misp_describe_types` for the complete list of supported types and categories.

## Testing

```bash
npm test                # Unit tests (55 tests, mocked)
npm run test:integration  # Integration tests against live MISP (27 tests)
npm run test:watch      # Watch mode
npm run lint            # Type check
```

Integration tests require `MISP_URL`, `MISP_API_KEY`, and optionally `MISP_VERIFY_SSL=false` environment variables.

## Project Structure

```
misp-mcp/
  src/
    index.ts              # MCP server entry point
    config.ts             # Environment config + validation
    client.ts             # MISP REST API client
    types.ts              # MISP API type definitions
    resources.ts          # MCP resources
    prompts.ts            # MCP prompts
    tools/
      events.ts           # Event CRUD tools
      attributes.ts       # Attribute management tools
      correlation.ts      # Correlation & intelligence tools
      tags.ts             # Tag and taxonomy tools
      exports.ts          # Export format tools
      sightings.ts        # Sighting tools
      warninglists.ts     # Warninglist checks
      objects.ts          # Object template & CRUD tools
      galaxies.ts         # Galaxy & cluster tools (MITRE ATT&CK)
      feeds.ts            # Feed management tools
      organisations.ts    # Organisation management tools
      servers.ts          # Server admin & sharing group tools
  tests/
    client.test.ts        # API client unit tests
    tools.test.ts         # Tool handler unit tests
    integration.test.ts   # Live MISP API integration tests
  Dockerfile
  package.json
  tsconfig.json
  tsup.config.ts
  vitest.config.ts
  vitest.integration.config.ts
  README.md
```

## License

MIT
