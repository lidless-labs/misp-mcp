<p align="center">
  <img src="docs/assets/misp-mcp-banner.jpg" alt="misp-mcp banner" width="900">
</p>

<h1 align="center">misp-mcp</h1>

<p align="center"><strong>Query and manage your MISP threat-intelligence platform from any MCP client.</strong></p>

<p align="center">
  <a href="https://lidless.dev/misp-mcp"><strong>Website &amp; docs &rarr; lidless.dev/misp-mcp</strong></a>
</p>

<p align="center">
  <img src="https://shieldcn.dev/npm/misp-mcp.svg" alt="npm version">
  <img src="https://shieldcn.dev/github/ci/lidless-labs/misp-mcp.svg?branch=main&workflow=ci.yml" alt="CI">
  <img src="https://shieldcn.dev/badge/MCP-server-8A2BE2.svg" alt="MCP server">
  <img src="https://shieldcn.dev/badge/license-MIT-green.svg" alt="MIT license">
</p>

misp-mcp is a [Model Context Protocol](https://modelcontextprotocol.io/) server for [MISP](https://www.misp-project.org/), the open-source threat-intelligence sharing platform. It lets an LLM client such as Claude run IOC lookups, manage events, discover cross-event correlations, and export indicators directly against your own MISP instance. Unlike a generic HTTP wrapper, it ships 36 purpose-built tools, MISP-aware resources and prompts, and a confirmation gate that refuses destructive writes (delete, publish, untag) unless you explicitly approve them.

## What it does

misp-mcp connects an AI agent to a MISP (Malware Information Sharing Platform & Threat Intelligence Sharing) instance over MISP's REST API and exposes it as Model Context Protocol tools, resources, and prompts. Point it at your MISP server with an API key and an LLM can search threat-intelligence events, look up and add indicators of compromise (IOCs), correlate indicators across events, attach MITRE ATT&CK galaxy clusters, check warninglists for false positives, and export IOCs as Suricata, Snort, STIX, CSV, RPZ, or hash lists. Read paths are safe by default; state-changing and destructive operations are guarded behind explicit confirmation flags so an agent cannot delete an event or publish to sharing partners without approval.

- **36 MCP tools** covering events, attributes, correlations, tags, exports, sightings, warninglists, objects, galaxies, feeds, organisations, and server administration.
- **3 MCP resources** for browsing attribute types, instance statistics, and available taxonomies.
- **3 MCP prompts** for guided IOC investigation, incident event creation, and threat reporting.
- **Confirmation-gated writes** so destructive tools refuse to run without `confirm: true` (and `confirmHard: true` for permanent deletes).
- **MITRE ATT&CK integration** via galaxy cluster search and attachment.
- **Export formats** including CSV, STIX, Suricata, Snort, text, RPZ, and hash lists.
- **SSL flexibility** for the self-signed certificates common in on-prem MISP deployments.

## Quickstart

No checkout required. With Node.js 20+ installed, register the published package with any MCP client. For [Claude Code](https://docs.anthropic.com/en/docs/claude-code):

```bash
claude mcp add misp \
  --env MISP_URL=https://misp.example.com \
  --env MISP_API_KEY=your-api-key-here \
  --env MISP_VERIFY_SSL=false \
  -- npx -y misp-mcp
```

Add `--scope user` to make it available from any directory instead of only the current project.

### MCP client config (copy-paste)

For Claude Desktop, Cursor, or any client that reads a JSON `mcpServers` block, add:

```json
{
  "mcpServers": {
    "misp": {
      "command": "npx",
      "args": ["-y", "misp-mcp"],
      "env": {
        "MISP_URL": "https://misp.example.com",
        "MISP_API_KEY": "your-api-key-here",
        "MISP_VERIFY_SSL": "false"
      }
    }
  }
}
```

Claude Desktop reads this from `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows). Restart the client after editing.

### Prerequisites

- Node.js 20 or later.
- A running MISP instance with API access.
- A MISP API key (MISP UI: Administration > List Auth Keys).

### Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MISP_URL` | Yes | - | MISP instance base URL |
| `MISP_API_KEY` | Yes | - | API authentication key |
| `MISP_VERIFY_SSL` | No | `true` | Set `false` for self-signed certs |
| `MISP_TIMEOUT` | No | `30` | Request timeout in seconds |
| `MISP_ALLOW_DESTRUCTIVE` | No | `false` | Set `true` to pre-authorize destructive tools so the per-call `confirm` flag is not required. Permanent (`hard`) deletes still require `confirmHard`. |

### Destructive action safety

State-changing and destructive tools are guarded and refuse to run unless explicitly confirmed:

- `misp_delete_event`, `misp_delete_attribute`, `misp_delete_object`, `misp_publish_event`, and `misp_tag_event` (when `remove: true`) require `confirm: true`.
- Setting `MISP_ALLOW_DESTRUCTIVE=true` pre-authorizes these so the `confirm` flag can be omitted (useful for trusted automation).
- Permanent **hard** deletes (`hard: true` on `misp_delete_attribute` / `misp_delete_object`) require a **second** confirmation, `confirmHard: true`, in addition to `confirm: true`. The env opt-in does **not** bypass `confirmHard`.

A guarded call returns an error (`isError: true`) with a `Refused:` message and performs no MISP request.

## Tools

Verified against the server source (36 tools, registered in `src/tools/`).

### Event tools (6)

| Tool | Description |
|------|-------------|
| `misp_search_events` | Search events by IOC value, type, tags, date range, organization |
| `misp_get_event` | Get full event details including attributes, objects, galaxies, related events |
| `misp_create_event` | Create a new event with threat level, distribution, and analysis status |
| `misp_update_event` | Update event metadata (info, threat level, analysis, publish state) |
| `misp_publish_event` | Publish an event to trigger alerts to sharing partners (requires `confirm:true`) |
| `misp_tag_event` | Add or remove tags (TLP, MITRE ATT&CK, custom) from an event (removal requires `confirm:true`) |

### Attribute tools (4)

| Tool | Description |
|------|-------------|
| `misp_search_attributes` | Search IOCs across all events with type, category, and correlation filters |
| `misp_add_attribute` | Add a single IOC to an event |
| `misp_add_attributes_bulk` | Add multiple IOCs to an event in one operation |
| `misp_delete_attribute` | Soft or hard delete an attribute (requires `confirm:true`; hard delete also requires `confirmHard:true`) |

### Correlation & intelligence tools (3)

| Tool | Description |
|------|-------------|
| `misp_correlate` | Find all events and attributes matching a value, with cross-event correlations |
| `misp_get_related_events` | Discover events related through shared IOCs |
| `misp_describe_types` | Get all available attribute types and category mappings |

### Tag & taxonomy tools (2)

| Tool | Description |
|------|-------------|
| `misp_list_tags` | List available tags with usage statistics |
| `misp_search_by_tag` | Find events or attributes by tag |

### Export tools (2)

| Tool | Description |
|------|-------------|
| `misp_export_iocs` | Export IOCs in CSV, STIX, Suricata, Snort, text, or RPZ format |
| `misp_export_hashes` | Export file hashes (MD5, SHA1, SHA256) for HIDS integration |

### Sighting & warninglist tools (2)

| Tool | Description |
|------|-------------|
| `misp_add_sighting` | Report a sighting, false positive, or expiration for an IOC |
| `misp_check_warninglists` | Check if a value appears on known benign/false positive lists |

### Object tools (4)

| Tool | Description |
|------|-------------|
| `misp_list_object_templates` | List available MISP object templates (file, domain-ip, email, etc.) |
| `misp_get_object_template` | Get template details with required/optional attributes |
| `misp_add_object` | Add a structured object (grouped attributes) to an event |
| `misp_delete_object` | Delete an object from an event (requires `confirm:true`; hard delete also requires `confirmHard:true`) |

### Galaxy tools (4)

| Tool | Description |
|------|-------------|
| `misp_list_galaxies` | List galaxies (MITRE ATT&CK, threat actors, malware, tools, etc.) |
| `misp_get_galaxy` | Get galaxy details with all clusters |
| `misp_search_galaxy_clusters` | Search clusters by keyword (find ATT&CK techniques, threat actors) |
| `misp_attach_galaxy_cluster` | Attach a cluster (ATT&CK technique, etc.) to an event or attribute |

### Feed tools (4)

| Tool | Description |
|------|-------------|
| `misp_list_feeds` | List configured threat intel feeds |
| `misp_toggle_feed` | Enable or disable a feed |
| `misp_fetch_feed` | Trigger a fetch/pull from a feed |
| `misp_cache_feed` | Cache feed data locally for correlation |

### Organisation tools (2)

| Tool | Description |
|------|-------------|
| `misp_list_organisations` | List local and remote sharing partner organisations |
| `misp_get_organisation` | Get organisation details |

### Server & admin tools (3)

| Tool | Description |
|------|-------------|
| `misp_server_status` | Get MISP version, permissions, and diagnostics |
| `misp_list_sharing_groups` | List sharing groups for controlled distribution |
| `misp_delete_event` | Delete a MISP event (requires `confirm:true`) |

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

## Usage examples

### Search for an IOC

> "Search MISP for the IP address 203.0.113.50"

Uses `misp_search_events` and `misp_search_attributes` to find all events and attributes referencing this IP.

### Investigate a suspicious domain

> "Investigate suspicious-domain.example in MISP"

Triggers the `investigate-ioc` prompt workflow: searches for the domain, checks correlations, queries warninglists, and provides a structured threat assessment.

### Create an incident event

<!-- content-guard: allow email -->
> "Create a MISP event for a phishing campaign targeting our finance team. The phishing emails came from attacker@phish.example and linked to https://harvest.phish.example/login"

Uses `misp_create_event` followed by `misp_add_attributes_bulk` to create a fully populated event.

### Export Suricata rules

> "Export all IOCs from the last 7 days as Suricata rules"

Uses `misp_export_iocs` with format "suricata" and last "7d".

### Check for false positives

> "Is 192.0.2.123 on any MISP warninglists?"

Uses `misp_check_warninglists` to verify if the value is a known benign indicator.

### Find MITRE ATT&CK techniques

> "Search for phishing techniques in MITRE ATT&CK"

Uses `misp_search_galaxy_clusters` to find relevant ATT&CK techniques, then `misp_attach_galaxy_cluster` to link them to events.

### Add structured objects

> "Add a file object to event 1 with filename encrypt.exe, SHA256 hash, and file size"

Uses `misp_add_object` with the "file" template to create a structured group of related attributes.

## Supported attribute types

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

## Other clients & local development

<details>
<summary>Run from a source checkout, or wire up OpenClaw, Codex CLI, Hermes, Docker, or standalone Node.</summary>

### From source

```bash
git clone https://github.com/lidless-labs/misp-mcp.git
cd misp-mcp
npm install
npm run build
```

Then point any client's `command`/`args` at `node /absolute/path/to/misp-mcp/dist/index.js` instead of `npx -y misp-mcp`.

### Claude Code (source checkout)

```bash
claude mcp add misp \
  --env MISP_URL=https://misp.example.com \
  --env MISP_API_KEY=your-api-key-here \
  --env MISP_VERIFY_SSL=false \
  -- node /absolute/path/to/misp-mcp/dist/index.js
```

### OpenClaw

```bash
openclaw mcp set misp '{
  "command": "npx",
  "args": ["-y", "misp-mcp"],
  "env": {
    "MISP_URL": "https://misp.example.com",
    "MISP_API_KEY": "your-api-key-here",
    "MISP_VERIFY_SSL": "false"
  }
}'
```

For a source checkout, use `"command": "node"` with `"args": ["/absolute/path/to/misp-mcp/dist/index.js"]`. Then restart the gateway and confirm registration:

```bash
systemctl --user restart openclaw-gateway
openclaw mcp list   # confirm "misp" is registered
```

### Codex CLI

```bash
codex mcp add misp \
  --env MISP_URL=https://misp.example.com \
  --env MISP_API_KEY=your-api-key-here \
  --env MISP_VERIFY_SSL=false \
  -- npx -y misp-mcp
```

Codex writes the entry to `~/.codex/config.toml` under `[mcp_servers.misp]`. Verify with `codex mcp list`.

### Hermes Agent

[Hermes Agent](https://github.com/NousResearch/hermes-agent) reads MCP config from `~/.hermes/config.yaml` under `mcp_servers`:

```yaml
mcp_servers:
  misp:
    command: "npx"
    args: ["-y", "misp-mcp"]
    env:
      MISP_URL: "https://misp.example.com"
      MISP_API_KEY: "your-api-key-here"
      MISP_VERIFY_SSL: "false"
```

Then `/reload-mcp` inside a Hermes session.

### Docker

```bash
docker build -t misp-mcp .
docker run -e MISP_URL=https://misp.example.com -e MISP_API_KEY=your-key -e MISP_VERIFY_SSL=false misp-mcp
```

### Standalone

```bash
MISP_URL=https://misp.example.com MISP_API_KEY=your-key node dist/index.js
```

### Development

```bash
MISP_URL=https://misp.example.com MISP_API_KEY=your-key npm run dev
```

</details>

## Testing

```bash
npm test                  # Unit tests (mocked)
npm run test:integration  # Integration tests against a live MISP instance
npm run test:watch        # Watch mode
npm run lint              # Type check
```

Integration tests require `MISP_URL`, `MISP_API_KEY`, and optionally `MISP_VERIFY_SSL=false` environment variables.

## Project structure

```
misp-mcp/
  src/
    index.ts              # MCP server entry point
    config.ts             # Environment config + validation
    client.ts             # MISP REST API client
    guards.ts             # Destructive-action confirmation guards
    types.ts              # MISP API type definitions
    resources.ts          # MCP resources
    prompts.ts            # MCP prompts
    tools/                # One module per tool family (events, attributes, ...)
  tests/                  # Unit + integration tests
  Dockerfile
  package.json
```

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution path and [SECURITY.md](SECURITY.md) for how to report a vulnerability privately. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Why not the MISP web UI or raw API?

The MISP web UI and PyMISP are excellent for analysts working a console. misp-mcp is for the case where the operator is an LLM agent, not a human at a browser. It gives the model a typed, named tool for each common MISP operation, validates inputs with Zod, and shapes responses so a model can reason over them, rather than handing the model a raw REST endpoint and an OpenAPI dump. It also adds a guardrail layer the bare API does not: destructive operations fail closed unless the caller opts in, so an over-eager agent cannot publish or delete intelligence by accident. If you want a human-driven console, use the MISP UI. If you want PyMISP scripting, use PyMISP. Use misp-mcp when you want a chat or agent client to drive MISP safely.

## What misp-mcp is not

- **Not a MISP server.** It talks to an existing MISP instance over the REST API; it does not store, host, or replace MISP.
- **Not a general HTTP proxy.** It exposes a curated set of MISP operations as MCP tools, not arbitrary passthrough to every MISP endpoint.
- **Not a SIEM, EDR, or alerting system.** It reads and writes threat intelligence; it does not collect logs or generate alerts on its own.
- **Not a credential vault.** It reads `MISP_URL` and `MISP_API_KEY` from the environment; manage and rotate those keys with your own secrets tooling.
- **Not an autonomous deleter.** Destructive and publishing actions are confirmation-gated by design.

## License

[MIT](LICENSE)
