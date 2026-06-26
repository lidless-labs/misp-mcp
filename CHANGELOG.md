# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- README now opens with a what / why / how-it-differs lead and a copy-paste `npx -y misp-mcp` MCP client config, surfaces the website link near the top, and adds "Why not the MISP web UI or raw API?" and "What misp-mcp is not" sections. The full tool list is re-verified against the server source (36 tools, 3 resources, 3 prompts).

### Added
- Maintainer-health files: `SECURITY.md` (private reporting, scope, and the API-key trust model), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, a `CHANGELOG.md`, GitHub issue forms (`bug`, `feature`, plus a `config.yml` that disables blank issues and routes security and MISP-platform questions off-issue), and a pull request template with a no-PII / content-guard checklist.

## [1.2.0]

### Added
- 36 MCP tools across events, attributes, correlations, tags, exports, sightings, warninglists, objects, galaxies, feeds, organisations, and server administration.
- 3 MCP resources (`misp://types`, `misp://statistics`, `misp://taxonomies`) and 3 MCP prompts (`investigate-ioc`, `create-incident-event`, `threat-report`).
- Destructive-action confirmation gate: `misp_delete_event`, `misp_delete_attribute`, `misp_delete_object`, `misp_publish_event`, and tag removal require `confirm: true`; permanent hard deletes additionally require `confirmHard: true`. `MISP_ALLOW_DESTRUCTIVE=true` pre-authorizes the per-call `confirm` flag for trusted automation but never bypasses `confirmHard`.
- Export formats: CSV, STIX, Suricata, Snort, text, RPZ, and hash lists. MITRE ATT&CK galaxy cluster search and attachment. Bulk attribute add.
- Configuration via `MISP_URL`, `MISP_API_KEY`, `MISP_VERIFY_SSL`, `MISP_TIMEOUT`, and `MISP_ALLOW_DESTRUCTIVE`.

[Unreleased]: https://github.com/lidless-labs/misp-mcp/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/lidless-labs/misp-mcp/releases/tag/v1.2.0
