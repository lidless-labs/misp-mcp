# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- CI no longer carries a duplicate tag-triggered npm publish job; releases publish only through the `Publish npm` workflow (trusted publishing). The old job had no token and failed with `ENEEDAUTH` on every tag.
- `npm test` in CI is no longer `continue-on-error`, so test failures fail the build again.
- Repo memory owner switched from claude to codex; harness docs and Brigade config updated to match.

## [1.3.5] - 2026-07-16

### Fixed
- All MISP requests now go through undici's own `fetch` instead of the Node.js global fetch. Passing an npm-undici `Agent` to the runtime-bundled global fetch fails outright when the two undici versions disagree on the dispatcher interface (with undici 8 on Node 22 every request died with `fetch failed` before reaching the network), which surfaced as the server never contacting the MISP API (#2).
- Network errors now include the underlying cause chain and a targeted hint instead of a bare `fetch failed`: TLS certificate rejections point at `MISP_VERIFY_SSL`, DNS failures report the unresolvable hostname, and refused or unreachable connections call out the URL, port, and firewall path.

### Changed
- README now opens with a what / why / how-it-differs lead and a copy-paste `npx -y misp-mcp` MCP client config, surfaces the website link near the top, and adds "Why not the MISP web UI or raw API?" and "What misp-mcp is not" sections. The full tool list is re-verified against the server source (36 tools, 3 resources, 3 prompts).

### Added
- Maintainer-health files: `SECURITY.md` (private reporting, scope, and the API-key trust model), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, a `CHANGELOG.md`, GitHub issue forms (`bug`, `feature`, plus a `config.yml` that disables blank issues and routes security and MISP-platform questions off-issue), and a pull request template with a no-PII / content-guard checklist.

## [1.3.4] - 2026-07-08

Released from the `fire/mispctrl-2026-07-06` branch; merged back to main as part of 1.3.5. Versions 1.3.0 through 1.3.3 were release-pipeline iterations and never reached npm.

### Added
- `mispctrl` CLI (alias `mispctl`) alongside the MCP server: `status` (connection/auth validation), `events list` with IOC/type/tag/org/time filters, `events get`, and an `mcp` subcommand that starts the stdio server, all sharing the same env-based configuration.
- Container image published to GHCR.

### Changed
- The `misp-mcp` bin now starts through a dedicated MCP entry point (`dist/mcp-bin.js`); server wiring moved to `src/mcp-server.ts`.

## [1.2.0]

### Added
- 36 MCP tools across events, attributes, correlations, tags, exports, sightings, warninglists, objects, galaxies, feeds, organisations, and server administration.
- 3 MCP resources (`misp://types`, `misp://statistics`, `misp://taxonomies`) and 3 MCP prompts (`investigate-ioc`, `create-incident-event`, `threat-report`).
- Destructive-action confirmation gate: `misp_delete_event`, `misp_delete_attribute`, `misp_delete_object`, `misp_publish_event`, and tag removal require `confirm: true`; permanent hard deletes additionally require `confirmHard: true`. `MISP_ALLOW_DESTRUCTIVE=true` pre-authorizes the per-call `confirm` flag for trusted automation but never bypasses `confirmHard`.
- Export formats: CSV, STIX, Suricata, Snort, text, RPZ, and hash lists. MITRE ATT&CK galaxy cluster search and attachment. Bulk attribute add.
- Configuration via `MISP_URL`, `MISP_API_KEY`, `MISP_VERIFY_SSL`, `MISP_TIMEOUT`, and `MISP_ALLOW_DESTRUCTIVE`.

[Unreleased]: https://github.com/lidless-labs/misp-mcp/compare/v1.3.5...HEAD
[1.3.5]: https://github.com/lidless-labs/misp-mcp/compare/v1.3.4...v1.3.5
[1.3.4]: https://github.com/lidless-labs/misp-mcp/compare/v1.2.0...v1.3.4
[1.2.0]: https://github.com/lidless-labs/misp-mcp/releases/tag/v1.2.0
