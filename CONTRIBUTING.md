# Contributing to misp-mcp

misp-mcp is an MCP server that exposes a MISP threat-intelligence instance to LLM clients. Patches are welcome. Please skim this file first so we both spend time on the right things.

## What kinds of changes land easily

- **Bug fixes** in the MISP REST client, tool handlers, resources, or prompts.
- **New MISP tools** that wrap a real MISP API operation, with input validation and tests.
- **Better tool descriptions** that help a model pick the right tool and arguments.
- **Test coverage** for any of the above, especially the destructive-action guards.
- **Docs fixes** in the README, tool tables, or examples.

## What needs a conversation first

- **Renaming or removing an existing tool, resource, or prompt.** These are the public MCP surface; changing a tool name breaks every client config that references it. Open an issue first.
- **Changes to the destructive-action confirmation model** (`confirm`, `confirmHard`, `MISP_ALLOW_DESTRUCTIVE`). The default is fail-closed on purpose.
- **New runtime dependencies.** The server stays lean (`@modelcontextprotocol/sdk`, `undici`, `zod`); keep it that way.
- **New environment variables.** Document them in the README config table and the relevant `*.md` health files.

## What does not land

- Personal details, hostnames, real IPs, account IDs, API keys, or live MISP URLs in code, tests, examples, or docs. Use the [RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and `*.example` / `misp.example.com` in examples. The content-guard pre-push hook and CI will flag leaks.
- Code that disables SSL verification by default or logs the MISP API key.
- AI co-authorship trailers on commits (`Co-Authored-By: <model>`). Conventional commits only.

## Local development

```bash
git clone https://github.com/lidless-labs/misp-mcp.git
cd misp-mcp
npm install
npm run build
```

Run the unit tests (mocked, no live MISP needed):

```bash
npm test
npm run lint   # tsc --noEmit type check
```

To run against a live MISP instance, set the environment and run the integration suite:

```bash
export MISP_URL=https://misp.example.com
export MISP_API_KEY=your-api-key-here
export MISP_VERIFY_SSL=false   # only for self-signed dev instances
npm run test:integration
```

To iterate on the server live, `npm run dev` runs the TypeScript entry point under `tsx watch`.

## Adding a tool

1. Add the handler to the right family module under `src/tools/` (or create a new `register*Tools` module and wire it into `src/index.ts`).
2. Define the input schema with Zod and write a clear, model-readable `description`.
3. If the tool changes state or deletes data, route it through the guards in `src/guards.ts` so it requires `confirm` (and `confirmHard` for permanent deletes).
4. Add a unit test, and an integration test if it touches a real MISP endpoint.
5. Add a row to the matching tool table in `README.md` and the tool count in the header.
6. Add a `CHANGELOG.md` entry under `## [Unreleased]`.

## Filing issues

Please use the templates under `.github/ISSUE_TEMPLATE/`. For bug reports, include your misp-mcp version, Node version, MCP client, and the full (redacted) tool output. Remove your MISP URL, API key, and any real IOCs before posting.

## License

By contributing you agree that your contribution is licensed under the MIT License, same as the rest of the repo.
