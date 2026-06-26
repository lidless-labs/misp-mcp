# Security Policy

## Supported versions

Only the latest minor release on the `main` branch receives security fixes. Pin to a released tag (and lockfile) if you need a known-good version.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems. Email **me@solomonneas.dev** with: <!-- content-guard: allow pii/email -->

- A short description of the issue.
- Steps to reproduce (or a minimal proof of concept).
- The version or commit you tested against.
- Whether you would like to be credited in the release notes.

You should get an acknowledgment within 72 hours. If you do not, please follow up - the mail may have been filtered.

## In scope

- Code execution, command injection, or SSRF flaws in the MISP REST client or tool handlers.
- Bypasses of the destructive-action confirmation gate, where a `misp_delete_*`, `misp_publish_event`, or tag-removal call performs a write without the required `confirm` / `confirmHard` flag (and without `MISP_ALLOW_DESTRUCTIVE=true`).
- Leakage of `MISP_API_KEY` or other credentials into logs, error messages, or tool output.
- Input that escapes Zod validation and reaches the MISP API in an unintended shape.
- SSL verification being silently disabled when `MISP_VERIFY_SSL` is unset or `true`.

## The API key is as trusted as your MISP role

misp-mcp acts as the MISP user whose auth key you give it. It can read, write, publish, and delete exactly what that key's role permits on your instance.

- Provision a **scoped MISP auth key** for the server rather than reusing an admin key. Grant only the permissions the agent actually needs.
- The destructive-action gate (`confirm` / `confirmHard`, and the `MISP_ALLOW_DESTRUCTIVE` opt-in) is a guardrail against accidental writes by an over-eager agent. It is **not** a substitute for MISP-side role restrictions, and it does not protect against a malicious key holder.
- Treat `MISP_URL` and `MISP_API_KEY` as secrets. Set them through your MCP client's `env` block or your own secrets tooling, never inline in committed config.

## Out of scope

- Vulnerabilities in MISP itself - report those to the [MISP project](https://github.com/MISP/MISP).
- Vulnerabilities in the MCP clients (Claude, Codex, OpenClaw, Hermes) - report those to their respective projects.
- Issues that require an attacker to already have your MISP auth key, your machine, or write access to your MCP client config.
- A trusted operator intentionally setting `MISP_ALLOW_DESTRUCTIVE=true` and then losing data to their own agent. That env flag exists for trusted automation and disables the per-call confirmation prompt by design.

## Disclosure

We aim to ship a fix within 14 days of confirming a valid report. A coordinated disclosure timeline can be negotiated for issues that need longer.
