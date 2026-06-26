<!--
Thanks for sending a patch. Keep this short; delete sections that do not apply.
See CONTRIBUTING.md for what lands easily and what needs an issue first.
-->

## What and why

<!-- One or two sentences on the user-visible change and the problem it solves. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New or changed MCP tool / resource / prompt
- [ ] Docs
- [ ] Refactor with no tool-surface change
- [ ] Surface change (renamed/removed tool, changed confirmation model, new env var) — opened an issue first per CONTRIBUTING.md

## Checklist

- [ ] `npm test` and `npm run lint` pass locally
- [ ] Added or updated tests covering the change (including destructive-action guards where relevant)
- [ ] Updated the `## [Unreleased]` section of `CHANGELOG.md` for any user-visible effect
- [ ] Updated the tool table and tool count in `README.md` if tools changed
- [ ] No personal details, hostnames, real IPs, account names, API keys, or real MISP URLs/IOCs in code, tests, examples, or this PR (use RFC 5737 ranges and `*.example`; the content-guard hook and CI will fail otherwise)
- [ ] Destructive or publishing operations remain confirmation-gated by default
- [ ] No new runtime dependencies (unless discussed in an issue)
- [ ] Conventional commit messages, no AI co-authorship trailers
