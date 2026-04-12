# mcp-audit TODO

Last updated: 2026-04-12

## Shipped (v0.1.0-dev)

- [x] `MCPA-001` tool-description prompt-injection markers
- [x] `MCPA-002` ANSI / control / zero-width character detection
- [x] `MCPA-010` path traversal AST scan (with `--source`)
- [x] `MCPA-012` shell injection AST scan (with `--source`)
- [x] `MCPA-060` SSRF sink detection with dataflow tracking (with `--source`)
- [x] `MCPA-070` hardcoded secrets detection (with `--source`)
- [x] Fail-closed handling for introspection errors and crashed checks
- [x] Capability-aware introspection (advertised vs non-advertised)
- [x] Terminal, JSON, and Markdown report output
- [x] `vulnerable-mcp` reference server — 5/5 vulnerabilities caught

## Next Checks

- [ ] `MCPA-020` curated MCP dependency CVE match
- [ ] `MCPA-061` markdown image / auto-link exfiltration vector
- [ ] `MCPA-003` tool description hash-pin drift
- [ ] `MCPA-011` symlink-follow in sandboxed FS ops

## Launch

- [x] Create public GitHub repo and push
- [ ] Build static demo page on `veloxlabs.dev` showing scanner vs `vulnerable_mcp`
- [ ] Write launch blog post
- [ ] Publish to PyPI
- [ ] Send 5 DMs to AI security people

## Not Yet Implemented

- [ ] HTTP/SSE transport (`--url`)
- [ ] OAuth 2.1 DCR flow auditing
- [ ] Multi-server config analysis
