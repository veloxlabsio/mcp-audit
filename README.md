# mcp-audit

> Security scanner for Model Context Protocol (MCP) servers.

[![status: early alpha](https://img.shields.io/badge/status-early%20alpha-orange.svg)](https://github.com/veloxlabsio/mcp-audit)
[![python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![license: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**mcp-audit** is an open-source CLI that inspects MCP servers for known security issues. It connects to a server via stdio, fetches its tool/resource/prompt manifest, and runs a battery of checks against the metadata.

> **Early alpha.** Currently ships 6 checks: 2 protocol-level (prompt injection markers, ANSI/control character smuggling) and 4 source-code AST checks (path traversal, shell injection, SSRF sinks, hardcoded secrets). 19 more are planned — see [`docs/checks.md`](docs/checks.md) for the full roadmap. Only stdio transport is implemented; HTTP/SSE is planned.

Built by [Velox Labs](https://veloxlabs.dev) — an AI security and platform engineering studio.

---

## What it catches today

**Protocol-level checks** (run against any MCP server, no source access needed):

| Check | Severity | What it detects |
|---|---|---|
| **MCPA-001** | Critical | Prompt-injection markers in tool descriptions (imperative verbs, `<system>` tags, exfiltration phrases) |
| **MCPA-002** | High | ANSI escape sequences, C0 control chars, and zero-width characters hiding payloads in tool descriptions |

**Source-code AST checks** (require `--source <path>` pointing at the server's Python source):

| Check | Severity | What it detects |
|---|---|---|
| **MCPA-010** | Critical | Path traversal in file handlers — `open()`/`read_text()` without `is_relative_to()` containment (`resolve()` alone is not sufficient) |
| **MCPA-012** | Critical | Shell injection — `subprocess` with `shell=True`, especially with f-string/format commands |
| **MCPA-060** | High | SSRF sinks — HTTP client calls (`httpx`, `requests`, `urllib`) with variable URLs and no host validation guard |
| **MCPA-070** | High | Hardcoded secrets — API keys (`sk-`, `ghp_`, `AKIA`, `xoxb-`, etc.) and high-entropy strings in secret-named variables |

These catch the tool poisoning attacks published by Trail of Bits and Invariant Labs (2025), the EscapeRoute filesystem sandbox bypass (CVE-2025-53109/53110), and the Anthropic Git MCP argument injection (CVE-2025-68144).

See [`docs/checks.md`](docs/checks.md) for the 19 additional checks planned for v0.1 (dependency CVEs, OAuth conformance, SSRF, exfiltration channels, and more).

## Install

```bash
pip install mcp-audit           # from PyPI (coming soon)
# or during development:
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Quick start

```bash
# Scan a local stdio MCP server
mcp-audit scan --stdio "python3 -m my_mcp_server"

# Output JSON report
mcp-audit scan --stdio "python3 -m my_mcp_server" --format json --output report.json

# Only run critical-severity checks
mcp-audit scan --stdio "python3 -m my_mcp_server" --severity critical

# List registered checks
mcp-audit list-checks
```

## Try it on the vulnerable reference server

This repo ships with [`vulnerable-mcp`](vulnerable_mcp/) — a deliberately broken MCP server with 5 planted vulnerabilities. The scanner catches all 5 (7 findings total).

```bash
# Protocol-level checks only (catches vuln #1)
mcp-audit scan --stdio "python3 -m vulnerable_mcp.server"

# Protocol + source-code checks (catches all 5 vulns)
mcp-audit scan --stdio "python3 -m vulnerable_mcp.server" --source ./vulnerable_mcp
```

## Fail-closed design

A security scanner that silently passes when something goes wrong is worse than no scanner. mcp-audit follows fail-closed principles:

- **Introspection failures are surfaced as critical findings**, not swallowed. If the server can't respond to `tools/list`, you see a `CRITICAL` finding, not an empty clean report.
- **Check execution errors cause non-zero exit**, even if no findings were produced. In CI, a broken scan is a failed scan.
- **All MCP RPC calls have timeouts** (default 30s, configurable via `--timeout`). A hanging server can't hang the scanner.

## Roadmap

- **Current** — 6 checks (MCPA-001, MCPA-002, MCPA-010, MCPA-012, MCPA-060, MCPA-070), stdio transport, source-code AST scanning (`--source`), terminal/JSON/markdown reports, fail-closed error handling, capability-aware introspection.
- **v0.1** — 25 checks across tool-schema, resource-access, supply-chain, transport, OAuth, SSRF, exfiltration, and configuration categories. See [`docs/checks.md`](docs/checks.md).
- **v0.3** — OAuth 2.1 DCR flow auditing, multi-server config analysis, fuzz mode.

## License

MIT. See [LICENSE](LICENSE).

## Security

Found a security issue in `mcp-audit` itself? Email `security@veloxlabs.dev` — please do not file a public issue.
