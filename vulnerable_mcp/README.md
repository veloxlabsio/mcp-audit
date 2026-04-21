# vulnerable-mcp

A deliberately broken MCP server, shipped with `mcp-audit` as a reference target.

**Every tool in this server is insecure on purpose. Do not deploy it. Do not connect a production agent to it.**

## What's wrong with it

Five planted vulnerabilities across 4 tools and 1 module-level constant:

| # | Tool / location | Vulnerability | Check(s) that will catch it | Status |
|---|---|---|---|---|
| 1 | `weather.description` | ANSI-hidden line-jump prompt injection payload | `MCPA-001`, `MCPA-002` | **Caught** |
| 2 | `read_note` handler | Path traversal — no containment against `NOTES_DIR` | `MCPA-010` | **Caught** (with `--source`) |
| 3 | `git_log` handler | `shell=True` + unvalidated user arg (`git log {ref}`) | `MCPA-012` | **Caught** (with `--source`) |
| 4 | `fetch_url` handler | SSRF (no host allowlist) + markdown auto-render exfil | `MCPA-060` (SSRF caught); `MCPA-061` (exfil planned) | **Caught** (with `--source`) |
| 5 | Module source | Hardcoded OpenAI API key literal | `MCPA-070` | **Caught** (with `--source`) |

**The scanner catches all 5 planted vulnerabilities** (7 findings total). Vuln #1 is caught via protocol-level tool-description checks; vulns #2, #3, #4, and #5 are caught via `--source` AST scanning.

## Run it

```bash
python3 -m vulnerable_mcp.server
```

## Scan it

```bash
mcp-audit scan --stdio "python3 -m vulnerable_mcp.server"
```

Without `--source`: 2 findings (1 CRITICAL injection markers, 1 HIGH ANSI escape).
With `--source ./vulnerable_mcp`: 7 findings (4 CRITICAL + 3 HIGH) catching all 5 vulns.

No false criticals from introspection — the server only advertises tools, and the scanner respects that.

## Why this exists

Security tools that ship without a reference vulnerable target are hard to evaluate. `vulnerable-mcp` lets you see what the scanner catches (and what it doesn't yet catch) in 30 seconds, on your own laptop, without connecting to anything real.

All 5 planted vulnerabilities are now caught. As new checks land (e.g. MCPA-061 for markdown exfiltration), additional findings may appear for existing vulns.
