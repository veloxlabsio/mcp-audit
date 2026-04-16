---
title: Why `urlparse()` isn't a guard
published: false
description: A lot of MCP servers "validate" URLs with urlparse() and call it a day. Here's what actually counts as an SSRF guard, based on the AST check we ship in mcp-scan.
tags: security, python, mcp, ast
---

# Why `urlparse()` isn't a guard

A lot of code looks like this:

```python
def fetch_tool(url: str) -> str:
    parsed = urlparse(url)
    return httpx.get(url).text
```

The author parsed the URL, so the URL is validated. Right?

No. `urlparse()` is a parser. It tells you what the pieces of a URL are. It does not tell you whether you should fetch it. If `url` is `http://169.254.169.254/latest/meta-data/`, `urlparse()` returns a perfectly valid `ParseResult` and `httpx.get()` cheerfully fetches AWS metadata credentials from inside your VPC.

This is the SSRF class of bug. It's boring. It's also the thing that keeps showing up in MCP servers — tools that accept a URL, fetch it server-side, return the body to the model. The model decides what URL to fetch based on untrusted input (a prompt, a doc, a tool response). So the URL is attacker-controlled by construction.

When we wrote the SSRF check for [mcp-scan](https://github.com/veloxlabsio/mcp-scan) (MCPA-060), the hard part wasn't finding `httpx.get(url)`. The hard part was deciding what *counts* as a guard. I want to walk through that decision, because the answer is narrower than most people expect and it changes how you write the fix.

## What the check actually flags

The check triggers on HTTP fetch calls (`httpx.get`, `requests.post`, `urllib.request.urlopen`, etc.) where:

1. The URL argument is a variable, not a string literal.
2. The enclosing function has no recognized host validation tied to that variable.

A string literal like `httpx.get("https://api.github.com/user")` is fine — the developer hardcoded the host. A variable URL with no guard is not fine. The interesting question is the second condition: what is a "recognized guard"?

## Accepted: hostname membership against a trusted collection

The primary pattern the check accepts:

```python
def fetch_tool(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return httpx.get(url).text
```

Three things have to be true for this to count:

- The URL variable flows into `urlparse()` or `urlsplit()` and the result is bound to a name.
- `result.hostname` or `result.netloc` appears in a `Compare` node with `in` or `not in`.
- The other side of the comparison is a *trusted collection*.

That last bullet is where most of the logic lives.

## What counts as a trusted collection

Three things are accepted as the container side of the membership test:

**A literal.** `parsed.hostname in {"api.example.com", "api.stripe.com"}`. The allowlist is right there in the source. Nothing ambiguous.

**A local name whose every assignment is a literal collection.** If a function does `ALLOWED = {"host1"}; if debug: ALLOWED = {"host1", "host2"}`, both branches assign literals, so the name is trusted. If *any* branch assigns from a non-literal (`ALLOWED = load_from_request(request)`), the name is rejected — fail closed.

**A bare name that is not assigned locally and is not a parameter.** This is the module-scope case: `ALLOWED_HOSTS = {...}` at the top of the file, referenced from inside the function. The check trusts this because module-scope names are almost always developer-controlled constants. It's trust-based. `ALLOWED_HOSTS = load_policy_from_env()` at module scope would false-clean. Fixing that honestly would require whole-file analysis, which is out of scope for a check that runs in seconds.

## What doesn't count

This is where it gets interesting, because the rejections are the part that most linters and security tools get wrong.

**Function parameters are rejected.** If someone writes:

```python
def fetch_tool(url: str, allowed_hosts: set[str]) -> str:
    parsed = urlparse(url)
    if parsed.hostname not in allowed_hosts:
        raise ValueError("no")
    return httpx.get(url).text
```

The check fires. Why? Because `allowed_hosts` is attacker-controlled by construction — the caller passes it in. In an MCP server, the caller is usually the model, and the model is reading attacker input. A "guard" that reads its allowlist from the same context that chose the URL is not a guard. The check explicitly collects every parameter (positional, keyword-only, `*args`, `**kwargs`) and refuses to trust any of them as a container.

**Equality is rejected.** `parsed.hostname == "api.example.com"` is not accepted, only `in` / `not in`. Equality against a single literal is technically safe, but it collapses into a pattern that's hard to distinguish from garbage like `parsed.scheme == "https"` (which isn't a host guard at all). Narrowing the check to membership against a collection makes the accept rule cleanly describable. If you have a one-host allowlist, write `in {"api.example.com"}`. It reads better anyway.

**Attribute chains are rejected.** `parsed.hostname in request.headers["X-Allowed"]` gets flagged. The container lives in request state, which is attacker-controllable or at least not statically verifiable.

**DNS resolution alone is rejected.** Calling `socket.gethostbyname(host)` without inspecting the result proves nothing. An attacker can DNS-rebind or point at an internal IP. The check doesn't treat "we looked up the name" as validation — only "we compared the result to a trusted set" counts.

## Two secondary patterns

Two other patterns the check accepts:

**`ipaddress` family checks on a URL-derived attribute:**

```python
parsed = urlparse(url)
if ipaddress.ip_address(parsed.hostname).is_private:
    raise ValueError("no private")
```

Specifically, the check looks for a call to a method named `is_private`, `is_loopback`, or `is_reserved` where the argument is `parsed.hostname` or `parsed.netloc`. This is narrower than it could be — `ipaddress.ip_address(parsed.hostname).is_private` requires tracking the intermediate object, which is multi-hop dataflow. We don't do that. If you write it as `checker.is_private(parsed.hostname)` with the hostname passed directly, we catch it. If you chain it through an intermediate object, we miss the guard and false-positive. That's a documented limitation.

**Helper-name guards:**

```python
if not validate_url(url):
    raise ValueError("no")
return httpx.get(url).text
```

Calls to functions named `validate_url`, `check_url`, `allowed_host`, or `is_allowed` with the URL variable as an argument are trusted. This is the most generous of the three patterns — the check has no idea what `validate_url` actually does. It could be `return True`. But false-positives on URL handling code with custom validators were painful enough in testing that we accept the heuristic and document it.

## The four honest limitations

If you read the check's docstring in [source_code.py](https://github.com/veloxlabsio/mcp-scan/blob/main/src/mcp_audit/checks/source_code.py), you'll see four limitations called out explicitly:

1. **Single-hop dataflow.** We trace `url → urlparse(url) → parsed.hostname`. We don't trace through intermediate variables beyond that. `host = parsed.hostname; if host in ALLOWED` would miss.
2. **Helper-name trust.** `validate_url(url)` is accepted without looking inside the helper. A badly-named no-op would false-clean.
3. **Module-scope trust.** A module-level name is assumed to be a developer-controlled constant. Dynamic globals break this.
4. **No DNS resolution as guard.** We don't accept name resolution as a stand-in for policy enforcement. (This is actually correct — but it means tools that claim to guard via DNS are flagged.)

These are in the check's description string. They ship with every finding. That matters because "here's a false positive" is a different conversation than "here's an undocumented gap in the tool."

## What this changes about how you write the fix

If you were going to patch your MCP server's SSRF exposure, the version that passes mcp-scan looks like:

```python
ALLOWED_HOSTS: set[str] = {"api.example.com", "api.stripe.com"}

def fetch_tool(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return httpx.get(url).text
```

Module-scope literal set. Membership test. `hostname` attribute of a `urlparse` result. Every piece maps to a rule the check understands.

The version that *looks* like a fix but doesn't pass:

```python
def fetch_tool(url: str, allowed: set[str]) -> str:
    parsed = urlparse(url)
    if parsed.hostname not in allowed:
        raise ValueError("host not allowed")
    return httpx.get(url).text
```

Same shape. Parameter instead of module constant. Check fires — because the tool is right. `allowed` is whatever the caller passed. In an agent context, the caller is the model, and the model reads attacker input.

## The meta-point

Security checks that report "URL fetch without validation" don't give you a remediation. They give you a vibe. A developer who reads the finding and adds `urlparse()` has done nothing and the tool has no way to tell them.

The useful version of the check has to commit to a position on what counts. That commitment is the hard part. You'll be wrong sometimes — a valid guard using an AST shape you didn't anticipate, or a module-scope name that turns out to be dynamic. You'll false-positive real code and false-clean bad code. The discipline is documenting the shape you accept, documenting the shape you reject, and letting a developer read the check and understand why their code was flagged.

`urlparse()` isn't a guard. Neither is `validate()`. Neither is `if host:`. The guard is a membership test against a collection whose contents you control.

---

*[mcp-scan](https://github.com/veloxlabsio/mcp-scan) is an open-source AST-level security scanner for MCP servers. The SSRF check discussed here is [MCPA-060](https://github.com/veloxlabsio/mcp-scan/blob/main/src/mcp_audit/checks/source_code.py). If you run MCP tools in production and want the check to run on your source, `pip install mcp-scan` and point it at your repo.*
