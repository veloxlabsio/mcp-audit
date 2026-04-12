"""Tests for MCPA-010 (path traversal), MCPA-012 (shell injection),
MCPA-060 (SSRF sink), and MCPA-070 (hardcoded secrets) AST checks."""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace

from mcp_audit.checks.source_code import (
    HardcodedSecretsInSource,
    PathTraversalInHandlers,
    SsrfSinkInHandlers,
    ShellInjectionInHandlers,
)


def _make_target(source_code: str) -> SimpleNamespace:
    """Write source to a temp dir, return a mock target pointing at it."""
    tmp = tempfile.mkdtemp()
    (Path(tmp) / "server.py").write_text(source_code)
    return SimpleNamespace(source_path=tmp)


# ── MCPA-010: Path traversal ──

def test_010_catches_unguarded_read_text() -> None:
    target = _make_target("""
from pathlib import Path
NOTES = Path("/tmp/notes")

async def read_note(filename: str):
    path = NOTES / filename
    return path.read_text()
""")
    check = PathTraversalInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) >= 1
    assert any("MCPA-010" == f.check_id for f in findings)


def test_010_clean_when_guarded() -> None:
    target = _make_target("""
from pathlib import Path
NOTES = Path("/tmp/notes")

async def read_note(filename: str):
    path = (NOTES / filename).resolve()
    if not path.is_relative_to(NOTES):
        raise ValueError("nope")
    return path.read_text()
""")
    check = PathTraversalInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_010_catches_resolve_without_containment() -> None:
    """resolve() alone does NOT prevent traversal — still needs is_relative_to()."""
    target = _make_target("""
from pathlib import Path
NOTES = Path("/tmp/notes")

async def read_note(filename: str):
    path = (NOTES / filename).resolve()
    return path.read_text()
""")
    check = PathTraversalInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) >= 1
    assert any("MCPA-010" == f.check_id for f in findings)


def test_010_skips_when_no_source() -> None:
    target = SimpleNamespace(source_path=None)
    check = PathTraversalInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert findings == []


# ── MCPA-012: Shell injection ──

def test_012_catches_shell_true() -> None:
    target = _make_target("""
import subprocess

async def git_log(ref: str):
    result = subprocess.run(f"git log {ref}", shell=True, capture_output=True)
    return result.stdout
""")
    check = ShellInjectionInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-012"
    assert "dynamic command string" in findings[0].evidence


def test_012_clean_when_shell_false() -> None:
    target = _make_target("""
import subprocess

async def git_log(ref: str):
    result = subprocess.run(["git", "log", ref], capture_output=True)
    return result.stdout
""")
    check = ShellInjectionInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_012_skips_when_no_source() -> None:
    target = SimpleNamespace(source_path=None)
    check = ShellInjectionInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert findings == []


# ── MCPA-070: Hardcoded secrets ──

def test_070_catches_openai_key_prefix() -> None:
    target = _make_target("""
OPENAI_API_KEY = "sk-demo1234567890abcdefghijABCDEFGHIJ"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-070"
    assert "OpenAI API key" in findings[0].evidence


def test_070_catches_github_pat() -> None:
    target = _make_target("""
TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "GitHub personal access token" in findings[0].evidence


def test_070_catches_aws_key() -> None:
    target = _make_target("""
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "AWS access key ID" in findings[0].evidence


def test_070_catches_secret_named_var_with_high_entropy() -> None:
    target = _make_target("""
my_secret_key = "aB3$xR9!mK7@pL2&nQ5*"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "secret-like name" in findings[0].evidence


def test_070_catches_standalone_token_var() -> None:
    """Standalone TOKEN and SECRET should be caught when value has high entropy."""
    target = _make_target("""
TOKEN = "aB3xR9mK7pL2nQ5wZ8yT"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "secret-like name" in findings[0].evidence


def test_070_catches_annotated_assignment() -> None:
    """API_KEY: str = "sk-..." should be caught via AnnAssign."""
    target = _make_target("""
API_KEY: str = "sk-demo1234567890abcdefghijABCDEFGHIJ"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "OpenAI API key" in findings[0].evidence


def test_070_catches_annotated_secret_var() -> None:
    """SECRET: str = "high-entropy-value" should be caught."""
    target = _make_target("""
SECRET: str = "aB3xR9mK7pL2nQ5wZ8yT"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "secret-like name" in findings[0].evidence


def test_070_clean_on_substring_false_positives() -> None:
    """Words containing secret-like substrings should NOT match if the
    substring is not a proper underscore-delimited segment."""
    target = _make_target("""
notsecretly = "aB3xR9mK7pL2nQ5wZ8yT"
mytokenizer = "aB3xR9mK7pL2nQ5wZ8yT"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_070_clean_on_normal_strings() -> None:
    target = _make_target("""
APP_NAME = "my-cool-app"
VERSION = "1.0.0"
BASE_URL = "https://api.example.com"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_070_clean_on_short_prefix_match() -> None:
    """Prefix match requires minimum length after prefix — short strings are not flagged."""
    target = _make_target("""
MODE = "sk-test"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_070_clean_on_low_entropy_secret_name() -> None:
    """Secret-named var with low-entropy value (e.g. placeholder) is not flagged."""
    target = _make_target("""
API_KEY = "changeme"
""")
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_070_skips_when_no_source() -> None:
    target = SimpleNamespace(source_path=None)
    check = HardcodedSecretsInSource()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert findings == []


# ── MCPA-060: SSRF sink ──

def test_060_catches_httpx_get_with_variable_url() -> None:
    target = _make_target("""
import httpx

async def fetch(url: str):
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"
    assert "httpx.get()" in findings[0].evidence


def test_060_catches_requests_post() -> None:
    target = _make_target("""
import requests

async def send_data(endpoint: str, data: dict):
    r = requests.post(endpoint, json=data)
    return r.json()
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "requests.post()" in findings[0].evidence


def test_060_clean_when_url_is_hardcoded() -> None:
    """Hardcoded URLs are not SSRF — the attacker can't control the target."""
    target = _make_target("""
import httpx

async def fetch_weather():
    r = httpx.get("https://api.weather.com/v1/current", timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_060_clean_when_guarded_with_hostname_check() -> None:
    """urlparse(url) → parsed.hostname in ALLOWED counts as a guard."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

ALLOWED = {"api.example.com"}

async def fetch(url: str):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED:
        raise ValueError("not allowed")
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_060_catches_urlparse_without_hostname_check() -> None:
    """urlparse alone is parsing, not validation — still flagged."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str):
    parsed = urlparse(url)
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_clean_on_bare_get_helper() -> None:
    """A local function named get() should not be flagged as an HTTP sink."""
    target = _make_target("""
def get(url: str):
    return {"data": url}

async def handler(url: str):
    return get(url)
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_060_catches_requests_request_method_url() -> None:
    """requests.request("GET", url) — URL is the second arg, not first."""
    target = _make_target("""
import requests

async def fetch(url: str):
    r = requests.request("GET", url)
    return r.json()
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert "requests.request()" in findings[0].evidence


def test_060_catches_hostname_access_without_comparison() -> None:
    """Accessing parsed.hostname without comparing it is NOT a guard."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str):
    parsed = urlparse(url)
    host = parsed.hostname
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_allowlist_assigned_but_unused() -> None:
    """Defining an allowlist without using it in a comparison is NOT a guard."""
    target = _make_target("""
import httpx

async def fetch(url: str):
    allowlist = {"api.example.com"}
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_unrelated_hostname_comparison() -> None:
    """hostname comparison on an unrelated urlparse (not the fetched URL)
    must NOT suppress the finding."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str, other_url: str):
    parsed = urlparse(other_url)
    if parsed.hostname in {"example.com"}:
        pass
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_hostname_equality_comparison() -> None:
    """Equality (==) against a variable is too ambiguous to count as a guard.
    Only membership (in/not in) against a collection is accepted."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str, allowed: str):
    parsed = urlparse(url)
    if parsed.hostname == allowed:
        pass
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_membership_against_attribute_container() -> None:
    """Membership against an attribute chain (request.headers) is not a
    policy collection — should still flag."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str, request):
    parsed = urlparse(url)
    if parsed.hostname not in request.headers:
        pass
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_membership_against_function_param() -> None:
    """Membership against a function parameter is not a trusted
    policy — parameter values are attacker-controlled."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str, allowed_hosts: set):
    parsed = urlparse(url)
    if parsed.hostname not in allowed_hosts:
        raise ValueError("nope")
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_local_alias_of_param() -> None:
    """Local name assigned from a function parameter is not trustworthy."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str, allowed_hosts: set):
    ALLOWED = allowed_hosts
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED:
        raise ValueError("nope")
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_local_alias_of_attribute() -> None:
    """Local name assigned from an attribute chain is not trustworthy."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str, request):
    allowed = request.headers
    parsed = urlparse(url)
    if parsed.hostname not in allowed:
        raise ValueError("nope")
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_annotated_alias_of_param() -> None:
    """Annotated assignment from a parameter is not trustworthy."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str, allowed_hosts: set):
    ALLOWED: set[str] = allowed_hosts
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED:
        raise ValueError("nope")
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_annotated_alias_of_attribute() -> None:
    """Annotated assignment from an attribute is not trustworthy."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str, config):
    ALLOWED: set = config.allowed_hosts
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED:
        raise ValueError("nope")
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_mixed_branch_literal_then_param() -> None:
    """If any branch assigns a policy name from non-literal, reject it."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str, hosts: set, cond: bool):
    if cond:
        POLICY = {"api.example.com"}
    else:
        POLICY = hosts
    parsed = urlparse(url)
    if parsed.hostname not in POLICY:
        raise ValueError("nope")
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_catches_mixed_branch_param_then_literal() -> None:
    """Same as above but reversed branch order — still rejected."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str, hosts: set, cond: bool):
    if cond:
        POLICY = hosts
    else:
        POLICY = {"api.example.com"}
    parsed = urlparse(url)
    if parsed.hostname not in POLICY:
        raise ValueError("nope")
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_clean_when_local_assigned_from_literal() -> None:
    """Local name assigned from a literal set is trustworthy."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str):
    allowed = {"api.example.com", "cdn.example.com"}
    parsed = urlparse(url)
    if parsed.hostname not in allowed:
        raise ValueError("nope")
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_060_clean_when_membership_against_literal_set() -> None:
    """Membership against a literal set is an inline allowlist — valid guard."""
    target = _make_target("""
import httpx
from urllib.parse import urlparse

async def fetch(url: str):
    parsed = urlparse(url)
    if parsed.hostname not in {"api.example.com", "cdn.example.com"}:
        raise ValueError("nope")
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_060_clean_when_guarded_with_validate_url() -> None:
    """validate_url(url) where url is the fetched variable counts as guard."""
    target = _make_target("""
import httpx

def validate_url(u: str) -> None:
    ...

async def fetch(url: str):
    validate_url(url)
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 0


def test_060_catches_validate_url_on_wrong_var() -> None:
    """validate_url called on a different variable is NOT a guard."""
    target = _make_target("""
import httpx

def validate_url(u: str) -> None:
    ...

async def fetch(url: str, other: str):
    validate_url(other)
    r = httpx.get(url, timeout=5.0)
    return r.text
""")
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert len(findings) == 1
    assert findings[0].check_id == "MCPA-060"


def test_060_skips_when_no_source() -> None:
    target = SimpleNamespace(source_path=None)
    check = SsrfSinkInHandlers()
    findings = asyncio.run(check.run(target))  # type: ignore[arg-type]
    assert findings == []
