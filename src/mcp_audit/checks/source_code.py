"""Source-code AST checks — static analysis of MCP server handler code.

These checks require ``--source <path>`` to point at the server's source tree.
They walk the Python AST looking for patterns that indicate path traversal,
command injection, hardcoded secrets, and other handler-level vulnerabilities.

Requires no running server — purely static.
"""
from __future__ import annotations

import ast
import math
import re
from collections import Counter
from pathlib import Path

from mcp_audit.checks import register
from mcp_audit.checks.base import Category, Check, Finding, Severity
from mcp_audit.client import McpTarget


def _collect_python_files(root: Path) -> list[Path]:
    """Recursively collect .py files, skipping venvs and hidden dirs."""
    files: list[Path] = []
    for p in root.rglob("*.py"):
        parts = p.parts
        if any(
            part.startswith(".") or part in ("__pycache__", "venv", ".venv", "node_modules")
            for part in parts
        ):
            continue
        files.append(p)
    return files


def _parse_file(path: Path) -> ast.Module | None:
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        return ast.parse(source, filename=str(path))
    except SyntaxError:
        return None


# ── MCPA-010: Path traversal in filesystem handlers ────────────────────────

_PATH_TRAVERSAL_SINKS = {
    "open", "read_text", "read_bytes", "write_text", "write_bytes",
}

# Only is_relative_to (or equivalent containment check) actually prevents
# traversal. resolve()/realpath()/abspath() normalize the path but don't
# restrict it — an attacker can still escape the root directory.
_PATH_CONTAINMENT_GUARDS = {"is_relative_to"}


class _PathTraversalVisitor(ast.NodeVisitor):
    """Walk an AST and flag file-open calls that use unsanitized variables."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.findings: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_func_name(node)
        if func_name in _PATH_TRAVERSAL_SINKS:
            parent_func = getattr(self, "_current_func", None)
            if parent_func and not self._has_path_guard(parent_func):
                self.findings.append((
                    node.lineno,
                    f"`{func_name}()` call at line {node.lineno} with no "
                    f"is_relative_to() containment guard in the "
                    f"enclosing function",
                ))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Div):
            parent_func = getattr(self, "_current_func", None)
            if parent_func and not self._has_path_guard(parent_func):
                self.findings.append((
                    node.lineno,
                    f"Path division at line {node.lineno} with no containment "
                    f"guard in the enclosing function",
                ))
        self.generic_visit(node)

    @staticmethod
    def _get_func_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    @staticmethod
    def _has_path_guard(func_node: ast.FunctionDef) -> bool:
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr in _PATH_CONTAINMENT_GUARDS:
                        return True
            if isinstance(node, ast.Name) and node.id in _PATH_CONTAINMENT_GUARDS:
                return True
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old = getattr(self, "_current_func", None)
        self._current_func = node
        self.generic_visit(node)
        self._current_func = old

    visit_AsyncFunctionDef = visit_FunctionDef


@register
class PathTraversalInHandlers(Check):
    """MCPA-010 — path traversal in filesystem handler arguments."""

    id = "MCPA-010"
    name = "Path traversal: file ops without containment guard"
    description = (
        "Conservative AST heuristic: scans Python source for open()/read_text()/"
        "write_text() calls and Path division (base / user_input) where the "
        "enclosing function has no is_relative_to() containment guard. "
        "May produce false positives on internally-controlled paths. Catches "
        "the pattern behind CVE-2025-53109/53110 and CVE-2025-68143."
    )
    category = Category.RESOURCE_ACCESS
    default_severity = Severity.CRITICAL

    async def run(self, target: McpTarget) -> list[Finding]:
        if not target.source_path:
            return []

        root = Path(target.source_path)
        if not root.exists():
            return []

        findings: list[Finding] = []
        for py_file in _collect_python_files(root):
            tree = _parse_file(py_file)
            if tree is None:
                continue
            visitor = _PathTraversalVisitor(str(py_file))
            visitor.visit(tree)
            for lineno, detail in visitor.findings:
                rel = py_file.relative_to(root)
                findings.append(
                    self.finding(
                        title=f"Path traversal risk in `{rel}:{lineno}`",
                        description=(
                            "A file operation uses a path derived from input "
                            "without an is_relative_to() containment check. "
                            "resolve() alone is not sufficient — an attacker "
                            "can supply `../../etc/passwd` to escape the "
                            "intended directory."
                        ),
                        evidence=detail,
                        remediation=(
                            "Before any file operation, resolve the full path and "
                            "verify it stays within the allowed root:\n"
                            "  resolved = (root / user_input).resolve()\n"
                            "  if not resolved.is_relative_to(root):\n"
                            "      raise ValueError('path traversal')"
                        ),
                        reference="https://nvd.nist.gov/vuln/detail/CVE-2025-53110",
                    )
                )
        return findings


# ── MCPA-012: Shell injection via subprocess ────────────────────────────────

# Subprocess methods that accept shell= kwarg
_SUBPROCESS_ATTRS = {"run", "call", "check_call", "check_output", "Popen"}


class _ShellInjectionVisitor(ast.NodeVisitor):
    """Walk an AST and flag shell=True subprocess calls."""

    def __init__(self) -> None:
        self.findings: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_func_name(node)

        # subprocess.run(..., shell=True) and friends
        if func_name in _SUBPROCESS_ATTRS:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value:
                    first_arg = node.args[0] if node.args else None
                    is_dynamic = isinstance(first_arg, (ast.JoinedStr, ast.BinOp))
                    detail = (
                        f"`subprocess.{func_name}(shell=True)` at line {node.lineno}"
                    )
                    if is_dynamic:
                        detail += " with dynamic command string (f-string or format)"
                    self.findings.append((node.lineno, detail))

        self.generic_visit(node)

    @staticmethod
    def _get_func_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""


@register
class ShellInjectionInHandlers(Check):
    """MCPA-012 — shell=True / unsanitized subprocess in handlers."""

    id = "MCPA-012"
    name = "Shell injection: subprocess with shell=True"
    description = (
        "Conservative AST heuristic: flags any subprocess call with "
        "shell=True. May produce false positives when the command string "
        "is fully static, but shell=True is a code smell in MCP handlers "
        "regardless. Catches the pattern behind CVE-2025-68144."
    )
    category = Category.SANDBOX
    default_severity = Severity.CRITICAL

    async def run(self, target: McpTarget) -> list[Finding]:
        if not target.source_path:
            return []

        root = Path(target.source_path)
        if not root.exists():
            return []

        findings: list[Finding] = []
        for py_file in _collect_python_files(root):
            tree = _parse_file(py_file)
            if tree is None:
                continue
            visitor = _ShellInjectionVisitor()
            visitor.visit(tree)
            for lineno, detail in visitor.findings:
                rel = py_file.relative_to(root)
                findings.append(
                    self.finding(
                        title=f"Shell injection risk in `{rel}:{lineno}`",
                        description=(
                            "A subprocess call uses shell=True, making it "
                            "vulnerable to command injection if any part of the "
                            "command string comes from user input."
                        ),
                        evidence=detail,
                        remediation=(
                            "Replace shell=True with shell=False and pass "
                            "arguments as a list:\n"
                            '  subprocess.run(["git", "log", "--oneline", ref])\n'
                            "Never use f-strings in shell commands."
                        ),
                        reference="https://nvd.nist.gov/vuln/detail/CVE-2025-68144",
                    )
                )
        return findings


# ── MCPA-070: Hardcoded secrets in source ─────────────────────────────────────

# Known secret prefixes — each is (prefix, label).
_SECRET_PREFIXES: list[tuple[str, str]] = [
    ("sk-", "OpenAI API key"),
    ("sk-proj-", "OpenAI project key"),
    ("ghp_", "GitHub personal access token"),
    ("gho_", "GitHub OAuth token"),
    ("ghs_", "GitHub server-to-server token"),
    ("ghu_", "GitHub user-to-server token"),
    ("github_pat_", "GitHub fine-grained PAT"),
    ("AKIA", "AWS access key ID"),
    ("xoxb-", "Slack bot token"),
    ("xoxp-", "Slack user token"),
    ("xoxa-", "Slack app token"),
    ("xoxr-", "Slack refresh token"),
    ("sk_live_", "Stripe live key"),
    ("rk_live_", "Stripe restricted key"),
    ("SG.", "SendGrid API key"),
    ("AIza", "Google API key"),
    ("ya29.", "Google OAuth token"),
    ("eyJ", "JWT / bearer token"),
]

# Variable names that suggest a secret (case-insensitive).
# Uses underscore-segment boundaries ((?:^|_) and (?:_|$)) so keywords must
# appear as whole segments in underscore-delimited names. This avoids mid-word
# substring hits like "notsecretly" or "mytokenizer", but intentionally matches
# compound names where the keyword is a segment: token_bucket, password_hash,
# bearer_token, db_password are all in-scope — a high-entropy value in any of
# these is suspicious.
_SECRET_VAR_PATTERN = re.compile(
    r"(?:^|_)(?:secret|token|password|passwd|credential|bearer)(?:_|$)|"
    r"(?:^|_)(?:api|auth|access|private|secret)[_-]?key(?:_|$)",
    re.IGNORECASE,
)

# Minimum length and entropy for a string to be considered a potential secret
# when the variable name matches _SECRET_VAR_PATTERN.
_MIN_SECRET_LEN = 16
_MIN_SECRET_ENTROPY = 3.0


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


class _HardcodedSecretVisitor(ast.NodeVisitor):
    """Walk an AST and flag string constants that look like secrets."""

    def __init__(self) -> None:
        self.findings: list[tuple[int, str]] = []

    def _check_assignment(self, lineno: int, var_name: str, value: str) -> None:
        """Shared logic for Assign and AnnAssign nodes."""
        # Check 1: known secret prefix
        prefix_hit = self._check_prefix(value)
        if prefix_hit:
            self.findings.append((
                lineno,
                f"String at line {lineno} matches known secret "
                f"prefix ({prefix_hit})",
            ))
        # Check 2: variable name suggests secret + high-entropy value
        elif (
            var_name
            and _SECRET_VAR_PATTERN.search(var_name)
            and len(value) >= _MIN_SECRET_LEN
            and _shannon_entropy(value) >= _MIN_SECRET_ENTROPY
        ):
            self.findings.append((
                lineno,
                f"Variable `{var_name}` at line {lineno} has a "
                f"secret-like name and high-entropy value "
                f"(entropy={_shannon_entropy(value):.1f} bits/char)",
            ))

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            var_name = self._get_assign_name(node)
            self._check_assignment(node.lineno, var_name, node.value.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Handle annotated assignments: API_KEY: str = "sk-..."."""
        if (
            node.value
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            var_name = ""
            if isinstance(node.target, ast.Name):
                var_name = node.target.id
            self._check_assignment(node.lineno, var_name, node.value.value)
        self.generic_visit(node)

    @staticmethod
    def _check_prefix(value: str) -> str | None:
        for prefix, label in _SECRET_PREFIXES:
            if value.startswith(prefix) and len(value) >= len(prefix) + 8:
                return label
        return None

    @staticmethod
    def _get_assign_name(node: ast.Assign) -> str:
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            return node.targets[0].id
        return ""


@register
class HardcodedSecretsInSource(Check):
    """MCPA-070 — hardcoded secrets in Python source files."""

    id = "MCPA-070"
    name = "Hardcoded secret in source code"
    description = (
        "Conservative AST heuristic: scans Python source for string literals "
        "matching known secret prefixes (sk-, ghp_, AKIA, xoxb-, etc.) and "
        "for high-entropy strings assigned to secret-named variables. "
        "May produce false positives on example/placeholder strings."
    )
    category = Category.CONFIGURATION
    default_severity = Severity.HIGH

    async def run(self, target: McpTarget) -> list[Finding]:
        if not target.source_path:
            return []

        root = Path(target.source_path)
        if not root.exists():
            return []

        findings: list[Finding] = []
        for py_file in _collect_python_files(root):
            tree = _parse_file(py_file)
            if tree is None:
                continue
            visitor = _HardcodedSecretVisitor()
            visitor.visit(tree)
            for lineno, detail in visitor.findings:
                rel = py_file.relative_to(root)
                findings.append(
                    self.finding(
                        title=f"Hardcoded secret in `{rel}:{lineno}`",
                        description=(
                            "A string literal in the source code matches a known "
                            "secret prefix or has a secret-like variable name with "
                            "high entropy. Secrets in source code can be extracted "
                            "from version control, container images, or crash dumps."
                        ),
                        evidence=detail,
                        remediation=(
                            "Move secrets to environment variables or a secrets "
                            "manager. Never commit secrets to source control.\n"
                            "  import os\n"
                            '  API_KEY = os.environ["API_KEY"]'
                        ),
                    )
                )
        return findings


# ── MCPA-060: SSRF sink in HTTP-fetch tools ───────────────────────────────────

# HTTP client methods that take a URL as first positional argument.
_HTTP_FETCH_METHODS = {
    # httpx
    "get", "post", "put", "patch", "delete", "head", "options", "request",
    # requests
    # (same method names — requests.get, httpx.get, etc.)
    # urllib
    "urlopen",
}

# Modules whose methods are HTTP fetch sinks.
_HTTP_FETCH_MODULES = {"httpx", "requests", "urllib"}

# ── SSRF guard detection with lightweight dataflow tracking ─────────────────
#
# We trace the fetched URL variable through one level of assignment:
#
#   url → urlparse(url) → parsed → parsed.hostname in ALLOWED
#
# Only when we can connect the fetch's URL to a membership test against
# a collection do we suppress the finding. This avoids false-cleans from
# equality against arbitrary variables, bare hostname access, unrelated
# parsing, and validation calls on other data.
#
# Limitations (honest):
# - Single-hop tracking only — `host = parsed.hostname; if host in X` is
#   not followed. This causes false positives on well-structured code.
# - Helper-name guards (validate_url, check_url) are trust-based: we
#   assume a function with a validation-shaped name actually validates.
#   A no-op helper with the right name would suppress the finding.
# - Module-scope names used as membership targets (e.g. ALLOWED_HOSTS)
#   are trusted without verifying their assignment. Dynamic globals like
#   ALLOWED = load_policy() or ALLOWED = os.environ["ALLOW"] would
#   false-clean. Fixing this requires whole-file analysis.
# - DNS resolution (getaddrinfo, gethostbyname) is NOT treated as a guard
#   because resolution without result inspection proves nothing.

# Attributes on a urlparse/urlsplit result that indicate host inspection
# when used in a membership test (in, not in) against a collection.
# Equality (==, !=) against a single variable is too ambiguous — could be
# attacker-controlled — so only membership operators are accepted.
_SSRF_HOST_ATTRS = {"hostname", "netloc"}

# Method calls that ARE validation when called on a URL-derived value.
# DNS resolution (getaddrinfo, gethostbyname) is deliberately excluded:
# resolution without result inspection proves nothing about the host.
_SSRF_VALIDATION_CALLS = {
    "is_private", "is_loopback", "is_reserved",
}

# Function names assumed to validate when called with the URL variable.
# Trust-based heuristic: we cannot inspect the helper body, so a no-op
# helper with the right name would suppress the finding. Documented as
# a known limitation of AST-level analysis.
_SSRF_GUARD_CALL_NAMES = {
    "validate_url", "check_url", "allowed_host", "is_allowed",
}

# urlparse/urlsplit — used to find parse-result variable names.
_URL_PARSE_FUNCS = {"urlparse", "urlsplit"}


def _find_parse_result_names(
    func_node: ast.FunctionDef, url_var: str,
) -> set[str]:
    """Find variable names assigned from urlparse(url_var) / urlsplit(url_var).

    Returns the set of variable names that hold a parsed-URL result derived
    from the given URL variable. Only handles direct single assignment:
    ``parsed = urlparse(url)``."""
    names: set[str] = set()
    for node in ast.walk(func_node):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        fname = ""
        if isinstance(call.func, ast.Name):
            fname = call.func.id
        elif isinstance(call.func, ast.Attribute):
            fname = call.func.attr
        if fname not in _URL_PARSE_FUNCS:
            continue
        # First arg must be the URL variable
        if call.args and isinstance(call.args[0], ast.Name) and call.args[0].id == url_var:
            names.add(target.id)
    return names


_COLLECTION_LITERALS = (ast.Set, ast.List, ast.Tuple, ast.Dict)


def _classify_local_names(
    func_node: ast.FunctionDef,
) -> tuple[set[str], set[str]]:
    """Classify locally assigned names by whether all assignments are literals.

    Scans both Assign and AnnAssign. Returns (all_literal, any_assigned):
    - all_literal: names whose EVERY assignment is a literal collection
    - any_assigned: names that have ANY local assignment (literal or not)

    If a name is in any_assigned but not all_literal, it had at least one
    non-literal assignment and should not be trusted.
    """
    all_literal: dict[str, bool] = {}
    for node in ast.walk(func_node):
        name: str | None = None
        value: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                name = target.id
                value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value:
            if isinstance(node.target, ast.Name):
                name = node.target.id
                value = node.value
        if name is not None and value is not None:
            is_literal = isinstance(value, _COLLECTION_LITERALS)
            all_literal[name] = all_literal.get(name, True) and is_literal

    trusted = {n for n, ok in all_literal.items() if ok}
    assigned = set(all_literal.keys())
    return trusted, assigned


def _is_hostname_policy_check(
    compare: ast.Compare,
    parse_results: set[str],
    param_names: set[str],
    func_node: ast.FunctionDef,
) -> bool:
    """True if a Compare node is a hostname/netloc membership test against
    a policy-looking collection.

    Requirements:
    - One side is parsed.hostname/netloc where parsed is a URL-derived result
    - The other side (the container) is one of:
      - A literal collection (set, list, tuple, dict)
      - A local name whose EVERY assignment (Assign and AnnAssign) is a
        literal collection — if any branch assigns from a non-literal,
        the name is rejected (fail closed)
      - A bare Name not assigned within the function (assumed module-scope
        constant — trust-based; dynamic globals like
        ``ALLOWED = load_policy()`` would false-clean here)
    - Rejected: function parameters (all categories), attribute chains,
      Names with any non-literal local assignment.
    """
    # Find which side is the hostname attr and which is the container.
    hostname_side = None
    container_side = None

    all_parts = [compare.left, *compare.comparators]
    for part in all_parts:
        if (
            isinstance(part, ast.Attribute)
            and part.attr in _SSRF_HOST_ATTRS
            and isinstance(part.value, ast.Name)
            and part.value.id in parse_results
        ):
            hostname_side = part

    if hostname_side is None:
        return False

    # The container is the other side.
    for part in all_parts:
        if part is not hostname_side:
            container_side = part
            break

    if container_side is None:
        return False

    # Accept: literal collection directly in the comparison
    if isinstance(container_side, _COLLECTION_LITERALS):
        return True

    # Accept: bare Name, but only if it's trustworthy
    if isinstance(container_side, ast.Name):
        name = container_side.id

        # Reject function parameters (attacker-controlled)
        if name in param_names:
            return False

        literal_locals, assigned_locals = _classify_local_names(func_node)

        # Locally assigned from ONLY literal collections — trusted
        if name in literal_locals:
            return True

        # Locally assigned with any non-literal — fail closed
        if name in assigned_locals:
            return False

        # Not assigned locally and not a parameter — module-scope.
        # Trust-based: we assume module-scope names are developer-controlled
        # constants (e.g. ALLOWED_HOSTS = {"api.example.com"}). Dynamic
        # globals like ALLOWED = load_policy() would false-clean here.
        # Fixing this requires whole-file analysis, which is beyond our
        # single-function AST scope.
        return True

    return False


class _SsrfSinkVisitor(ast.NodeVisitor):
    """Walk an AST and flag HTTP fetch calls with no host validation."""

    def __init__(self) -> None:
        self.findings: list[tuple[int, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        func_name, module_hint = self._get_call_info(node)

        if func_name in _HTTP_FETCH_METHODS and module_hint in _HTTP_FETCH_MODULES:
            url_arg = self._extract_url_arg(func_name, node)
            if url_arg and not isinstance(url_arg, ast.Constant):
                # Extract URL variable name for dataflow tracking.
                # If not a simple Name (e.g. f-string, subscript), we can't
                # trace it, so url_var stays empty and no guard is recognized.
                url_var = url_arg.id if isinstance(url_arg, ast.Name) else ""
                parent_func = getattr(self, "_current_func", None)
                if parent_func and not self._has_ssrf_guard(parent_func, url_var):
                    detail = (
                        f"`{module_hint}.{func_name}()` at line {node.lineno} "
                        f"with variable URL and no host validation"
                    )
                    self.findings.append((node.lineno, detail))

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old = getattr(self, "_current_func", None)
        self._current_func = node
        self.generic_visit(node)
        self._current_func = old

    visit_AsyncFunctionDef = visit_FunctionDef

    @staticmethod
    def _extract_url_arg(func_name: str, node: ast.Call) -> ast.expr | None:
        """Return the AST node for the URL argument of an HTTP call.

        For request(method, url, ...) the URL is the second positional arg.
        For get(url, ...), post(url, ...), etc. it's the first.
        Also checks for a url= keyword argument.
        """
        # Keyword url=... takes precedence
        for kw in node.keywords:
            if kw.arg == "url":
                return kw.value

        if func_name == "request":
            # requests.request("GET", url) / httpx.request("GET", url)
            return node.args[1] if len(node.args) >= 2 else None
        # All other methods: get(url), post(url), urlopen(url), etc.
        return node.args[0] if node.args else None

    @staticmethod
    def _get_call_info(node: ast.Call) -> tuple[str, str]:
        """Return (method_name, module_hint) for a call node."""
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            # httpx.get(...) or requests.get(...)
            if isinstance(node.func.value, ast.Name):
                return method, node.func.value.id
            # urllib.request.urlopen(...)
            if (
                isinstance(node.func.value, ast.Attribute)
                and isinstance(node.func.value.value, ast.Name)
            ):
                return method, node.func.value.value.id
        if isinstance(node.func, ast.Name):
            # Only treat bare urlopen() as a urllib sink — other bare names
            # like get() or post() are too ambiguous (could be local helpers).
            if node.func.id == "urlopen":
                return node.func.id, "urllib"
        return "", ""

    @staticmethod
    def _has_ssrf_guard(func_node: ast.FunctionDef, url_var: str) -> bool:
        """Check if the function validates the URL host before fetching.

        Uses lightweight dataflow: traces url_var through urlparse/urlsplit
        to a result variable, then checks if that result's hostname/netloc
        appears in a membership test (in/not in). Equality comparisons are
        not accepted (too ambiguous). DNS resolution alone is not accepted
        (proves nothing without result inspection). Helper-name guards
        (validate_url, check_url) are trust-based. If url_var is empty
        (non-Name URL expression), no guard is recognized.
        """
        if not url_var:
            return False

        # Step 1: find variables assigned from urlparse(url_var).
        parse_results = _find_parse_result_names(func_node, url_var)

        # Function parameters are attacker-controlled — reject them as
        # membership targets (e.g. `hostname in attacker_supplied_hosts`).
        param_names: set[str] = {
            arg.arg
            for arg in (
                func_node.args.args
                + func_node.args.posonlyargs
                + func_node.args.kwonlyargs
            )
        }
        if func_node.args.vararg:
            param_names.add(func_node.args.vararg.arg)
        if func_node.args.kwarg:
            param_names.add(func_node.args.kwarg.arg)

        for node in ast.walk(func_node):
            # Guard pattern 1: parsed.hostname in ALLOWED (membership only).
            # Only membership ops (in, not in) are accepted. The container
            # (the other side) must look like a policy collection:
            # - bare Name that is NOT a function parameter (e.g. ALLOWED)
            # - literal set/list/tuple/dict (e.g. {"host1", "host2"})
            # Rejected: attribute chains (request.headers), function params.
            if isinstance(node, ast.Compare):
                has_membership_op = any(
                    isinstance(op, (ast.In, ast.NotIn)) for op in node.ops
                )
                if has_membership_op and _is_hostname_policy_check(
                    node, parse_results, param_names, func_node,
                ):
                    return True

            # Guard pattern 2: obj.is_private() / obj.is_loopback() /
            # obj.is_reserved() where a URL-derived host attribute is
            # passed as argument, e.g. `checker.is_private(parsed.hostname)`.
            # Does NOT match ip_address(hostname).is_private() — that
            # requires multi-hop tracking beyond our scope.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in _SSRF_VALIDATION_CALLS:
                    for arg in node.args:
                        if (
                            isinstance(arg, ast.Attribute)
                            and arg.attr in _SSRF_HOST_ATTRS
                            and isinstance(arg.value, ast.Name)
                            and arg.value.id in parse_results
                        ):
                            return True

            # Guard pattern 3: validate_url(url) / check_url(url).
            # Trust-based: assumes the helper actually validates.
            # Only counts when the fetched URL variable is passed.
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in _SSRF_GUARD_CALL_NAMES:
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id == url_var:
                            return True

        return False


@register
class SsrfSinkInHandlers(Check):
    """MCPA-060 — SSRF sink in HTTP-fetch tools."""

    id = "MCPA-060"
    name = "SSRF sink: HTTP fetch with no host validation"
    description = (
        "AST heuristic with lightweight dataflow: flags HTTP client calls "
        "(httpx, requests, urllib) where the URL comes from a variable and "
        "the enclosing function has no host validation tied to that URL. "
        "Traces the URL through urlparse/urlsplit to hostname/netloc "
        "membership tests (in/not in). Equality comparisons are not "
        "accepted as guards. Helper-name guards (validate_url, check_url) "
        "are trust-based. May false-positive when validation uses "
        "intermediate variables the single-hop tracker can't follow."
    )
    category = Category.DATA_EXFILTRATION
    default_severity = Severity.HIGH

    async def run(self, target: McpTarget) -> list[Finding]:
        if not target.source_path:
            return []

        root = Path(target.source_path)
        if not root.exists():
            return []

        findings: list[Finding] = []
        for py_file in _collect_python_files(root):
            tree = _parse_file(py_file)
            if tree is None:
                continue
            visitor = _SsrfSinkVisitor()
            visitor.visit(tree)
            for lineno, detail in visitor.findings:
                rel = py_file.relative_to(root)
                findings.append(
                    self.finding(
                        title=f"SSRF sink in `{rel}:{lineno}`",
                        description=(
                            "An HTTP fetch call uses a variable URL with no host "
                            "validation in the enclosing function. Without an "
                            "allowlist, an attacker can force the server to fetch "
                            "internal URLs (cloud metadata, localhost services, "
                            "RFC1918 addresses)."
                        ),
                        evidence=detail,
                        remediation=(
                            "Parse the URL and validate the host before fetching:\n"
                            "  from urllib.parse import urlparse\n"
                            "  parsed = urlparse(url)\n"
                            "  if parsed.hostname not in ALLOWED_HOSTS:\n"
                            "      raise ValueError('host not allowed')\n"
                            "Also block requests to private/loopback IP ranges."
                        ),
                    )
                )
        return findings
