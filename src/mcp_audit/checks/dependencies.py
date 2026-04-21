"""MCPA-020 — Vulnerable dependency match.

Parses ``pyproject.toml`` or ``requirements.txt`` from the target's source
tree, extracts declared package + version specifier pairs, and matches them
against a small curated database of known CVEs in MCP-adjacent packages.

Design notes:

- **Offline / deterministic.** The advisory DB is bundled in source. No
  network calls. This matches mcp-audit's core promise. The trade-off is
  coverage — we catch only what we explicitly curate. For full coverage
  use ``pip-audit`` or ``osv-scanner`` alongside mcp-audit.
- **Match rule.** A declared specifier is considered vulnerable if it
  *permits* any version inside the advisory's vulnerable range. Example:
  ``python-multipart>=0.0.5`` permits 0.0.6 (vulnerable) so we flag it.
  ``python-multipart>=0.0.9`` does not permit anything in the vulnerable
  range so it's clean.
- **Scope.** Only top-level declared dependencies. Transitive resolution
  is out of scope — it requires a solver and a lockfile. Users running
  Poetry/uv should export a lockfile and audit that separately.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from mcp_audit.checks import register
from mcp_audit.checks.base import Category, Check, Finding, Severity
from mcp_audit.client import McpTarget


# ── Curated advisory database ──────────────────────────────────────────────
# Only includes CVEs the author has verified against the official advisory.
# This is intentionally small. Contributions welcome in dependencies.py.

@dataclass(frozen=True)
class _Advisory:
    package: str  # PyPI name, lowercase
    vulnerable: str  # SpecifierSet string, e.g. "<0.0.7"
    cve_id: str
    severity: Severity
    summary: str
    fixed_in: str  # earliest fixed version, human-readable
    reference: str


_ADVISORY_DB: list[_Advisory] = [
    _Advisory(
        package="python-multipart",
        vulnerable="<0.0.7",
        cve_id="CVE-2024-24762",
        severity=Severity.HIGH,
        summary=(
            "ReDoS in Content-Type header parsing. A crafted Content-Type "
            "causes catastrophic backtracking, stalling the server. Exposed "
            "via any Starlette/FastAPI MCP server accepting multipart form "
            "data."
        ),
        fixed_in="0.0.7",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2024-24762",
    ),
    _Advisory(
        package="idna",
        vulnerable="<3.7",
        cve_id="CVE-2024-3651",
        severity=Severity.MEDIUM,
        summary=(
            "Quadratic complexity in idna.encode() when processing crafted "
            "internationalized domain names. Can be triggered by any code "
            "path that parses attacker-supplied URLs — including MCP tools "
            "that call httpx/requests with a user-provided URL."
        ),
        fixed_in="3.7",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2024-3651",
    ),
    _Advisory(
        package="cryptography",
        vulnerable="<42.0.4",
        cve_id="CVE-2024-26130",
        severity=Severity.HIGH,
        summary=(
            "NULL pointer dereference in PKCS#12 parsing when the input "
            "lacks a certificate. Reachable in MCP servers that accept "
            "user-provided key material (auth flows, upload tools)."
        ),
        fixed_in="42.0.4",
        reference="https://nvd.nist.gov/vuln/detail/CVE-2024-26130",
    ),
]


# ── Dependency parsers ─────────────────────────────────────────────────────

_REQ_LINE_CONTINUATION = re.compile(r"\\\s*\n")


def _parse_pyproject(path: Path) -> list[tuple[str, SpecifierSet]]:
    """Return (name, specifier) for every declared dep in pyproject.toml.

    Handles PEP 621 ``[project.dependencies]`` and Poetry
    ``[tool.poetry.dependencies]``. Optional-dependency groups and
    dev-dependencies are skipped — runtime deps are the SSRF surface.
    """
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []

    pairs: list[tuple[str, SpecifierSet]] = []

    # PEP 621 style
    project = data.get("project", {})
    for dep_str in project.get("dependencies", []) or []:
        parsed = _parse_pep508(dep_str)
        if parsed:
            pairs.append(parsed)

    # Poetry style — maps name -> spec string (or table with "version" key)
    poetry_deps = (
        data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    )
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        spec_str = spec if isinstance(spec, str) else spec.get("version", "")
        if not spec_str:
            continue
        converted = _poetry_spec_to_pep440(spec_str)
        try:
            pairs.append((name.lower(), SpecifierSet(converted)))
        except Exception:
            continue

    return pairs


def _parse_requirements_txt(path: Path) -> list[tuple[str, SpecifierSet]]:
    """Return (name, specifier) for each line in a requirements.txt file.

    Comments, blank lines, ``-e`` editable installs, URL-based installs,
    and ``-r`` recursive includes are skipped. Line continuations with
    backslash are joined.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []

    joined = _REQ_LINE_CONTINUATION.sub(" ", text)
    pairs: list[tuple[str, SpecifierSet]] = []
    for raw_line in joined.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-", "--")):
            continue
        if "://" in line:
            continue
        parsed = _parse_pep508(line)
        if parsed:
            pairs.append(parsed)
    return pairs


def _parse_pep508(dep_str: str) -> tuple[str, SpecifierSet] | None:
    try:
        req = Requirement(dep_str)
    except InvalidRequirement:
        return None
    return req.name.lower(), req.specifier


def _poetry_spec_to_pep440(spec: str) -> str:
    """Convert Poetry's caret/tilde specifiers to a PEP 440 SpecifierSet.

    Poetry: ``^1.2.3`` means ``>=1.2.3,<2.0.0``. ``~1.2.3`` means
    ``>=1.2.3,<1.3.0``. Plain ``1.2.3`` means ``==1.2.3``. Already-PEP440
    specifiers pass through.
    """
    spec = spec.strip()
    if spec.startswith("^"):
        base = spec[1:]
        try:
            v = Version(base)
        except InvalidVersion:
            return ""
        # Next major: bump first non-zero component per Poetry's rule.
        parts = [v.major, v.minor, v.micro]
        for i, p in enumerate(parts):
            if p != 0 or i == len(parts) - 1:
                upper = list(parts)
                upper[i] = p + 1
                for j in range(i + 1, len(upper)):
                    upper[j] = 0
                return f">={base},<{'.'.join(str(x) for x in upper)}"
        return f">={base}"
    if spec.startswith("~"):
        base = spec[1:]
        try:
            v = Version(base)
        except InvalidVersion:
            return ""
        return f">={base},<{v.major}.{v.minor + 1}.0"
    if spec and spec[0] not in "<>=!~":
        return f"=={spec}"
    return spec


# ── Matcher ────────────────────────────────────────────────────────────────

def _spec_permits_vulnerable(
    declared: SpecifierSet, vulnerable: SpecifierSet,
) -> bool:
    """Return True if ``declared`` allows any version in ``vulnerable``.

    We enumerate the releases of every CVE's vulnerable range at a coarse
    grid (the fixed-version and each explicit bound) and test them against
    the user's declared specifier. If the user's spec says ``>=0.0.5`` and
    the CVE range is ``<0.0.7``, version 0.0.5 satisfies both → vulnerable.

    This is pragmatic, not exhaustive. We don't enumerate every PyPI
    release — we synthesize candidate versions from both SpecifierSets
    and check for overlap.
    """
    candidates = _candidate_versions(declared) | _candidate_versions(vulnerable)
    for v in candidates:
        if declared.contains(v, prereleases=True) and vulnerable.contains(
            v, prereleases=True,
        ):
            return True
    return False


def _candidate_versions(spec: SpecifierSet) -> set[Version]:
    """Pull bound versions out of a SpecifierSet as test candidates.

    For each spec like ``<0.0.7`` we extract ``0.0.7`` and also synthesize
    a "just below" version (``0.0.6.999``) so ranges like ``<X`` have
    something testable. This is intentionally coarse — correct for the
    ranges our advisory DB uses.
    """
    candidates: set[Version] = set()
    for s in spec:
        try:
            v = Version(s.version)
        except InvalidVersion:
            continue
        candidates.add(v)
        # For upper bounds, also test a value just below.
        if s.operator in ("<", "<="):
            # Bump micro down by synthesizing a prerelease pin.
            try:
                lower = Version(f"{v.major}.{v.minor}.{max(v.micro - 1, 0)}")
                candidates.add(lower)
            except InvalidVersion:
                pass
    return candidates


# ── Check ──────────────────────────────────────────────────────────────────

_MANIFEST_NAMES = ("pyproject.toml", "requirements.txt")


@register
class DependencyCveMatch(Check):
    """MCPA-020 — Curated CVE match against declared Python dependencies."""

    id = "MCPA-020"
    name = "Vulnerable dependency declared"
    description = (
        "Parses pyproject.toml and requirements.txt in the target's source "
        "tree and matches declared packages against a curated list of CVEs "
        "in MCP-adjacent packages (python-multipart, idna, cryptography, "
        "…). Offline and deterministic; trades coverage for reproducibility. "
        "Only top-level declared dependencies are checked — transitive "
        "resolution requires a lockfile and is out of scope."
    )
    category = Category.SUPPLY_CHAIN
    default_severity = Severity.HIGH

    async def run(self, target: McpTarget) -> list[Finding]:
        if not target.source_path:
            return []

        root = Path(target.source_path)
        if not root.exists():
            return []

        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()  # (package, cve, manifest)

        for manifest_name in _MANIFEST_NAMES:
            manifest = root / manifest_name
            if not manifest.is_file():
                continue

            if manifest_name == "pyproject.toml":
                deps = _parse_pyproject(manifest)
            else:
                deps = _parse_requirements_txt(manifest)

            for name, declared in deps:
                for advisory in _ADVISORY_DB:
                    if name != advisory.package:
                        continue
                    try:
                        vulnerable_spec = SpecifierSet(advisory.vulnerable)
                    except Exception:
                        continue
                    if not _spec_permits_vulnerable(declared, vulnerable_spec):
                        continue

                    key = (name, advisory.cve_id, manifest_name)
                    if key in seen:
                        continue
                    seen.add(key)

                    rel = manifest.relative_to(root)
                    findings.append(
                        self.finding(
                            title=(
                                f"{advisory.package} "
                                f"{advisory.cve_id} "
                                f"({advisory.severity.value})"
                            ),
                            severity=advisory.severity,
                            description=advisory.summary,
                            evidence=(
                                f"`{rel}` declares "
                                f"`{advisory.package}{declared}` which "
                                f"permits versions in the vulnerable range "
                                f"`{advisory.vulnerable}`."
                            ),
                            remediation=(
                                f"Pin to `{advisory.package}>="
                                f"{advisory.fixed_in}` or later and "
                                f"regenerate your lockfile."
                            ),
                            reference=advisory.reference,
                        )
                    )

        return findings
