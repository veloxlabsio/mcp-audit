"""Tests for MCPA-020 — curated CVE match on declared dependencies."""
from __future__ import annotations

import asyncio
import tempfile
import textwrap
from pathlib import Path
from types import SimpleNamespace

from mcp_audit.checks.dependencies import DependencyCveMatch


def _target_with(files: dict[str, str]) -> SimpleNamespace:
    """Write ``files`` (relpath -> content) into a temp dir, return mock target."""
    tmp = tempfile.mkdtemp()
    for rel, content in files.items():
        (Path(tmp) / rel).write_text(textwrap.dedent(content))
    return SimpleNamespace(source_path=tmp)


def _run(target: SimpleNamespace) -> list:
    return asyncio.run(DependencyCveMatch().run(target))  # type: ignore[arg-type]


# ── Positive cases ─────────────────────────────────────────────────────────

def test_020_flags_vulnerable_python_multipart_in_pyproject() -> None:
    target = _target_with({
        "pyproject.toml": """
        [project]
        name = "demo"
        version = "0.1.0"
        dependencies = ["python-multipart==0.0.6"]
        """,
    })
    findings = _run(target)
    assert any(f.check_id == "MCPA-020" for f in findings)
    assert any("CVE-2024-24762" in f.title for f in findings)


def test_020_flags_permissive_spec_that_includes_vulnerable() -> None:
    # >=0.0.5 permits 0.0.6 (vulnerable). Should flag.
    target = _target_with({
        "pyproject.toml": """
        [project]
        name = "demo"
        version = "0.1.0"
        dependencies = ["python-multipart>=0.0.5"]
        """,
    })
    findings = _run(target)
    assert any(f.check_id == "MCPA-020" for f in findings)


def test_020_flags_requirements_txt() -> None:
    target = _target_with({
        "requirements.txt": "idna==3.6\n",
    })
    findings = _run(target)
    assert any(
        f.check_id == "MCPA-020" and "CVE-2024-3651" in f.title
        for f in findings
    )


def test_020_flags_poetry_caret_spec() -> None:
    # ^42.0.0 = >=42.0.0,<43.0.0 — permits 42.0.3 (vulnerable). Should flag.
    target = _target_with({
        "pyproject.toml": """
        [tool.poetry.dependencies]
        python = "^3.11"
        cryptography = "^42.0.0"
        """,
    })
    findings = _run(target)
    assert any(
        f.check_id == "MCPA-020" and "cryptography" in f.title
        for f in findings
    )


# ── Negative cases ─────────────────────────────────────────────────────────

def test_020_clean_when_pinned_above_fix() -> None:
    target = _target_with({
        "pyproject.toml": """
        [project]
        name = "demo"
        version = "0.1.0"
        dependencies = ["python-multipart>=0.0.9"]
        """,
    })
    assert _run(target) == []


def test_020_clean_when_no_tracked_packages() -> None:
    target = _target_with({
        "pyproject.toml": """
        [project]
        name = "demo"
        version = "0.1.0"
        dependencies = ["fastapi>=0.110.0", "uvicorn>=0.28.0"]
        """,
    })
    assert _run(target) == []


def test_020_clean_when_no_manifest() -> None:
    tmp = tempfile.mkdtemp()
    (Path(tmp) / "server.py").write_text("print('hi')\n")
    target = SimpleNamespace(source_path=tmp)
    assert _run(target) == []


def test_020_skips_when_no_source_path() -> None:
    target = SimpleNamespace(source_path=None)
    assert _run(target) == []


# ── Parser edge cases ──────────────────────────────────────────────────────

def test_020_handles_requirements_comments_and_blanks() -> None:
    target = _target_with({
        "requirements.txt": """
        # this is a comment

        idna==3.6  # inline comment
        -e ./local-pkg
        --index-url https://example.com
        git+https://github.com/x/y.git@main
        """,
    })
    findings = _run(target)
    assert any(f.check_id == "MCPA-020" for f in findings)


def test_020_dedup_between_manifests() -> None:
    # Same package vulnerable in both files — should only flag once per
    # (package, cve, manifest) tuple. With both manifests, two findings.
    target = _target_with({
        "pyproject.toml": """
        [project]
        name = "demo"
        version = "0.1.0"
        dependencies = ["idna==3.6"]
        """,
        "requirements.txt": "idna==3.6\n",
    })
    findings = _run(target)
    # Two findings: one per manifest. Not one per manifest repetition.
    idna_findings = [f for f in findings if "idna" in f.title]
    assert len(idna_findings) == 2
