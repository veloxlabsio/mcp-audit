"""CLI contract tests — verify exit codes, not just internal semantics.

These use typer.testing.CliRunner to invoke the actual CLI entry point and
assert on exit codes + output content.
"""
from __future__ import annotations

from typer.testing import CliRunner

from mcp_audit.cli import app

runner = CliRunner()


def test_no_args_shows_help() -> None:
    """No arguments should print help text (typer exits 2 for no-args-is-help)."""
    result = runner.invoke(app, [])
    # typer no_args_is_help causes exit 2 via click, which is correct behavior
    assert result.exit_code in (0, 2)
    assert "scan" in result.output.lower() or "Usage" in result.output


def test_scan_missing_target_exits_2() -> None:
    """scan without --stdio or --url should exit 2."""
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 2
    assert "provide --stdio or --url" in result.output


def test_scan_both_targets_exits_2() -> None:
    """scan with both --stdio and --url should exit 2."""
    result = runner.invoke(app, ["scan", "--stdio", "echo", "--url", "http://localhost"])
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_scan_bad_severity_exits_2() -> None:
    """scan with invalid severity should exit 2."""
    result = runner.invoke(app, ["scan", "--stdio", "echo", "--severity", "banana"])
    assert result.exit_code == 2
    assert "invalid severity" in result.output


def test_scan_bad_format_exits_2() -> None:
    """scan with unknown format should exit 2."""
    result = runner.invoke(app, ["scan", "--stdio", "echo", "--format", "xml"])
    assert result.exit_code == 2
    assert "unknown format" in result.output


def test_scan_output_with_terminal_format_exits_2() -> None:
    """--output with --format terminal should exit 2."""
    result = runner.invoke(app, ["scan", "--stdio", "echo", "--output", "/tmp/x", "--format", "terminal"])
    assert result.exit_code == 2
    assert "requires --format json or --format markdown" in result.output


def test_scan_vulnerable_mcp_exits_1() -> None:
    """Scanning vulnerable-mcp should exit 1 (findings detected)."""
    result = runner.invoke(app, ["scan", "--stdio", "python3 -m vulnerable_mcp.server"])
    assert result.exit_code == 1
    assert "MCPA-001" in result.output
    assert "MCPA-002" in result.output


def test_scan_vulnerable_mcp_json_exits_1() -> None:
    """JSON output against vulnerable-mcp should also exit 1."""
    result = runner.invoke(app, ["scan", "--stdio", "python3 -m vulnerable_mcp.server", "-f", "json"])
    assert result.exit_code == 1
    assert '"MCPA-001"' in result.output


def test_scan_vulnerable_mcp_no_false_criticals_from_introspection() -> None:
    """vulnerable-mcp only advertises tools, not resources/prompts.
    The scanner must NOT produce CRITICAL introspection findings for
    endpoints the server doesn't advertise."""
    result = runner.invoke(app, ["scan", "--stdio", "python3 -m vulnerable_mcp.server", "-f", "json"])
    # Should not contain introspection CRITICAL findings
    assert "INTROSPECTION FAILED" not in result.output
    # But should still have real tool-schema findings
    assert "MCPA-001" in result.output


def test_scan_vulnerable_mcp_with_source_catches_all_five() -> None:
    """--source against vulnerable-mcp must produce actual findings for
    MCPA-010, MCPA-012, MCPA-060, and MCPA-070. This is the 5/5 regression
    gate. We parse the JSON and check the flattened findings list, not just
    whether check IDs appear in the output."""
    import json

    result = runner.invoke(app, [
        "scan", "--stdio", "python3 -m vulnerable_mcp.server",
        "--source", "./vulnerable_mcp", "-f", "json",
    ])
    assert result.exit_code == 1
    report = json.loads(result.output)

    # Flatten all findings from all results
    all_findings = []
    for r in report["results"]:
        all_findings.extend(r["findings"])

    finding_ids = [f["check_id"] for f in all_findings]
    assert "MCPA-001" in finding_ids
    assert "MCPA-010" in finding_ids
    assert "MCPA-012" in finding_ids
    assert "MCPA-060" in finding_ids
    assert "MCPA-070" in finding_ids

    # MCPA-070: must have found the hardcoded secret
    mcpa_070_findings = [f for f in all_findings if f["check_id"] == "MCPA-070"]
    assert len(mcpa_070_findings) >= 1
    assert mcpa_070_findings[0]["severity"] == "high"
    assert "server.py" in mcpa_070_findings[0]["title"]

    # MCPA-060: must have found the SSRF sink
    mcpa_060_findings = [f for f in all_findings if f["check_id"] == "MCPA-060"]
    assert len(mcpa_060_findings) >= 1
    assert mcpa_060_findings[0]["severity"] == "high"


def test_scan_benign_server_exits_0() -> None:
    """Scanning a clean server with no findings should exit 0."""
    result = runner.invoke(app, ["scan", "--stdio", "python3 tests/benign_server.py"])
    assert result.exit_code == 0
    assert "No findings" in result.output


def test_scan_benign_server_json_exits_0() -> None:
    """Clean server JSON output should exit 0 with empty findings array."""
    result = runner.invoke(app, ["scan", "--stdio", "python3 tests/benign_server.py", "-f", "json"])
    assert result.exit_code == 0
    assert '"findings": []' in result.output


def test_list_checks() -> None:
    result = runner.invoke(app, ["list-checks"])
    assert result.exit_code == 0
    assert "MCPA-001" in result.output
    assert "MCPA-002" in result.output


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "mcp-audit" in result.output
