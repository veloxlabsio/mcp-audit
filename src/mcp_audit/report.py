"""Report formatters — terminal, Markdown, JSON.

All formatters surface introspection errors and check execution errors
prominently. A security scanner must never say "clean" when something failed.
"""
from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_audit.checks.base import Severity
from mcp_audit.runner import ScanReport

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def print_terminal(report: ScanReport, console: Console | None = None) -> None:
    console = console or Console()

    counts = report.summary_counts()
    checks_run = len([r for r in report.results if not r.skipped])
    checks_errored = len(report.check_errors)

    header = Table.grid(padding=(0, 2))
    header.add_row("[bold]mcp-scan[/bold]", f"target: [cyan]{report.target_description}[/cyan]")
    header.add_row("checks run", str(checks_run))
    header.add_row("findings", str(len(report.findings)))
    if checks_errored:
        header.add_row("[red]check errors[/red]", f"[red]{checks_errored}[/red]")
    if report.critical_introspection_errors:
        header.add_row(
            "[red]introspection errors[/red]",
            f"[red]{len(report.critical_introspection_errors)}[/red]",
        )
    if report.info_introspection_errors:
        header.add_row(
            "[dim]introspection notes[/dim]",
            f"[dim]{len(report.info_introspection_errors)}[/dim]",
        )
    console.print(header)
    console.print()

    # ── Critical introspection errors — LOUD ──
    if report.critical_introspection_errors:
        console.print(
            Panel(
                "\n".join(
                    f"{ie.endpoint}: {ie.error}"
                    for ie in report.critical_introspection_errors
                ),
                title="[bold red]INTROSPECTION FAILED[/bold red]",
                subtitle="Scanner could not see the full attack surface. Do NOT trust this result.",
                border_style="red",
            )
        )
        console.print()

    # ── Non-advertised introspection errors — dim/informational ──
    if report.info_introspection_errors:
        for ie in report.info_introspection_errors:
            console.print(f"[dim]info: {ie.endpoint} not supported ({ie.error})[/dim]")
        console.print()

    # ── Check execution errors ──
    for r in report.check_errors:
        console.print(f"[red]CHECK ERROR[/red] {r.check_id} ({r.check_name}): {r.error}")
    if report.check_errors:
        console.print()

    # ── Severity summary ──
    summary = Table(title="Summary by severity", show_header=True, header_style="bold")
    summary.add_column("severity")
    summary.add_column("count", justify="right")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        c = counts[sev.value]
        style = SEVERITY_STYLE[sev.value] if c > 0 else "dim"
        summary.add_row(f"[{style}]{sev.value}[/{style}]", str(c))
    console.print(summary)
    console.print()

    # ── Findings ──
    if not report.findings and not report.check_errors and not report.critical_introspection_errors:
        console.print("[green]No findings. All checks passed.[/green]")
        return

    if not report.findings:
        return

    for finding in sorted(report.findings, key=lambda f: -f.severity.rank):
        style = SEVERITY_STYLE[finding.severity.value]
        console.rule(f"[{style}]{finding.severity.value.upper()}[/{style}]  {finding.title}")
        console.print(f"[dim]check:[/dim] {finding.check_id}  [dim]category:[/dim] {finding.category.value}")
        console.print()
        console.print(finding.description)
        if finding.evidence:
            console.print()
            console.print("[bold]Evidence[/bold]")
            console.print(f"  {finding.evidence}")
        if finding.remediation:
            console.print()
            console.print("[bold]Remediation[/bold]")
            console.print(f"  {finding.remediation}")
        if finding.reference:
            console.print()
            console.print(f"[dim]ref:[/dim] {finding.reference}")
        console.print()


def to_json(report: ScanReport) -> str:
    payload = {
        "target": report.target_description,
        "started_at": report.started_at,
        "finished_at": report.finished_at,
        "server_info": report.server_info,
        "summary": report.summary_counts(),
        "introspection_errors": [
            {
                "endpoint": ie.endpoint,
                "error": ie.error,
                "advertised": ie.advertised,
                "severity": "critical" if ie.advertised else "info",
            }
            for ie in report.introspection_errors
        ],
        "check_errors": [
            {"check_id": r.check_id, "check_name": r.check_name, "error": r.error}
            for r in report.check_errors
        ],
        "results": [
            {
                "check_id": r.check_id,
                "check_name": r.check_name,
                "skipped": r.skipped,
                "skip_reason": r.skip_reason,
                "error": r.error,
                "findings": [f.to_dict() for f in r.findings],
            }
            for r in report.results
        ],
    }
    return json.dumps(payload, indent=2)


def to_markdown(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append("# mcp-scan report")
    lines.append("")
    lines.append(f"**Target:** `{report.target_description}`  ")
    lines.append(f"**Started:** {report.started_at}  ")
    lines.append(f"**Finished:** {report.finished_at}  ")
    lines.append("")

    if report.critical_introspection_errors:
        lines.append("## !! INTROSPECTION FAILED")
        lines.append("")
        lines.append(
            "**The scanner could not see the full attack surface. Do NOT trust this result.**"
        )
        lines.append("")
        for ie in report.critical_introspection_errors:
            lines.append(f"- `{ie.endpoint}: {ie.error}`")
        lines.append("")

    if report.info_introspection_errors:
        lines.append("## Introspection notes (informational)")
        lines.append("")
        for ie in report.info_introspection_errors:
            lines.append(f"- `{ie.endpoint}`: {ie.error} _(not advertised by server)_")
        lines.append("")

    if report.check_errors:
        lines.append("## Check execution errors")
        lines.append("")
        for r in report.check_errors:
            lines.append(f"- `{r.check_id}` ({r.check_name}): {r.error}")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| severity | count |")
    lines.append("|---|---:|")
    for sev, count in report.summary_counts().items():
        lines.append(f"| {sev} | {count} |")
    lines.append("")

    if not report.findings:
        if report.critical_introspection_errors or report.check_errors:
            lines.append("_No findings from the checks that ran, but errors occurred above._")
        else:
            lines.append("_No findings. All checks passed._")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    for finding in sorted(report.findings, key=lambda f: -f.severity.rank):
        lines.append(f"### [{finding.severity.value.upper()}] {finding.title}")
        lines.append("")
        lines.append(f"- **Check:** `{finding.check_id}`")
        lines.append(f"- **Category:** {finding.category.value}")
        lines.append("")
        lines.append(finding.description)
        if finding.evidence:
            lines.append("")
            lines.append("**Evidence**")
            lines.append("")
            lines.append(f"```\n{finding.evidence}\n```")
        if finding.remediation:
            lines.append("")
            lines.append(f"**Remediation:** {finding.remediation}")
        if finding.reference:
            lines.append("")
            lines.append(f"**Reference:** {finding.reference}")
        lines.append("")

    return "\n".join(lines)
