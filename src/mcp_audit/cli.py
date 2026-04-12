"""mcp-audit command-line interface."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from mcp_audit import __version__
from mcp_audit.checks import REGISTRY
from mcp_audit.checks.base import Severity
from mcp_audit.client import McpTarget
from mcp_audit.report import print_terminal, to_json, to_markdown
from mcp_audit.runner import ScanReport, run_scan

# Importing for side-effect: each module registers its checks.
import mcp_audit.checks  # noqa: F401

app = typer.Typer(
    name="mcp-audit",
    help="Security scanner for Model Context Protocol (MCP) servers.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


@app.command()
def scan(
    stdio: Annotated[
        str | None,
        typer.Option("--stdio", help="Shell command to launch a stdio MCP server"),
    ] = None,
    url: Annotated[
        str | None,
        typer.Option("--url", help="URL of an HTTP/SSE MCP server (not yet implemented)"),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: terminal | json | markdown"),
    ] = "terminal",
    severity: Annotated[
        str,
        typer.Option("--severity", help="Minimum severity to run: critical|high|medium|low|info"),
    ] = "info",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write report to file (json or markdown only)"),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help="Timeout per MCP RPC call in seconds"),
    ] = 30.0,
    source: Annotated[
        Path | None,
        typer.Option("--source", help="Path to the MCP server source for AST checks"),
    ] = None,
) -> None:
    """Scan an MCP server for security issues."""
    if not stdio and not url:
        console.print("[red]error:[/red] provide --stdio or --url")
        raise typer.Exit(2)

    if stdio and url:
        console.print("[red]error:[/red] --stdio and --url are mutually exclusive")
        raise typer.Exit(2)

    if output and output_format == "terminal":
        console.print("[red]error:[/red] --output requires --format json or --format markdown")
        raise typer.Exit(2)

    try:
        severity_floor = Severity(severity.lower())
    except ValueError:
        console.print(f"[red]error:[/red] invalid severity '{severity}'")
        raise typer.Exit(2) from None

    if output_format not in ("terminal", "json", "markdown"):
        console.print(f"[red]error:[/red] unknown format '{output_format}'")
        raise typer.Exit(2)

    transport = "stdio" if stdio else "http"
    target = McpTarget(
        transport=transport,
        command=stdio,
        url=url,
        timeout=timeout,
        source_path=str(source) if source else None,
    )

    async def _scan():
        async with target as t:
            return await run_scan(t, severity_floor=severity_floor)

    try:
        report = asyncio.run(_scan())
    except Exception as exc:  # noqa: BLE001 — user-facing
        console.print(f"[red]scan failed:[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(1) from None

    # ── render output ─────────────────────────────────────────────────────
    if output_format == "json":
        text = to_json(report)
    elif output_format == "markdown":
        text = to_markdown(report)
    else:
        # terminal format — print directly, then exit
        print_terminal(report, console)
        _exit_on_problems(report)
        return

    if output:
        output.write_text(text)
        console.print(f"[green]wrote[/green] {output}")
    else:
        sys.stdout.write(text)
        sys.stdout.write("\n")

    _exit_on_problems(report)


def _exit_on_problems(report: ScanReport) -> None:
    """Exit non-zero if real problems exist: findings, check errors, or
    CRITICAL introspection errors. Non-advertised (INFO) introspection
    errors are informational and do not cause non-zero exit."""
    if report.check_errors:
        console.print(
            f"[red]{len(report.check_errors)} check(s) errored during execution.[/red]"
        )
    if report.critical_introspection_errors:
        console.print(
            f"[red]{len(report.critical_introspection_errors)} introspection call(s) failed.[/red]"
        )
    if report.has_problems:
        raise typer.Exit(1)


@app.command()
def list_checks() -> None:
    """List all registered checks."""
    if not REGISTRY:
        console.print("[yellow]No checks registered yet.[/yellow]")
        return

    from rich.table import Table

    table = Table(title=f"Registered checks ({len(REGISTRY)})")
    table.add_column("id")
    table.add_column("name")
    table.add_column("category")
    table.add_column("severity")
    for c in REGISTRY:
        table.add_row(c.id, c.name, c.category.value, c.default_severity.value)
    console.print(table)


@app.command()
def version() -> None:
    """Print mcp-audit version."""
    console.print(f"mcp-audit {__version__}")


if __name__ == "__main__":
    app()
