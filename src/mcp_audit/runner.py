"""Scan runner — executes all registered checks against a target.

**Fail-closed contract:** advertised introspection errors are surfaced as
CRITICAL findings. Non-advertised introspection errors are informational
notes only (no finding, no non-zero exit). Check execution errors are
surfaced as errors and cause non-zero exit.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone

from mcp_audit.checks import REGISTRY
from mcp_audit.checks.base import Category, CheckResult, Finding, Severity
from mcp_audit.client import IntrospectionError, McpTarget


@dataclass
class ScanReport:
    """Full output of a scan — all check results plus metadata."""

    target_description: str
    started_at: str
    finished_at: str
    server_info: dict = field(default_factory=dict)
    results: list[CheckResult] = field(default_factory=list)
    introspection_errors: list[IntrospectionError] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        out: list[Finding] = []
        for r in self.results:
            out.extend(r.findings)
        return out

    @property
    def check_errors(self) -> list[CheckResult]:
        """Checks that crashed during execution."""
        return [r for r in self.results if r.error]

    @property
    def critical_introspection_errors(self) -> list[IntrospectionError]:
        """Introspection errors on advertised endpoints — these are real failures."""
        return [ie for ie in self.introspection_errors if ie.advertised]

    @property
    def info_introspection_errors(self) -> list[IntrospectionError]:
        """Introspection errors on non-advertised endpoints — informational only."""
        return [ie for ie in self.introspection_errors if not ie.advertised]

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            grouped[f.severity.value].append(f)
        return grouped

    def summary_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def has_problems(self) -> bool:
        """True if real problems exist: findings, check errors, or CRITICAL introspection errors.

        Non-advertised (INFO) introspection errors are informational and do not
        constitute a scan failure.
        """
        return bool(self.findings or self.check_errors or self.critical_introspection_errors)


async def run_scan(
    target: McpTarget,
    *,
    severity_floor: Severity = Severity.INFO,
) -> ScanReport:
    """Run all registered checks against ``target`` and return a report."""
    started = datetime.now(timezone.utc).isoformat()
    results: list[CheckResult] = []

    # ── Surface introspection failures ─────────────────────────────────────
    # Only advertised-endpoint failures become CRITICAL findings. Non-advertised
    # errors are informational — they live in introspection_errors for the
    # renderers to show as dim notes, but are NOT materialized as findings
    # (which would pollute has_problems and drive non-zero exit).
    for ie in target.introspection_errors:
        if not ie.advertised:
            continue
        results.append(
            CheckResult(
                check_id="INTROSPECTION",
                check_name=f"Introspection: {ie.endpoint}",
                findings=[
                    Finding(
                        check_id="INTROSPECTION",
                        title=f"Failed to introspect `{ie.endpoint}`",
                        severity=Severity.CRITICAL,
                        category=Category.CONFIGURATION,
                        description=(
                            f"The server advertised `{ie.endpoint}` capability but "
                            "the call failed. Because the server claimed this "
                            "capability, the scanner expected data it could not "
                            "retrieve. Do NOT trust this scan result for the "
                            "affected attack surface."
                        ),
                        evidence=ie.error,
                        remediation=(
                            "Investigate why the server failed to respond to an "
                            "endpoint it advertised in its capabilities."
                        ),
                    )
                ],
            )
        )

    # ── Run registered checks ───────────────────────────────────────────────
    for check_cls in REGISTRY:
        if check_cls.default_severity.rank < severity_floor.rank:
            results.append(
                CheckResult(
                    check_id=check_cls.id,
                    check_name=check_cls.name,
                    skipped=True,
                    skip_reason=f"below severity floor ({severity_floor.value})",
                )
            )
            continue

        check = check_cls()
        try:
            findings = await check.run(target)
            results.append(
                CheckResult(
                    check_id=check_cls.id,
                    check_name=check_cls.name,
                    findings=findings,
                )
            )
        except Exception as exc:  # noqa: BLE001 — we want to surface failures
            results.append(
                CheckResult(
                    check_id=check_cls.id,
                    check_name=check_cls.name,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    finished = datetime.now(timezone.utc).isoformat()
    return ScanReport(
        target_description=target.command or target.url or "unknown",
        started_at=started,
        finished_at=finished,
        server_info=target.server_info,
        results=results,
        introspection_errors=list(target.introspection_errors),
    )


def run_scan_sync(target: McpTarget, **kwargs) -> ScanReport:
    return asyncio.run(run_scan(target, **kwargs))
