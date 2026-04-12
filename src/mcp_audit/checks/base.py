"""Base classes for mcp-scan checks.

Every check subclasses ``Check`` and implements ``run``. A check returns a list
of ``Finding`` objects — zero findings means the check passed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp_audit.client import McpTarget


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class Category(str, Enum):
    TOOL_SCHEMA = "tool_schema"
    TRANSPORT = "transport"
    AUTH = "auth"
    RESOURCE_ACCESS = "resource_access"
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    SANDBOX = "sandbox"
    CONFIGURATION = "configuration"
    SUPPLY_CHAIN = "supply_chain"
    OBSERVABILITY = "observability"


@dataclass
class Finding:
    """A single security finding produced by a check."""

    check_id: str
    title: str
    severity: Severity
    category: Category
    description: str
    evidence: str = ""
    remediation: str = ""
    reference: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reference": self.reference,
        }


@dataclass
class CheckResult:
    """Outcome of running a single check against a target."""

    check_id: str
    check_name: str
    findings: list[Finding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    error: str | None = None

    @property
    def passed(self) -> bool:
        return not self.findings and not self.error and not self.skipped


class Check:
    """Base class for all mcp-scan checks.

    Subclasses must set ``id``, ``name``, ``category``, and ``default_severity``,
    and implement ``run``.
    """

    id: str = ""
    name: str = ""
    description: str = ""
    category: Category = Category.CONFIGURATION
    default_severity: Severity = Severity.MEDIUM

    async def run(self, target: "McpTarget") -> list[Finding]:  # pragma: no cover
        raise NotImplementedError

    def finding(
        self,
        title: str,
        description: str,
        evidence: str = "",
        remediation: str = "",
        reference: str = "",
        severity: Severity | None = None,
    ) -> Finding:
        """Helper for subclasses to build a Finding with check defaults pre-filled."""
        return Finding(
            check_id=self.id,
            title=title,
            severity=severity or self.default_severity,
            category=self.category,
            description=description,
            evidence=evidence,
            remediation=remediation,
            reference=reference,
        )
