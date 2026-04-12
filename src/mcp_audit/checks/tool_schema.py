"""Tool schema checks — static inspection of `tools/list` output.

These checks run against data that any MCP client receives at connection time.
No dynamic probing, no AST walking, no source code required. They are the
cheapest checks in the scanner and catch the highest-profile MCP attacks
published to date (tool poisoning / line jumping / ANSI smuggling).
"""
from __future__ import annotations

import re

from mcp_audit.checks import register
from mcp_audit.checks.base import Category, Check, Finding, Severity
from mcp_audit.client import McpTarget

# ── Imperative phrases seen in published tool-poisoning payloads. ────────────
INJECTION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bignore\s+(all\s+)?(prior|previous|above)\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\bdisregard\s+(all\s+)?(prior|previous)\b", re.IGNORECASE),
    re.compile(r"^\s*system\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"<\s*/?\s*(system|instructions?|assistant|user)\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]|\[/INST\]", re.IGNORECASE),
    re.compile(r"\bexfiltrat", re.IGNORECASE),
    re.compile(r"\bbase64\s*(encode|decode)\b", re.IGNORECASE),
    re.compile(r"\b(curl|wget)\s+https?://", re.IGNORECASE),
    re.compile(r"\b(read|send|fetch|exfil)\s+(the\s+)?(contents?\s+of\s+)?[~$]?/", re.IGNORECASE),
    re.compile(r"\.ssh/|id_rsa|\.env|/etc/passwd", re.IGNORECASE),
]

# ── Hidden / control characters used to smuggle instructions past reviewers. ─
ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# C0 controls (except common whitespace \t\n\r), DEL, zero-width chars, bidi overrides.
HIDDEN_CHAR_PATTERN = re.compile(
    r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F"
    r"\u200B-\u200F"  # zero-width space, non-joiner, joiner, LTR/RTL marks
    r"\u202A-\u202E"  # bidi overrides
    r"\u2060-\u2064"  # word joiner, invisible ops
    r"\uFEFF"          # zero-width no-break space
    r"]"
)

TOB_LINE_JUMPING_URL = (
    "https://blog.trailofbits.com/2025/04/21/"
    "jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/"
)
TOB_ANSI_URL = (
    "https://blog.trailofbits.com/2025/04/29/"
    "deceiving-users-with-ansi-terminal-codes-in-mcp/"
)


@register
class ToolDescriptionInjectionMarkers(Check):
    """MCPA-001 — tool description contains prompt-injection markers."""

    id = "MCPA-001"
    name = "Tool description contains prompt-injection markers"
    description = (
        "Scans every tool description returned by `tools/list` for imperative "
        "phrases, system/instruction tags, and exfiltration verbs commonly seen "
        "in MCP tool poisoning / line-jumping attacks. Because tool descriptions "
        "are loaded into an agent's context *before* any tool is invoked, an "
        "attacker-controlled description can hijack the agent even if the user "
        "never calls the tool."
    )
    category = Category.TOOL_SCHEMA
    default_severity = Severity.CRITICAL

    async def run(self, target: McpTarget) -> list[Finding]:
        findings: list[Finding] = []
        for tool in target.tools:
            hits = self._scan(tool.description)
            if hits:
                findings.append(
                    self.finding(
                        title=f"Tool `{tool.name}` description contains injection markers",
                        description=(
                            "The tool description contains phrases that an LLM host "
                            "may interpret as instructions. This is the `line jumping` "
                            "/ tool poisoning pattern — the description enters the "
                            "agent's context at connection time, before any explicit "
                            "tool call, so the attack fires even if the user never "
                            "invokes this tool."
                        ),
                        evidence="; ".join(f'matched {pat!r}' for pat in hits),
                        remediation=(
                            "Treat tool descriptions as untrusted input. Strip or "
                            "reject imperative instructions, system/instruction tags, "
                            "and exfiltration verbs. Pin descriptions by SHA-256 hash "
                            "and reject silent mutations."
                        ),
                        reference=TOB_LINE_JUMPING_URL,
                    )
                )
        return findings

    @staticmethod
    def _scan(text: str) -> list[str]:
        hits: list[str] = []
        for pattern in INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                hits.append(match.group(0).strip())
        return hits


@register
class ToolDescriptionHiddenChars(Check):
    """MCPA-002 — tool description contains hidden / control characters."""

    id = "MCPA-002"
    name = "Tool description contains ANSI / control / zero-width chars"
    description = (
        "Detects ANSI escape sequences, C0 control characters, zero-width "
        "characters, and bidi overrides inside tool names and descriptions. "
        "These are used to hide prompt-injection payloads from human review: "
        "the text renders as benign in terminals and chat UIs while the LLM "
        "still reads the hidden instructions."
    )
    category = Category.TOOL_SCHEMA
    default_severity = Severity.HIGH

    async def run(self, target: McpTarget) -> list[Finding]:
        findings: list[Finding] = []
        for tool in target.tools:
            ansi = ANSI_ESCAPE_PATTERN.findall(tool.description or "")
            hidden = HIDDEN_CHAR_PATTERN.findall(tool.description or "")
            ansi_name = ANSI_ESCAPE_PATTERN.findall(tool.name or "")
            hidden_name = HIDDEN_CHAR_PATTERN.findall(tool.name or "")

            if not (ansi or hidden or ansi_name or hidden_name):
                continue

            parts: list[str] = []
            if ansi:
                parts.append(f"{len(ansi)} ANSI escape(s) in description")
            if hidden:
                parts.append(f"{len(hidden)} hidden/control char(s) in description")
            if ansi_name:
                parts.append(f"{len(ansi_name)} ANSI escape(s) in tool name")
            if hidden_name:
                parts.append(f"{len(hidden_name)} hidden char(s) in tool name")

            findings.append(
                self.finding(
                    title=f"Tool `{tool.name}` description contains hidden characters",
                    description=(
                        "Tool descriptions containing ANSI escapes, zero-width, or "
                        "bidi-override characters are used to smuggle prompt-injection "
                        "payloads past human review. The rendered text looks benign "
                        "while the LLM still reads the hidden content."
                    ),
                    evidence=", ".join(parts),
                    remediation=(
                        "Normalize tool descriptions: strip all C0 controls, ANSI "
                        "escapes (`\\x1b[...m`), zero-width code points, and bidi "
                        "overrides before passing the description into the agent's "
                        "context."
                    ),
                    reference=TOB_ANSI_URL,
                )
            )
        return findings
