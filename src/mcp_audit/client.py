"""MCP target abstraction — wraps the official ``mcp`` SDK client.

``McpTarget`` represents a server under test. It handles connection bring-up
for stdio and HTTP/SSE transports, exposes the raw manifest (tools, resources,
prompts) to checks, and provides a thin ``call_tool`` helper for dynamic probes.

Checks should treat ``McpTarget`` as read-mostly. They must not mutate server
state unless explicitly running a dynamic probe check.

**Fail-closed design:** introspection errors are recorded, not swallowed.
If a server *advertises* tools but fails to respond to ``tools/list``, the
scanner sees that as a critical finding. If a server simply doesn't advertise
resources/prompts, that's fine — the scanner skips those endpoints.
"""
from __future__ import annotations

import asyncio
import shlex
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Default timeout for any single MCP RPC call (seconds).
DEFAULT_RPC_TIMEOUT: float = 30.0


@dataclass
class IntrospectionError:
    """Records a failed introspection call so the runner can surface it."""

    endpoint: str  # e.g. "tools/list", "resources/list"
    error: str
    advertised: bool  # True if the server claimed this capability


@dataclass
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class ResourceSpec:
    uri: str
    name: str
    description: str
    mime_type: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class PromptSpec:
    name: str
    description: str
    arguments: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class McpTarget:
    """A connected MCP server under test."""

    def __init__(
        self,
        *,
        transport: str,
        command: str | None = None,
        url: str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = DEFAULT_RPC_TIMEOUT,
        source_path: str | None = None,
    ) -> None:
        self.transport = transport
        self.command = command
        self.url = url
        self.env = env or {}
        self.timeout = timeout
        self.source_path = source_path

        self._stack: AsyncExitStack | None = None
        self.session: ClientSession | None = None

        self.tools: list[ToolSpec] = []
        self.resources: list[ResourceSpec] = []
        self.prompts: list[PromptSpec] = []
        self.introspection_errors: list[IntrospectionError] = []
        self.server_info: dict[str, Any] = {}
        # Default tools to True so we always attempt tools/list even if the
        # server omits capabilities entirely. A server that doesn't respond
        # will get an INFO-level introspection note, not a silent pass.
        # Resources/prompts default to False — those are opt-in.
        self.capabilities: dict[str, bool] = {
            "tools": True,
            "resources": False,
            "prompts": False,
        }
        # Tracks whether the server provided capability metadata at all.
        self._capabilities_provided: bool = False

    # ── connection lifecycle ────────────────────────────────────────────────
    async def __aenter__(self) -> "McpTarget":
        self._stack = AsyncExitStack()
        await self._stack.__aenter__()
        await self._connect()
        await self._introspect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._stack is not None:
            await self._stack.__aexit__(*exc_info)
            self._stack = None
            self.session = None

    async def _connect(self) -> None:
        assert self._stack is not None
        if self.transport == "stdio":
            if not self.command:
                raise ValueError("stdio transport requires --stdio command")
            parts = shlex.split(self.command)
            params = StdioServerParameters(command=parts[0], args=parts[1:], env=self.env)
            read, write = await self._stack.enter_async_context(stdio_client(params))
            self.session = await self._stack.enter_async_context(ClientSession(read, write))
            init_result = await asyncio.wait_for(
                self.session.initialize(), timeout=self.timeout
            )

            # Capture server info and capabilities from the initialize response.
            if hasattr(init_result, "serverInfo") and init_result.serverInfo:
                info = init_result.serverInfo
                self.server_info = {
                    "name": getattr(info, "name", ""),
                    "version": getattr(info, "version", ""),
                }

            caps = init_result.capabilities
            if caps:
                self._capabilities_provided = True
                self.capabilities["tools"] = caps.tools is not None
                self.capabilities["resources"] = caps.resources is not None
                self.capabilities["prompts"] = caps.prompts is not None
            # If caps is None/empty, tools stays True (default) so we still
            # attempt tools/list. _capabilities_provided stays False so the
            # introspection method can set advertised=False on errors.

        elif self.transport == "http":
            raise NotImplementedError("HTTP/SSE transport is not yet implemented")
        else:
            raise ValueError(f"Unknown transport: {self.transport}")

    async def _introspect(self) -> None:
        """Fetch tools, resources, prompts once after connection.

        Only calls endpoints the server advertised in its capabilities.
        Errors on advertised endpoints are recorded as critical.
        Errors on non-advertised endpoints (if we tried) would be info-level,
        but we simply skip them.
        """
        assert self.session is not None

        # ── tools ──
        if self.capabilities["tools"]:
            try:
                tools_resp = await asyncio.wait_for(
                    self.session.list_tools(), timeout=self.timeout
                )
                self.tools = [
                    ToolSpec(
                        name=t.name,
                        description=t.description or "",
                        input_schema=t.inputSchema or {},
                        raw=t.model_dump() if hasattr(t, "model_dump") else {},
                    )
                    for t in tools_resp.tools
                ]
            except Exception as exc:
                # If the server explicitly advertised tools, this is critical.
                # If we're just probing because caps were missing, it's INFO.
                advertised = self._capabilities_provided and self.capabilities["tools"]
                self.introspection_errors.append(
                    IntrospectionError(
                        "tools/list", f"{type(exc).__name__}: {exc}", advertised=advertised
                    )
                )
                self.tools = []

        # ── resources ──
        if self.capabilities["resources"]:
            try:
                resources_resp = await asyncio.wait_for(
                    self.session.list_resources(), timeout=self.timeout
                )
                self.resources = [
                    ResourceSpec(
                        uri=str(r.uri),
                        name=r.name or "",
                        description=r.description or "",
                        mime_type=r.mimeType,
                        raw=r.model_dump() if hasattr(r, "model_dump") else {},
                    )
                    for r in resources_resp.resources
                ]
            except Exception as exc:
                self.introspection_errors.append(
                    IntrospectionError(
                        "resources/list", f"{type(exc).__name__}: {exc}", advertised=True
                    )
                )
                self.resources = []

        # ── prompts ──
        if self.capabilities["prompts"]:
            try:
                prompts_resp = await asyncio.wait_for(
                    self.session.list_prompts(), timeout=self.timeout
                )
                self.prompts = [
                    PromptSpec(
                        name=p.name,
                        description=p.description or "",
                        arguments=[a.model_dump() for a in (p.arguments or [])]
                        if hasattr(p, "arguments")
                        else [],
                        raw=p.model_dump() if hasattr(p, "model_dump") else {},
                    )
                    for p in prompts_resp.prompts
                ]
            except Exception as exc:
                self.introspection_errors.append(
                    IntrospectionError(
                        "prompts/list", f"{type(exc).__name__}: {exc}", advertised=True
                    )
                )
                self.prompts = []

    # ── helpers for checks ──────────────────────────────────────────────────
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Invoke a tool. Used by dynamic-probe checks only."""
        assert self.session is not None
        return await asyncio.wait_for(
            self.session.call_tool(name, arguments), timeout=self.timeout
        )
