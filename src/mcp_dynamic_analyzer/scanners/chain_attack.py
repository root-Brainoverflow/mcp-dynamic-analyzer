"""Server-responsibility checks for risky tool-chain metadata.

This scanner intentionally avoids inferring risk from client-side call
ordering alone. A client deciding to call ``read_*`` then ``delete_*`` is not
by itself evidence of a vulnerable MCP server. Instead, we look for cases
where the server's own metadata can mislead or steer an LLM toward unsafe
follow-up actions.

Current checks:
1. A tool advertises ``readOnlyHint`` but its metadata looks destructive.
2. A tool description/annotations explicitly guide the model toward a
   destructive follow-up tool.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_dynamic_analyzer.models import (
    AnalysisContext,
    Finding,
    RiskType,
    Severity,
    ToolInfo,
)
from mcp_dynamic_analyzer.scanners.base import BaseScanner

_CHAIN_PHRASES = (
    "then call",
    "then use",
    "after calling",
    "after using",
    "follow up with",
    "next call",
    "next use",
    "use the result with",
    "before calling",
)

_DANGEROUS_WORDS = (
    "delete",
    "remove",
    "drop",
    "truncate",
    "write",
    "overwrite",
    "exec",
    "execute",
    "run",
    "install",
)

class ChainAttackScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "chain_attack"

    @property
    def risk_type(self) -> RiskType:
        return RiskType.R3

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        anchor_event_id = await self._find_tools_event_id(ctx.event_reader)
        findings: list[Finding] = []
        findings.extend(self._detect_readonly_mismatch(ctx.tools, anchor_event_id))
        findings.extend(self._detect_server_guided_chains(ctx.tools, anchor_event_id))
        return findings

    async def _find_tools_event_id(self, reader: Any) -> str | None:
        """Return the init-enumeration event that captured server tool metadata."""
        events_by_type = getattr(reader, "events_by_type", None)
        if events_by_type is None:
            return None
        async for evt in events_by_type("test_result"):
            if evt.data.get("sequence") == "init_enumerate" and "tools" in evt.data:
                return evt.event_id
        return None

    def _detect_readonly_mismatch(
        self,
        tools: list[ToolInfo],
        anchor_event_id: str | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for tool in tools:
            annotations = tool.annotations or {}
            if annotations.get("readOnlyHint") is not True:
                continue
            if not _looks_destructive(tool):
                continue

            findings.append(
                Finding(
                    risk_type=RiskType.R3,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Read-only annotation mismatch on '{tool.name}'",
                    description=(
                        f"Tool '{tool.name}' advertises readOnlyHint=true, but its "
                        "name/description/schema suggest destructive capability. "
                        "This can mislead an LLM into unsafe tool selection."
                    ),
                    related_events=[anchor_event_id] if anchor_event_id else [],
                    tool_name=tool.name,
                    reproduction=f"Inspect metadata for tool '{tool.name}' in tools/list",
                )
            )
        return findings

    def _detect_server_guided_chains(
        self,
        tools: list[ToolInfo],
        anchor_event_id: str | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_pairs: set[tuple[str, str]] = set()

        for tool in tools:
            text = _tool_metadata_text(tool)
            if not text or not _contains_chain_language(text):
                continue

            for dest in tools:
                if dest.name == tool.name:
                    continue
                pair = (tool.name, dest.name)
                if pair in seen_pairs:
                    continue
                if dest.name.lower() not in text:
                    continue
                if not _looks_destructive(dest):
                    continue

                seen_pairs.add(pair)
                findings.append(
                    Finding(
                        risk_type=RiskType.R3,
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        title=f"Server-guided tool chain: {tool.name} → {dest.name}",
                        description=(
                            f"Tool '{tool.name}' metadata references destructive tool "
                            f"'{dest.name}' using sequential guidance. This is server-"
                            "supplied context that can steer an LLM toward a risky "
                            "follow-up action."
                        ),
                        related_events=[anchor_event_id] if anchor_event_id else [],
                        tool_name=tool.name,
                        reproduction=(
                            f"Inspect description/annotations of '{tool.name}' and "
                            f"its reference to '{dest.name}'"
                        ),
                    )
                )

        return findings


def _tool_metadata_text(tool: ToolInfo) -> str:
    parts = [tool.name.lower()]
    if tool.description:
        parts.append(tool.description.lower())
    if tool.annotations:
        parts.append(json.dumps(tool.annotations, ensure_ascii=False).lower())
    if tool.input_schema:
        parts.append(json.dumps(tool.input_schema, ensure_ascii=False).lower())
    return " ".join(parts)


def _contains_chain_language(text: str) -> bool:
    return any(phrase in text for phrase in _CHAIN_PHRASES)


def _looks_destructive(tool: ToolInfo) -> bool:
    text = _tool_metadata_text(tool)
    return any(word in text for word in _DANGEROUS_WORDS)
