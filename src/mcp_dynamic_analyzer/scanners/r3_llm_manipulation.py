"""R3: LLM Behavior Manipulation scanner.

Detects prompt injection in tool descriptions, tool-return injection in
responses, and shared-context pollution patterns.  Operates entirely on
collected EventStore data (post-hoc analysis).
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from mcp_dynamic_analyzer.models import (
    AnalysisContext,
    Finding,
    RiskType,
    Severity,
)
from mcp_dynamic_analyzer.payloads.injection_patterns import (
    PatternMatch,
    scan_description,
    scan_response,
)
from mcp_dynamic_analyzer.scanners.base import BaseScanner

log = structlog.get_logger()


class R3LlmManipulationScanner(BaseScanner):
    """Analyses tool descriptions and responses for LLM manipulation attempts."""

    @property
    def name(self) -> str:
        return "r3_llm_manipulation"

    @property
    def risk_type(self) -> RiskType:
        return RiskType.R3

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._scan_descriptions(ctx))
        findings.extend(await self._scan_responses(ctx))
        return findings

    # -- description analysis ------------------------------------------------

    async def _scan_descriptions(self, ctx: AnalysisContext) -> list[Finding]:
        """Check every tool description for injection patterns."""
        findings: list[Finding] = []

        for tool in ctx.tools:
            if not tool.description:
                continue
            matches = scan_description(tool.description)
            for m in matches:
                findings.append(self._desc_finding(tool.name, tool.description, m))

            if tool.annotations:
                anno_text = json.dumps(tool.annotations)
                for m in scan_description(anno_text):
                    findings.append(self._desc_finding(tool.name, anno_text, m))

        return findings

    def _desc_finding(self, tool_name: str, text: str, m: PatternMatch) -> Finding:
        sev = _sev(m.severity)
        return Finding(
            risk_type=RiskType.R3,
            severity=sev,
            confidence=0.85 if sev in (Severity.HIGH, Severity.CRITICAL) else 0.6,
            title=f"Suspicious pattern '{m.pattern_name}' in tool description",
            description=(
                f"Tool '{tool_name}' description contains pattern '{m.pattern_name}' "
                f"that may manipulate LLM behaviour.  Matched: \"{m.matched_text}\""
            ),
            tool_name=tool_name,
            reproduction=f"Inspect description of tool '{tool_name}'",
        )

    # -- response analysis ---------------------------------------------------

    async def _scan_responses(self, ctx: AnalysisContext) -> list[Finding]:
        """Check tool-call responses for return-injection patterns."""
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]

        async for evt in reader.events_by_type("mcp_response"):
            msg: dict[str, Any] = evt.data.get("message", {})
            result = msg.get("result", {})
            content_list = result.get("content", [])
            response_text = _extract_text(content_list)
            if not response_text:
                continue

            matches = scan_response(response_text)
            req_method = evt.data.get("method")
            for m in matches:
                findings.append(
                    Finding(
                        risk_type=RiskType.R3,
                        severity=_sev(m.severity),
                        confidence=0.8,
                        title=f"Tool-return injection: '{m.pattern_name}'",
                        description=(
                            f"A tool response contains pattern '{m.pattern_name}' "
                            f"that may hijack LLM behaviour.  Matched: \"{m.matched_text}\""
                        ),
                        related_events=[evt.event_id],
                        reproduction=f"Replay request {req_method} and inspect response",
                    ),
                )

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _sev(s: str) -> Severity:
    return _SEV_MAP.get(s, Severity.MEDIUM)


def _extract_text(content_list: list[dict[str, Any]] | Any) -> str:
    """Flatten MCP content array to plain text."""
    if not isinstance(content_list, list):
        return str(content_list) if content_list else ""
    parts: list[str] = []
    for item in content_list:
        if isinstance(item, dict) and item.get("type") == "text":
            parts.append(item.get("text", ""))
        elif isinstance(item, str):
            parts.append(item)
    return "\n".join(parts)
