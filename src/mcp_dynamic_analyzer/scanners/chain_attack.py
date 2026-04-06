"""Shared-Context Chain Attack scanner.

Detects multi-tool attack chains where individual tool calls appear
benign but their *combined* effect through shared context is dangerous.

Analysis approach:
1. Reconstruct the chronological sequence of tool calls + responses.
2. Check if data from one tool's response flows into another tool's arguments.
3. Flag chains where the second call touches sensitive resources.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_dynamic_analyzer.models import (
    AnalysisContext,
    Event,
    Finding,
    RiskType,
    Severity,
)
from mcp_dynamic_analyzer.scanners.base import BaseScanner

_SENSITIVE_KEYWORDS = {
    "delete", "remove", "drop", "truncate", "exec", "execute",
    "eval", "system", "shell", "sudo", "admin", "password",
    "secret", "credential", "token", "key", "write", "overwrite",
}


class ChainAttackScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "chain_attack"

    @property
    def risk_type(self) -> RiskType:
        return RiskType.R3  # chain attacks manipulate LLM tool-calling behaviour

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]

        calls = await self._build_call_chain(reader)
        findings.extend(self._detect_data_flow(calls))
        findings.extend(self._detect_escalation(calls))

        return findings

    async def _build_call_chain(self, reader: Any) -> list[_ToolCall]:
        """Reconstruct ordered tool call + response pairs."""
        requests: dict[Any, Event] = {}
        chain: list[_ToolCall] = []

        async for evt in reader.protocol_events():
            msg = evt.data.get("message", {})

            if evt.type == "mcp_request" and msg.get("method") == "tools/call":
                requests[msg.get("id")] = evt

            elif evt.type == "mcp_response":
                req_id = msg.get("id")
                req_evt = requests.pop(req_id, None)
                if req_evt is None:
                    continue
                req_msg = req_evt.data.get("message", {})
                if req_msg.get("method") != "tools/call":
                    continue

                params = req_msg.get("params", {})
                result = msg.get("result", {})
                chain.append(_ToolCall(
                    tool_name=params.get("name", ""),
                    arguments=params.get("arguments", {}),
                    response=result,
                    req_event_id=req_evt.event_id,
                    resp_event_id=evt.event_id,
                ))

        return chain

    def _detect_data_flow(self, calls: list[_ToolCall]) -> list[Finding]:
        """Check if response content from call N appears in arguments of call N+k."""
        findings: list[Finding] = []
        for i, src in enumerate(calls):
            src_text = json.dumps(src.response, default=str).lower()
            src_tokens = {t for t in src_text.split() if len(t) > 6}

            for j in range(i + 1, min(i + 4, len(calls))):
                dest = calls[j]
                dest_args_text = json.dumps(dest.arguments, default=str).lower()

                overlap = src_tokens & {t for t in dest_args_text.split() if len(t) > 6}
                if len(overlap) >= 2 and _has_sensitive(dest):
                    findings.append(Finding(
                        risk_type=RiskType.R3,
                        severity=Severity.HIGH,
                        confidence=0.7,
                        title=f"Data flow chain: {src.tool_name} → {dest.tool_name}",
                        description=(
                            f"Data from '{src.tool_name}' response appears in "
                            f"'{dest.tool_name}' arguments, which touches sensitive operations."
                        ),
                        related_events=[src.resp_event_id, dest.req_event_id],
                        reproduction=(
                            f"Call '{src.tool_name}', then pass response data to '{dest.tool_name}'"
                        ),
                    ))

        return findings

    def _detect_escalation(self, calls: list[_ToolCall]) -> list[Finding]:
        """Flag chains where a read-like tool precedes a dangerous write-like tool."""
        findings: list[Finding] = []
        for i, call in enumerate(calls):
            if not _is_read_like(call):
                continue
            for j in range(i + 1, min(i + 3, len(calls))):
                next_call = calls[j]
                if _is_dangerous(next_call):
                    findings.append(Finding(
                        risk_type=RiskType.R3,
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                        title=f"Privilege escalation chain: {call.tool_name} → {next_call.tool_name}",
                        description=(
                            f"Read-like tool '{call.tool_name}' immediately precedes "
                            f"dangerous tool '{next_call.tool_name}', suggesting a "
                            f"reconnaissance → exploit chain."
                        ),
                        related_events=[call.req_event_id, next_call.req_event_id],
                        reproduction=f"Call '{call.tool_name}' then '{next_call.tool_name}'",
                    ))
        return findings


# ---------------------------------------------------------------------------
# Internal types & helpers
# ---------------------------------------------------------------------------

class _ToolCall:
    __slots__ = ("tool_name", "arguments", "response", "req_event_id", "resp_event_id")

    def __init__(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        response: dict[str, Any],
        req_event_id: str,
        resp_event_id: str,
    ) -> None:
        self.tool_name = tool_name
        self.arguments = arguments
        self.response = response
        self.req_event_id = req_event_id
        self.resp_event_id = resp_event_id


def _has_sensitive(call: _ToolCall) -> bool:
    text = (call.tool_name + " " + json.dumps(call.arguments, default=str)).lower()
    return any(kw in text for kw in _SENSITIVE_KEYWORDS)


def _is_read_like(call: _ToolCall) -> bool:
    name = call.tool_name.lower()
    return any(w in name for w in ("read", "get", "list", "search", "find", "show", "cat"))


def _is_dangerous(call: _ToolCall) -> bool:
    name = call.tool_name.lower()
    return any(w in name for w in ("write", "delete", "exec", "run", "install", "remove", "drop"))
