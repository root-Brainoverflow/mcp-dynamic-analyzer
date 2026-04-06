"""R5: Input Handling Vulnerabilities scanner + fuzzing sequences.

Collection phase:  ``FuzzingSequence`` sends payloads (path traversal,
command injection, SQL injection, type confusion) to every tool and
records test_input / test_result events.

Analysis phase:  ``R5InputValidationScanner`` reads those events and
checks responses for indicators of successful exploitation or poor
error handling.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from mcp_dynamic_analyzer.correlation.event_store import EventWriter
from mcp_dynamic_analyzer.models import (
    AnalysisContext,
    Event,
    Finding,
    RiskType,
    Severity,
    ToolInfo,
)
from mcp_dynamic_analyzer.payloads import (
    command_injection,
    path_traversal,
    sql_injection,
    type_confusion,
)
from mcp_dynamic_analyzer.protocol.client import McpClient, McpError
from mcp_dynamic_analyzer.scanners.base import BaseScanner, TestSequence

log = structlog.get_logger()


# ═══════════════════════════════════════════════════════════════════════════
# Collection-phase: TestSequences
# ═══════════════════════════════════════════════════════════════════════════


class FuzzingSequence(TestSequence):
    """Send fuzzing payloads to all string parameters of every tool."""

    def __init__(self, session_id: str, fuzz_rounds: int = 10) -> None:
        self._session_id = session_id
        self._rounds = fuzz_rounds

    @property
    def name(self) -> str:
        return "fuzz_input_validation"

    @property
    def timeout(self) -> float:
        return 120.0

    async def execute(self, client: Any, writer: EventWriter) -> None:
        cli: McpClient = client
        tools = await cli.list_tools()

        for tool in tools:
            string_params = _string_param_names(tool)
            if not string_params:
                continue

            payloads = self._build_payloads()
            tested = 0
            for category, payload in payloads:
                if tested >= self._rounds:
                    break
                for param in string_params:
                    args = {param: payload}
                    await self._fuzz_one(cli, writer, tool.name, category, args)
                tested += 1

    async def _fuzz_one(
        self,
        cli: McpClient,
        writer: EventWriter,
        tool_name: str,
        category: str,
        arguments: dict[str, Any],
    ) -> None:
        await writer.write(Event(
            session_id=self._session_id,
            source="test",
            type="test_input",
            data={
                "sequence": self.name,
                "tool": tool_name,
                "category": category,
                "arguments": _safe_dump(arguments),
            },
        ))

        try:
            result = await cli.call_tool(tool_name, arguments)
            resp_text = json.dumps(result, ensure_ascii=False, default=str)
        except McpError as e:
            resp_text = f"McpError({e.code}): {e.message}"
        except Exception as e:
            resp_text = f"Exception: {e}"

        await writer.write(Event(
            session_id=self._session_id,
            source="test",
            type="test_result",
            data={
                "sequence": self.name,
                "tool": tool_name,
                "category": category,
                "response_preview": resp_text[:2000],
            },
        ))

    def _build_payloads(self) -> list[tuple[str, Any]]:
        """Return ``(category, value)`` pairs from all payload modules."""
        out: list[tuple[str, Any]] = []
        for p in path_traversal.ALL_PAYLOADS:
            out.append(("path_traversal", p))
        for p in command_injection.PAYLOADS:
            out.append(("command_injection", p))
        for p in sql_injection.PAYLOADS:
            out.append(("sql_injection", p))
        out.extend(type_confusion.generate_type_payloads())
        return out


# ═══════════════════════════════════════════════════════════════════════════
# Analysis-phase: Scanner
# ═══════════════════════════════════════════════════════════════════════════


class R5InputValidationScanner(BaseScanner):
    """Analyse fuzzing results for signs of successful exploitation."""

    @property
    def name(self) -> str:
        return "r5_input_validation"

    @property
    def risk_type(self) -> RiskType:
        return RiskType.R5

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]

        results: list[Event] = []
        async for evt in reader.events_by_type("test_result"):
            if evt.data.get("sequence") == "fuzz_input_validation":
                results.append(evt)

        for evt in results:
            cat = evt.data.get("category", "")
            resp = evt.data.get("response_preview", "")
            tool = evt.data.get("tool", "")

            finding = self._check(cat, resp, tool, evt.event_id)
            if finding:
                findings.append(finding)

        return findings

    def _check(
        self,
        category: str,
        response: str,
        tool_name: str,
        event_id: str,
    ) -> Finding | None:
        if category == "path_traversal" and path_traversal.looks_like_traversal_success(response):
            return Finding(
                risk_type=RiskType.R5,
                severity=Severity.CRITICAL,
                confidence=0.9,
                title=f"Path traversal succeeded on tool '{tool_name}'",
                description="Fuzzing payload triggered disclosure of sensitive file content.",
                related_events=[event_id],
                tool_name=tool_name,
                reproduction=f"Call tool '{tool_name}' with a path-traversal payload",
            )

        if category == "command_injection" and command_injection.looks_like_injection_success(response):
            return Finding(
                risk_type=RiskType.R5,
                severity=Severity.CRITICAL,
                confidence=0.9,
                title=f"Command injection succeeded on tool '{tool_name}'",
                description="Fuzzing payload caused command execution output in response.",
                related_events=[event_id],
                tool_name=tool_name,
                reproduction=f"Call tool '{tool_name}' with a command-injection payload",
            )

        if category == "sql_injection" and sql_injection.looks_like_sql_error(response):
            return Finding(
                risk_type=RiskType.R5,
                severity=Severity.HIGH,
                confidence=0.75,
                title=f"SQL error leaked on tool '{tool_name}'",
                description="SQL injection payload triggered a database error in the response.",
                related_events=[event_id],
                tool_name=tool_name,
                reproduction=f"Call tool '{tool_name}' with a SQL-injection payload",
            )

        if category.startswith(("null_values", "type_mismatch", "boundary", "nested", "special")):
            if type_confusion.looks_like_unhandled_error(response):
                return Finding(
                    risk_type=RiskType.R5,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title=f"Unhandled error on type-confusion input for '{tool_name}'",
                    description=f"Category '{category}' caused an unhandled exception.",
                    related_events=[event_id],
                    tool_name=tool_name,
                    reproduction=f"Call tool '{tool_name}' with type-confusion input",
                )

        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _string_param_names(tool: ToolInfo) -> list[str]:
    """Extract parameter names that accept string values from JSON Schema."""
    schema = tool.input_schema or {}
    props = schema.get("properties", {})
    return [k for k, v in props.items() if isinstance(v, dict) and v.get("type") == "string"]


def _safe_dump(obj: Any) -> str:
    """JSON-serialise, falling back to str() for non-serialisable values."""
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(obj)
