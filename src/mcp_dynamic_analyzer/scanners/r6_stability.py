"""R6: Service Stability Threats scanner + fuzzing sequence.

Collection phase:  ``StabilityFuzzingSequence`` sends DoS-class payloads
(memory bombs, deeply-nested objects, ReDoS strings, XML/JSON bombs) to
every tool parameter and records test_input / test_result events.

Analysis phase:  ``R6StabilityScanner`` reads those events and checks:
* Server crashes (``server_crash`` events)
* Sequence timeouts (hang / infinite loop indicator)
* Excessive error rate
* OOM / stack-overflow / parser-failure strings in responses
"""

from __future__ import annotations

import asyncio
import json
import reprlib
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
from mcp_dynamic_analyzer.payloads.stability import (
    SLOW_RESPONSE_THRESHOLD_SEC,
    generate_stability_payloads,
    looks_like_crash,
    looks_like_oom,
    looks_like_parser_failure,
    looks_like_stack_overflow,
    looks_like_timeout,
)
from mcp_dynamic_analyzer.models import ServerCrashError
from mcp_dynamic_analyzer.protocol.client import McpClient, McpError
from mcp_dynamic_analyzer.scanners.base import BaseScanner, TestSequence

log = structlog.get_logger()
_ARG_PREVIEW_LIMIT = 2000
_CALL_TIMEOUT = 15.0
# After this many timeouts on the same (tool, category), skip the rest of that
# category for that tool. Hangs on inputs like NaN / inf / huge ints reproduce
# on every payload of the same shape, so re-firing eats the global budget
# without producing new evidence.
_CIRCUIT_BREAKER_THRESHOLD = 1
_REPR = reprlib.Repr()
_REPR.maxstring = 200
_REPR.maxother = 200
_REPR.maxlist = 8
_REPR.maxtuple = 8
_REPR.maxset = 8
_REPR.maxfrozenset = 8
_REPR.maxdict = 8
_REPR.maxlevel = 4


# ═══════════════════════════════════════════════════════════════════════════
# Collection-phase: TestSequence
# ═══════════════════════════════════════════════════════════════════════════


class StabilityFuzzingSequence(TestSequence):
    """Send stability / DoS payloads to every tool parameter."""

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id

    @property
    def name(self) -> str:
        return "fuzz_stability"

    @property
    def timeout(self) -> float:
        # Stability payloads may legitimately cause slow responses;
        # give extra headroom before the sequence itself times out.
        return 300.0

    async def execute(self, client: Any, writer: EventWriter) -> None:
        cli: McpClient = client
        tools = await cli.list_tools()
        payloads = generate_stability_payloads()

        for tool in tools:
            params = _all_param_names(tool)
            if not params:
                continue

            timeout_counts: dict[str, int] = {}
            for category, payload in payloads:
                if timeout_counts.get(category, 0) >= _CIRCUIT_BREAKER_THRESHOLD:
                    continue
                for param in params:
                    args: dict[str, Any] = {param: payload}
                    timed_out = await self._fuzz_one(cli, writer, tool.name, category, args)
                    if timed_out:
                        timeout_counts[category] = timeout_counts.get(category, 0) + 1
                        if timeout_counts[category] >= _CIRCUIT_BREAKER_THRESHOLD:
                            log.info(
                                "fuzz.circuit_breaker_tripped",
                                tool=tool.name,
                                category=category,
                                hint="Skipping remaining payloads in this category for this tool.",
                            )
                            break

    async def _fuzz_one(
        self,
        cli: McpClient,
        writer: EventWriter,
        tool_name: str,
        category: str,
        arguments: dict[str, Any],
    ) -> bool:
        args_preview = _safe_dump(arguments)
        await writer.write(Event(
            session_id=self._session_id,
            source="test",
            type="test_input",
            data={
                "sequence": self.name,
                "tool": tool_name,
                "category": category,
                "arguments": args_preview,
            },
        ))

        resp_text: str
        timed_out = False
        encoding_error = _json_encoding_error(arguments)
        if encoding_error is not None:
            resp_text = f"ClientSerializationError: {encoding_error}"
        else:
            try:
                result = await asyncio.wait_for(
                    cli.call_tool(tool_name, arguments), timeout=_CALL_TIMEOUT
                )
                resp_text = _safe_dump(result)
            except ServerCrashError:
                raise  # propagate immediately — do not record a fake test_result
            except asyncio.TimeoutError:
                resp_text = f"CallTimeout: no response within {_CALL_TIMEOUT:.0f}s"
                timed_out = True
                log.warning(
                    "fuzz.call_timeout",
                    tool=tool_name,
                    category=category,
                    timeout=_CALL_TIMEOUT,
                )
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
        return timed_out


# ═══════════════════════════════════════════════════════════════════════════
# Analysis-phase: Scanner
# ═══════════════════════════════════════════════════════════════════════════


class R6StabilityScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "r6_stability"

    @property
    def risk_type(self) -> RiskType:
        return RiskType.R6

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]

        findings.extend(await self._check_crashes(reader))
        findings.extend(await self._check_timeouts(reader))
        findings.extend(await self._check_error_rate(reader))
        findings.extend(await self._check_response_indicators(reader))

        return findings

    async def _check_crashes(self, reader: Any) -> list[Finding]:
        findings: list[Finding] = []
        async for evt in reader.events_by_type("server_crash"):
            seq = evt.data.get("sequence", "unknown")
            findings.append(Finding(
                risk_type=RiskType.R6,
                severity=Severity.HIGH,
                confidence=0.9,
                title=f"Server crashed during sequence '{seq}'",
                description=(
                    f"The MCP server process terminated unexpectedly while "
                    f"running test sequence '{seq}'. This indicates fragile "
                    f"error handling that could be exploited for DoS."
                ),
                related_events=[evt.event_id],
                reproduction=f"Run sequence '{seq}' and observe server process",
            ))
        return findings

    async def _check_timeouts(self, reader: Any) -> list[Finding]:
        findings: list[Finding] = []
        async for evt in reader.events_by_type("sequence_timeout"):
            seq = evt.data.get("sequence", "unknown")
            findings.append(Finding(
                risk_type=RiskType.R6,
                severity=Severity.MEDIUM,
                confidence=0.7,
                title=f"Sequence timeout: '{seq}'",
                description=(
                    f"Test sequence '{seq}' did not complete within its timeout. "
                    f"The server may hang on certain inputs, enabling resource exhaustion."
                ),
                related_events=[evt.event_id],
                reproduction=f"Run sequence '{seq}' with its specific inputs",
            ))
        return findings

    async def _check_error_rate(self, reader: Any) -> list[Finding]:
        total_calls = 0
        error_calls = 0
        async for evt in reader.events_by_type("mcp_response"):
            msg = evt.data.get("message", {})
            if evt.direction != "s2c":
                continue
            total_calls += 1
            if "error" in msg:
                error_calls += 1

        findings: list[Finding] = []
        if total_calls >= 5:
            rate = error_calls / total_calls
            if rate >= 0.5:
                findings.append(Finding(
                    risk_type=RiskType.R6,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    title=f"High error rate: {error_calls}/{total_calls} ({rate:.0%})",
                    description=(
                        f"{error_calls} out of {total_calls} server responses were errors. "
                        f"This suggests poor input validation or unstable implementation."
                    ),
                    reproduction="Review error responses across all tool calls",
                ))
        return findings

    async def _check_response_indicators(self, reader: Any) -> list[Finding]:
        """Check stability-fuzz test_result events for OOM/crash/parser strings."""
        findings: list[Finding] = []
        async for evt in reader.events_by_type("test_result"):
            if evt.data.get("sequence") != "fuzz_stability":
                continue
            resp = evt.data.get("response_preview", "")
            # Client couldn't serialize arguments — server never received this payload.
            # Matching indicators against client-side errors produces false positives.
            if resp.startswith("ClientSerializationError:"):
                continue
            tool = evt.data.get("tool", "")
            cat = evt.data.get("category", "")

            if looks_like_oom(resp):
                findings.append(Finding(
                    risk_type=RiskType.R6,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"OOM indicator on category '{cat}' for tool '{tool}'",
                    description=f"Stability payload in category '{cat}' triggered an out-of-memory condition.",
                    related_events=[evt.event_id],
                    tool_name=tool,
                    reproduction=f"Send '{cat}' payload to tool '{tool}'",
                ))
            elif looks_like_stack_overflow(resp):
                findings.append(Finding(
                    risk_type=RiskType.R6,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Stack overflow on category '{cat}' for tool '{tool}'",
                    description=f"Deeply-nested input in category '{cat}' caused a stack overflow.",
                    related_events=[evt.event_id],
                    tool_name=tool,
                    reproduction=f"Send deeply-nested '{cat}' payload to tool '{tool}'",
                ))
            elif looks_like_parser_failure(resp):
                findings.append(Finding(
                    risk_type=RiskType.R6,
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    title=f"Parser failure on category '{cat}' for tool '{tool}'",
                    description=f"Bomb payload in category '{cat}' caused a parser error (entity expansion / nesting limit).",
                    related_events=[evt.event_id],
                    tool_name=tool,
                    reproduction=f"Send '{cat}' bomb payload to tool '{tool}'",
                ))
            elif looks_like_crash(resp):
                findings.append(Finding(
                    risk_type=RiskType.R6,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    title=f"Process crash on category '{cat}' for tool '{tool}'",
                    description=f"Payload in category '{cat}' caused the server process to crash (segfault / abort).",
                    related_events=[evt.event_id],
                    tool_name=tool,
                    reproduction=f"Send '{cat}' payload to tool '{tool}'",
                ))
            elif looks_like_timeout(resp):
                findings.append(Finding(
                    risk_type=RiskType.R6,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title=f"Timeout / hang on category '{cat}' for tool '{tool}'",
                    description=f"Payload in category '{cat}' caused the server to time out.",
                    related_events=[evt.event_id],
                    tool_name=tool,
                    reproduction=f"Send '{cat}' payload to tool '{tool}'",
                ))
        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _all_param_names(tool: ToolInfo) -> list[str]:
    """Return all parameter names regardless of type."""
    schema = tool.input_schema or {}
    return list((schema.get("properties") or {}).keys())


def _safe_dump(obj: Any) -> str:
    try:
        text = json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError, OverflowError, RecursionError):
        text = _REPR.repr(obj)
    return _truncate_preview(text)


def _json_encoding_error(obj: Any) -> str | None:
    try:
        json.dumps(obj, ensure_ascii=False)
        return None
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return f"{type(exc).__name__}: {exc}"


def _truncate_preview(text: str, limit: int = _ARG_PREVIEW_LIMIT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "...<truncated>"
