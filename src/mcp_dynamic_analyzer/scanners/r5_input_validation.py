"""R5: Input Handling Vulnerabilities scanner + fuzzing sequences.

Collection phase:  ``FuzzingSequence`` sends payloads (path traversal,
command injection, SQL injection, NoSQL injection, SSRF, RCE, type
confusion) to every tool and records test_input / test_result events.

Analysis phase:  ``R5InputValidationScanner`` reads those events and
checks responses for indicators of successful exploitation or poor
error handling.
"""

from __future__ import annotations

import asyncio
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
    nosql_injection,
    path_traversal,
    rce,
    sql_injection,
    ssrf,
    type_confusion,
)
from mcp_dynamic_analyzer.payloads._response_filters import is_validation_rejection
from mcp_dynamic_analyzer.models import ServerCrashError
from mcp_dynamic_analyzer.protocol.client import McpClient, McpError
from mcp_dynamic_analyzer.scanners.base import BaseScanner, TestSequence

log = structlog.get_logger()

_CALL_TIMEOUT = 30.0
# Skip the rest of a (tool, category) pair after this many timeouts —
# successive payloads in the same shape (huge ints, etc.) hang for the
# same reason and only burn the global budget.
_CIRCUIT_BREAKER_THRESHOLD = 1


# ═══════════════════════════════════════════════════════════════════════════
# Collection-phase: TestSequences
# ═══════════════════════════════════════════════════════════════════════════


class FuzzingSequence(TestSequence):
    """Send fuzzing payloads to all string parameters of every tool."""

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id

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
            url_params = _url_param_names(tool)
            obj_params = _object_param_names(tool)

            timeout_counts: dict[str, int] = {}

            async def fire(category: str, payload: Any, params: list[str]) -> None:
                if timeout_counts.get(category, 0) >= _CIRCUIT_BREAKER_THRESHOLD:
                    return
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
                            return

            # String-typed params → all payload categories, every payload.
            if string_params:
                for category, payload in self._build_string_payloads():
                    await fire(category, payload, string_params)

            # URL-typed string params → full SSRF payload set.
            if url_params:
                for category, payload in ssrf.generate_ssrf_payloads():
                    await fire(category, payload, url_params)

            # Object/any params → full NoSQL operator set.
            if obj_params:
                for category, payload in nosql_injection.generate_nosql_payloads():
                    await fire(category, payload, obj_params)

    async def _fuzz_one(
        self,
        cli: McpClient,
        writer: EventWriter,
        tool_name: str,
        category: str,
        arguments: dict[str, Any],
    ) -> bool:
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

        timed_out = False
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

    def _build_string_payloads(self) -> list[tuple[str, Any]]:
        """Return ``(category, value)`` pairs for all string-targeted payload modules."""
        out: list[tuple[str, Any]] = []
        for p in path_traversal.ALL_PAYLOADS:
            out.append(("path_traversal", p))
        for p in command_injection.PAYLOADS:
            out.append(("command_injection", p))
        for p in sql_injection.PAYLOADS:
            out.append(("sql_injection", p))
        out.extend(type_confusion.generate_type_payloads())
        # RCE / SSTI probes also delivered as strings.
        out.extend(rce.generate_rce_payloads())
        # NoSQL string-form operator smuggling (e.g. "[$ne]=x").
        for p in nosql_injection.SQL_LIKE_NOSQL:
            out.append(("nosql_sql_like", p))
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

        # Schema-level rejection short-circuit. Pydantic/JSONSchema responses
        # echo the rejected input verbatim, which falsely matches every
        # success heuristic below. The unhandled-error check at the bottom
        # is still allowed to fire because Pydantic rejection is itself a
        # *handled* error (structured response, not stack trace).
        rejected = is_validation_rejection(response)

        if not rejected and category == "path_traversal" and path_traversal.looks_like_traversal_success(response):
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

        if not rejected and category == "command_injection" and command_injection.looks_like_injection_success(response):
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

        if not rejected and category.startswith("ssrf_") and ssrf.looks_like_ssrf_success(response):
            return Finding(
                risk_type=RiskType.R5,
                severity=Severity.CRITICAL,
                confidence=0.85,
                title=f"SSRF succeeded on tool '{tool_name}'",
                description="Server-side request forgery: tool fetched internal/metadata endpoint.",
                related_events=[event_id],
                tool_name=tool_name,
                reproduction=f"Call tool '{tool_name}' with an SSRF URL payload",
            )

        if not rejected and (category.startswith("nosql_") or category == "nosql_sql_like"):
            if nosql_injection.looks_like_nosql_error(response):
                return Finding(
                    risk_type=RiskType.R5,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    title=f"NoSQL error leaked on tool '{tool_name}'",
                    description="NoSQL injection payload triggered a backend error.",
                    related_events=[event_id],
                    tool_name=tool_name,
                    reproduction=f"Call tool '{tool_name}' with a NoSQL operator payload",
                )
            if nosql_injection.looks_like_nosql_leak(response):
                return Finding(
                    risk_type=RiskType.R5,
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    title=f"NoSQL injection data leak on tool '{tool_name}'",
                    description="NoSQL injection payload caused over-broad query result.",
                    related_events=[event_id],
                    tool_name=tool_name,
                    reproduction=f"Call tool '{tool_name}' with a NoSQL injection payload",
                )

        if not rejected and (category.startswith("rce_") or category in (
            "ssti", "eval_python", "eval_js", "eval_ruby", "eval_php", "eval_perl",
            "expr_lang", "jndi", "deserialize", "yaml_load", "xxe",
        )):
            if rce.looks_like_rce_success(response):
                return Finding(
                    risk_type=RiskType.R2,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    title=f"RCE indicator in response for tool '{tool_name}'",
                    description="RCE/SSTI/eval payload produced code-execution output.",
                    related_events=[event_id],
                    tool_name=tool_name,
                    reproduction=f"Call tool '{tool_name}' with an RCE/SSTI payload",
                )

        # Type-confusion: all categories including new ones.
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


def _url_param_names(tool: ToolInfo) -> list[str]:
    """Extract string parameters whose name or format hints at a URL."""
    schema = tool.input_schema or {}
    props = schema.get("properties", {})
    url_hints = {"url", "uri", "endpoint", "href", "link", "src", "source", "target", "fetch", "remote"}
    result = []
    for k, v in props.items():
        if not isinstance(v, dict):
            continue
        if v.get("format") == "uri":
            result.append(k)
        elif v.get("type") == "string" and any(h in k.lower() for h in url_hints):
            result.append(k)
    return result


def _object_param_names(tool: ToolInfo) -> list[str]:
    """Extract parameter names that accept object/any types (NoSQL targets)."""
    schema = tool.input_schema or {}
    props = schema.get("properties", {})
    return [
        k for k, v in props.items()
        if isinstance(v, dict) and v.get("type") in ("object", None)
        and "properties" not in v  # skip nested structured schemas
    ]


def _safe_dump(obj: Any) -> str:
    """JSON-serialise, falling back to str() for non-serialisable values."""
    try:
        return json.dumps(obj, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(obj)
