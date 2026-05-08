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
from itertools import groupby
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
from mcp_dynamic_analyzer.payloads._response_filters import (
    is_server_outcome,
    is_validation_rejection,
)
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
        """Breadth-first fuzzing across (depth, category, tool, param).

        Outer loop iterates the **payload index inside each category** so
        depth=0 visits one payload of every category for every tool before
        any tool sees its second payload. If the sequence-level timeout
        fires partway through, every (tool, category) has at least one
        payload tried — no tool is left untested.

        Categories are kept in risk-priority order so the highest-impact /
        highest-precision signals (sql_injection, command_injection, rce_*)
        run before the noisier ones (path_traversal mass, type_confusion
        variants).
        """
        cli: McpClient = client
        tools = await cli.list_tools()
        if not tools:
            return

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout * 0.95

        # Pre-compute per-tool param sets and per-(tool, category) circuit
        # breaker state. We use the tool name as a stable key.
        tool_state: list[dict[str, Any]] = []
        for t in tools:
            tool_state.append({
                "tool": t,
                "string_params": _string_param_names(t),
                "url_params": _url_param_names(t),
                "obj_params": _object_param_names(t),
                "broken_cats": set(),
            })

        # Risk-priority payload groups: list of (category, [payload, payload, ...]).
        string_groups = self._payload_groups("string")
        url_groups = self._payload_groups("url")
        obj_groups = self._payload_groups("object")

        max_depth = max(
            (len(p) for _, p in string_groups + url_groups + obj_groups),
            default=0,
        )

        log.info(
            "fuzz.breadth_first_start",
            tools=len(tools),
            max_depth=max_depth,
            string_categories=len(string_groups),
            url_categories=len(url_groups),
            object_categories=len(obj_groups),
            timeout_sec=self.timeout,
        )

        for depth in range(max_depth):
            if loop.time() >= deadline:
                log.warning(
                    "fuzz.deadline_hit",
                    depth_reached=depth,
                    hint="Sequence budget exhausted — every tool has at least "
                         f"{depth} payload(s) per category from earlier depths.",
                )
                break
            await self._run_depth(
                cli, writer, depth, tool_state, string_groups, "string", deadline,
            )
            if loop.time() >= deadline: break
            await self._run_depth(
                cli, writer, depth, tool_state, url_groups, "url", deadline,
            )
            if loop.time() >= deadline: break
            await self._run_depth(
                cli, writer, depth, tool_state, obj_groups, "object", deadline,
            )

    async def _run_depth(
        self,
        cli: McpClient,
        writer: EventWriter,
        depth: int,
        tool_state: list[dict[str, Any]],
        groups: list[tuple[str, list[Any]]],
        param_kind: str,  # "string" | "url" | "object"
        deadline: float,
    ) -> None:
        """For each category at *depth*, fire its payload at every tool."""
        loop = asyncio.get_running_loop()
        param_key = {
            "string": "string_params",
            "url": "url_params",
            "object": "obj_params",
        }[param_kind]
        for category, payloads in groups:
            if depth >= len(payloads):
                continue
            if loop.time() >= deadline:
                return
            payload = payloads[depth]
            for state in tool_state:
                if loop.time() >= deadline:
                    return
                params = state[param_key]
                if not params:
                    continue
                if category in state["broken_cats"]:
                    continue
                tool = state["tool"]
                for param in params:
                    if loop.time() >= deadline:
                        return
                    args: dict[str, Any] = {param: payload}
                    timed_out = await self._fuzz_one(cli, writer, tool.name, category, args)
                    if timed_out:
                        state["broken_cats"].add(category)
                        log.info(
                            "fuzz.circuit_breaker_tripped",
                            tool=tool.name,
                            category=category,
                            depth=depth,
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
        outcome: str
        # Refuse to send anything that wouldn't survive RFC 8259 — Python's
        # default ``json.dumps`` emits ``Infinity`` / ``NaN`` literals that
        # the server can't parse, which used to surface as a 15 s phantom
        # timeout misclassified as a hang.
        encoding_error = _json_encoding_error(arguments)
        if encoding_error is not None:
            resp_text = f"ClientSerializationError: {encoding_error}"
            outcome = "client_serialization"
        else:
            try:
                result = await asyncio.wait_for(
                    cli.call_tool(tool_name, arguments), timeout=_CALL_TIMEOUT
                )
                resp_text = _safe_dump(result)
                outcome = "server_response"
            except ServerCrashError:
                raise  # propagate immediately — do not record a fake test_result
            except asyncio.TimeoutError:
                resp_text = f"CallTimeout: no response within {_CALL_TIMEOUT:.0f}s"
                timed_out = True
                outcome = "client_timeout"
                log.warning(
                    "fuzz.call_timeout",
                    tool=tool_name,
                    category=category,
                    timeout=_CALL_TIMEOUT,
                )
            except McpError as e:
                resp_text = f"McpError({e.code}): {e.message}"
                outcome = "server_error"
            except Exception as e:
                resp_text = f"Exception: {e}"
                outcome = "client_exception"

        await writer.write(Event(
            session_id=self._session_id,
            source="test",
            type="test_result",
            data={
                "sequence": self.name,
                "tool": tool_name,
                "category": category,
                "response_preview": resp_text[:2000],
                # Distinguishes server-originated content from our own
                # wrapper text (timeouts, serialisation errors, ...). Indicator
                # matching MUST only run on server-sourced outcomes — otherwise
                # our ``ClientSerializationError: ValueError: ...`` wrapper
                # itself trips the ``valueerror`` indicator.
                "outcome": outcome,
            },
        ))
        return timed_out

    def _payload_groups(self, kind: str) -> list[tuple[str, list[Any]]]:
        """Return ``[(category, [payloads...]), ...]`` in priority order.

        Grouping by category lets the breadth-first executor run one payload
        per category at depth=0, then a second one at depth=1, etc., so a
        partial run still tests every category for every tool.
        """
        if kind == "string":
            flat = self._build_string_payloads()
        elif kind == "url":
            flat = list(ssrf.generate_ssrf_payloads())
        elif kind == "object":
            flat = list(nosql_injection.generate_nosql_payloads())
        else:
            return []
        # ``groupby`` preserves the input order, which is the priority order.
        groups: list[tuple[str, list[Any]]] = []
        for cat, items in groupby(flat, key=lambda x: x[0]):
            groups.append((cat, [p for _, p in items]))
        return groups

    def _build_string_payloads(self) -> list[tuple[str, Any]]:
        """Return ``(category, value)`` pairs in **risk-priority order**.

        Categories are ordered so that the highest-impact / highest-precision
        signals run first within each tool's time budget. If a tool's budget
        is exhausted partway through, the categories most likely to surface
        a real finding have already been tested.

        Order rationale:
          1. ``sql_injection``     — high precision (postgres / mysql error
             patterns are unambiguous), critical impact for DB-bound MCPs.
          2. ``command_injection`` — broadly applicable, ``uid=`` / ``uname``
             output indicators are unambiguous.
          3. ``rce_*``             — catastrophic when present; canary echo
             is high precision after the response-filter cleanup.
          4. ``path_traversal``    — broad coverage but many payloads (~70)
             so it would otherwise hog the time budget.
          5. ``type_confusion``    — many payloads, mostly noise (Pydantic
             rejection); run late so it doesn't crowd out the others.
          6. ``nosql_sql_like``    — niche.
        """
        out: list[tuple[str, Any]] = []
        # 1. SQL injection
        for p in sql_injection.PAYLOADS:
            out.append(("sql_injection", p))
        # 2. Command injection
        for p in command_injection.PAYLOADS:
            out.append(("command_injection", p))
        # 3. RCE family (SSTI, eval sinks, JNDI, deserialise, YAML load, ...)
        out.extend(rce.generate_rce_payloads())
        # 4. Path traversal (large set)
        for p in path_traversal.ALL_PAYLOADS:
            out.append(("path_traversal", p))
        # 5. Type confusion (largest set, lowest signal-to-noise)
        out.extend(type_confusion.generate_type_payloads())
        # 6. NoSQL operator smuggling
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
            outcome = evt.data.get("outcome")  # None for legacy events

            finding = self._check(cat, resp, tool, evt.event_id, outcome)
            if finding:
                findings.append(finding)

        return findings

    def _check(
        self,
        category: str,
        response: str,
        tool_name: str,
        event_id: str,
        outcome: str | None = None,
    ) -> Finding | None:

        # Indicator matching is only meaningful on text the server actually
        # produced. ``client_serialization`` / ``client_timeout`` /
        # ``client_exception`` carry text we wrote ourselves (wrappers like
        # ``ClientSerializationError: ValueError: ...``) — letting them
        # through would falsely match e.g. the ``valueerror`` indicator on
        # our own message. For legacy events with no ``outcome`` field the
        # helper falls back to checking ``response`` for known client-wrapper
        # prefixes.
        if not is_server_outcome(outcome, response):
            return None

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


def _json_encoding_error(obj: Any) -> str | None:
    """Return an error message if *obj* can't be sent on the JSON-RPC wire.

    Mirrors the gate in R6 (``r6_stability._json_encoding_error``). Uses
    ``allow_nan=False`` to catch ``float('inf')`` / ``NaN`` here so the
    fuzzer records a ``ClientSerializationError`` instead of letting the
    payload reach the wire as an ``Infinity`` literal — which Node-side
    JSON.parse rejects, producing a 15 s phantom timeout that misclassifies
    as a server hang.
    """
    try:
        json.dumps(obj, ensure_ascii=False, allow_nan=False)
        return None
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return f"{type(exc).__name__}: {exc}"
