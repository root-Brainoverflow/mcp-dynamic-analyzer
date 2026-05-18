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
from mcp_dynamic_analyzer.payloads._response_filters import (
    is_clean_success_envelope,
    is_handled_tool_error,
    is_server_outcome,
    strip_payload_echo,
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
# Cascade-grouping window for client_timeout events. The fuzzer's call
# timeout is 15 s, so back-to-back timeouts on the same tool sit ~15 s
# apart. 30 s gives slack for the next test's setup + write while still
# being far below any reasonable independent-hang spacing — if a user
# really managed to construct two distinct payloads that each hang the
# tool, the tests for them would not run within 30 s of each other
# because the first one keeps the slot occupied.
_CASCADE_GAP_S = 30.0
_REPR = reprlib.Repr()
_REPR.maxstring = 200


def _group_cascading_timeouts(events: list[Any], max_gap_s: float) -> list[list[Any]]:
    """Group client_timeout events on the same tool that occur within
    ``max_gap_s`` seconds of each other. Each returned inner list is one
    cascade (size 1 = independent timeout, size > 1 = stall + queued
    requests behind it).
    """
    if not events:
        return []
    events_sorted = sorted(events, key=lambda e: e.ts)
    groups: list[list[Any]] = [[events_sorted[0]]]
    for evt in events_sorted[1:]:
        gap = (evt.ts - groups[-1][-1].ts).total_seconds()
        if gap <= max_gap_s:
            groups[-1].append(evt)
        else:
            groups.append([evt])
    return groups
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
        # Payload *categories* the orchestrator flagged as crash triggers
        # after a previous run died and the sandbox was restarted. Skipped
        # for every tool (a process crash takes down all tools, so re-sending
        # the same category elsewhere only buys more crashes), so the rerun
        # makes progress instead of exhausting restart budget on one bug.
        self.skip_categories: set[str] = set()

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
                if category in self.skip_categories:
                    continue
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
        outcome: str
        timed_out = False
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
            except ServerCrashError as exc:
                # Tag the in-flight (tool, category) so the orchestrator can
                # tell the restarted sequence to skip it rather than replay
                # the payload that just crashed the server.
                if not getattr(exc, "crash_signature", None):
                    exc.crash_signature = (tool_name, category)  # type: ignore[attr-defined]
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
                "outcome": outcome,
                "payload_repr": _payload_repr(arguments),
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
        findings.extend(await self._check_prerequisites(reader))

        # Suppress sequence-timeout meta-findings when per-tool timeout
        # findings already cover the same ground. The sequence timeout fires
        # whenever a fuzz batch overruns its budget — but if the per-tool
        # ``_check_client_timeouts`` cascade detector also found stalls, the
        # sequence timeout is just the aggregate symptom of those stalls,
        # not an independent signal. ses-4e4da42e (RSS) showed three R6
        # findings — two real per-tool stalls and one redundant LOW
        # "Sequence timeout: fuzz_input_validation" whose own description
        # admits "Per-tool client_timeout findings, when present, localise
        # the cause." When they're present, we don't need it.
        has_per_tool_timeout = any(
            f.risk_type == RiskType.R6
            and f.tool_name
            and ("timeout" in f.title.lower() or "stalled" in f.title.lower() or "cascading" in f.title.lower())
            for f in findings
        )
        if has_per_tool_timeout:
            findings = [
                f for f in findings
                if not (f.risk_type == RiskType.R6 and f.title.startswith("Sequence timeout:"))
            ]

        return findings

    async def _check_prerequisites(self, reader: Any) -> list[Finding]:
        """Surface ``prerequisite_missing`` events the orchestrator recorded —
        the server needs a runtime component (binary / browser / module) that
        the sandbox couldn't auto-install, so part of the tool surface went
        untested. A coverage caveat, not a threat — hence LOW."""
        findings: list[Finding] = []
        seen: set[str] = set()
        async for evt in reader.events_by_type("prerequisite_missing"):
            name = (str(evt.data.get("name") or "")).strip() or "an external component"
            if name in seen:
                continue
            seen.add(name)
            findings.append(Finding(
                risk_type=RiskType.R6,
                severity=Severity.LOW,
                confidence=0.7,
                title=f"Scan coverage incomplete — server needs '{name}' (not installed)",
                description=(
                    f"This server's tools depend on '{name}', which wasn't available in the "
                    f"sandbox (the analyzer tried to auto-install it and couldn't). So those "
                    f"tools weren't actually exercised — **the verdict reflects only the parts "
                    f"that could be tested**, not the whole server. Treat the result as partial.\n\n"
                    f"To get a full scan: run the analyzer with `--no-docker` on a machine that "
                    f"already has '{name}' installed. If that's not an option, this is worth "
                    f"reporting to whoever maintains the analyzer — '{name}' is usually a one-line "
                    f"addition to the bootstrap recipes, after which it's handled automatically."
                ),
                related_events=[evt.event_id],
                reproduction=f"Call any tool that needs '{name}'",
            ))
        return findings

    async def _check_crashes(self, reader: Any) -> list[Finding]:
        # Group server_crash events by (sequence, category). A process-level
        # crash from a malformed-input class (e.g. lone-surrogate
        # ``encoding_traps``) reproduces on every tool that takes the
        # offending argument and triggers one server_crash per restart — all
        # of those describe a single vulnerability, usually in the shared
        # transport/SDK layer rather than one tool. Events with no category
        # recorded (legacy / non-fuzz crashes) each stand on their own.
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        order: list[tuple[str, str]] = []
        async for evt in reader.events_by_type("server_crash"):
            seq = evt.data.get("sequence", "unknown")
            tool = evt.data.get("tool")
            cat = evt.data.get("category")
            key = (seq, cat) if cat else (seq, f"\x00{evt.event_id}")
            g = groups.get(key)
            if g is None:
                g = {"seq": seq, "cat": cat, "tools": [], "event_ids": []}
                groups[key] = g
                order.append(key)
            g["event_ids"].append(evt.event_id)
            if tool and tool not in g["tools"]:
                g["tools"].append(tool)

        findings: list[Finding] = []
        for key in order:
            g = groups[key]
            seq, cat, tools, event_ids = g["seq"], g["cat"], g["tools"], g["event_ids"]
            if cat and tools:
                tool_list = ", ".join(f"'{t}'" for t in tools)
                multi = len(tools) > 1
                title = (
                    f"Server crash on '{cat}' input — affects tools {tool_list}"
                    if multi else
                    f"Server crash triggered by '{cat}' payload to tool {tool_list}"
                )
                description = (
                    f"Sending a '{cat}'-class payload to {tool_list} terminated the "
                    f"MCP server process (sequence '{seq}'). A single malformed request "
                    f"crashes the server — a trivially exploitable DoS."
                )
                if multi:
                    description += (
                        " The crash reproduces across every listed tool, so the fault "
                        "is in the shared request/transport handling rather than one "
                        "tool's logic."
                    )
                reproduction = f"Send a '{cat}' payload to tool '{tools[0]}'"
                tool_name: str | None = tools[0]
            else:
                title = f"Server crashed during sequence '{seq}'"
                description = (
                    f"The MCP server process terminated unexpectedly while running "
                    f"test sequence '{seq}'. This indicates fragile error handling "
                    f"that could be exploited for DoS."
                )
                reproduction = f"Run sequence '{seq}' and observe server process"
                tool_name = None
            findings.append(Finding(
                risk_type=RiskType.R6,
                severity=Severity.HIGH,
                confidence=0.9,
                title=title,
                description=description,
                related_events=event_ids,
                tool_name=tool_name,
                reproduction=reproduction,
            ))
        return findings

    async def _check_timeouts(self, reader: Any) -> list[Finding]:
        findings: list[Finding] = []
        async for evt in reader.events_by_type("sequence_timeout"):
            seq = evt.data.get("sequence", "unknown")
            # Sequence-level timeouts are *meta*-signals: the whole test
            # sequence (init_enumerate / fuzz_input_validation / ...) didn't
            # finish in its budget. That conflates three different causes:
            #
            #   1. A real per-input stall — but then a corresponding
            #      ``client_timeout`` test_result fires at the *tool* level
            #      with much higher specificity, which ``_check_client_timeouts``
            #      reports at MEDIUM with cascade grouping.
            #   2. The server is slow because it makes outbound network calls
            #      (wikipedia-mcp, fetch-mcp, github-mcp do live HTTP) and
            #      network latency exceeds the scan budget — not a server
            #      defect at all.
            #   3. The fuzz set is too large for the configured budget — an
            #      analyzer-configuration concern, not a server one.
            #
            # Demote to LOW so the meta-signal still surfaces (useful when
            # debugging a scan) but doesn't drive the overall verdict. Real
            # hangs continue to be reported at MEDIUM via the per-tool
            # client_timeout path.
            findings.append(Finding(
                risk_type=RiskType.R6,
                severity=Severity.LOW,
                confidence=0.5,
                title=f"Sequence timeout: '{seq}'",
                description=(
                    f"Test sequence '{seq}' did not complete within its timeout. "
                    f"This can indicate a server hang, slow outbound calls "
                    f"(retrieval / API-wrapping tools), or an undersized scan "
                    f"budget. Per-tool ``client_timeout`` findings, when present, "
                    f"localise the cause."
                ),
                related_events=[evt.event_id],
                reproduction=f"Run sequence '{seq}' with its specific inputs",
            ))
        return findings

    async def _check_client_timeouts(self, reader: Any) -> list[Finding]:
        """Group client_timeout test_result events into cascades.

        A single Node/asyncio MCP server is single-threaded: when one fuzz
        input puts it into an unresponsive state, every subsequent input is
        queued behind that stalled request and hits the same client-side
        15 s timeout. Without dedup, each of those queued requests becomes
        its own "Timeout / hang on category 'X' for tool 'Y'" finding —
        inflating one underlying stall into N findings (one per category
        that happened to be tested during the cascade window).

        Heuristic: timeouts on the same tool with consecutive gaps ≤
        ``_CASCADE_GAP_S`` are treated as one cascade. The first event's
        category is the actual trigger; the others are "subsequent requests
        also timed out behind the stall."
        """
        from collections import defaultdict
        by_tool: dict[str, list[Any]] = defaultdict(list)
        async for evt in reader.events_by_type("test_result"):
            if evt.data.get("sequence") != "fuzz_stability":
                continue
            if evt.data.get("outcome") != "client_timeout":
                continue
            by_tool[str(evt.data.get("tool") or "")].append(evt)

        findings: list[Finding] = []
        for tool, evts in by_tool.items():
            for group in _group_cascading_timeouts(evts, _CASCADE_GAP_S):
                first = group[0]
                cat = str(first.data.get("category") or "")
                rel = [e.event_id for e in group]
                if len(group) == 1:
                    findings.append(Finding(
                        risk_type=RiskType.R6,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        title=f"Timeout / hang on category '{cat}' for tool '{tool}'",
                        description=f"Payload in category '{cat}' caused the server to time out.",
                        related_events=rel,
                        tool_name=tool,
                        reproduction=f"Send '{cat}' payload to tool '{tool}'",
                    ))
                else:
                    others = sorted({str(e.data.get("category") or "") for e in group[1:]} - {cat})
                    others_blurb = ", ".join(f"'{c}'" for c in others) or "various"
                    findings.append(Finding(
                        risk_type=RiskType.R6,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        title=f"Tool '{tool}' stalled after '{cat}' input (cascading timeouts on {len(group) - 1} subsequent requests)",
                        description=(
                            f"A payload in category '{cat}' put '{tool}' into an unresponsive state; "
                            f"the following {len(group) - 1} subsequent fuzz inputs "
                            f"({others_blurb}) were also queued behind the stall and hit the client "
                            f"timeout — one underlying stall, not {len(group)} independent hangs. "
                            f"Root cause is the first input; the cascade indicates the stall is "
                            f"persistent (the server did not recover within the test window)."
                        ),
                        related_events=rel,
                        tool_name=tool,
                        reproduction=f"Send '{cat}' payload to tool '{tool}'",
                    ))
        return findings

    async def _check_error_rate(self, reader: Any) -> list[Finding]:
        """Examine the distribution of JSON-RPC error codes across all
        server responses. The default behavior under malformed input is
        well-defined by the spec:

        * ``-32700`` Parse error — malformed JSON itself
        * ``-32600`` Invalid Request — structurally wrong JSON-RPC envelope
        * ``-32601`` Method not found — unknown tool / method
        * ``-32602`` **Invalid Params** — bad argument shape / type. *This*
          is what a properly-validating server returns for user input that
          fails its tool schema.
        * ``-32603`` **Internal error** — an unexpected server-side
          exception. Should not be the response to user input; if it is,
          input is reaching exception-prone code paths *before* validation,
          and the ``message`` typically carries a leaked stack trace.

        We surface two distinct findings:

        1. *Predominantly -32603*: input validation weakness + info
           disclosure (CWE-20 + CWE-209). Higher severity than the generic
           rate finding because the cause is specific and actionable.
        2. *High error rate, mixed codes*: fall back to the generic
           "noisy server" signal at lower confidence.
        """
        from collections import Counter

        total_calls = 0
        error_codes: Counter[int] = Counter()
        sample_msg: dict[int, str] = {}

        async for evt in reader.events_by_type("mcp_response"):
            if evt.direction != "s2c":
                continue
            msg = evt.data.get("message", {}) or {}
            total_calls += 1
            err = msg.get("error")
            if not isinstance(err, dict):
                continue
            code = err.get("code")
            if not isinstance(code, int):
                continue
            error_codes[code] += 1
            if code not in sample_msg:
                sample_msg[code] = str(err.get("message", ""))[:200]

        total_errors = sum(error_codes.values())
        if total_calls < 5 or total_errors == 0:
            return []
        rate = total_errors / total_calls
        if rate < 0.5:
            return []

        findings: list[Finding] = []
        n_32603 = error_codes.get(-32603, 0)
        n_32602 = error_codes.get(-32602, 0)
        share_32603 = n_32603 / total_errors if total_errors else 0.0

        if n_32603 >= 5 and share_32603 >= 0.5:
            # ses-c392aa7f / ses-ee7da439 (chart server): malformed input
            # reaches a backend NPE that's wrapped in -32603 with a leaked
            # TypeError trace, instead of being rejected as -32602.
            sample = sample_msg.get(-32603, "")
            findings.append(Finding(
                risk_type=RiskType.R6,
                severity=Severity.MEDIUM,
                confidence=0.8,
                title=(
                    f"Server returns -32603 'Internal error' for "
                    f"{n_32603}/{total_errors} malformed inputs "
                    f"(should be -32602 Invalid Params)"
                ),
                description=(
                    f"Of {total_errors} JSON-RPC error responses across the scan, "
                    f"{n_32603} ({share_32603:.0%}) used code -32603 (Internal Error) "
                    f"and only {n_32602} used -32602 (Invalid Params). MCP servers "
                    f"should reserve -32603 for unexpected internal failures; user "
                    f"input that fails validation belongs in -32602. The -32603 "
                    f"misuse implies input is reaching exception-prone code paths "
                    f"before any schema validation runs, and the ``message`` field "
                    f"typically leaks a stack trace from the deepest failing layer "
                    f"(library / backend / dependency). Maps to CWE-20 (Improper "
                    f"Input Validation) + CWE-209 (Information Exposure Through "
                    f"Error Messages). Sample message: {sample!r}"
                ),
                reproduction=(
                    "Send malformed input (wrong type, missing required field, "
                    "out-of-range value) to any tool; observe a -32603 response "
                    "with a stack trace where a -32602 'Invalid Params' would "
                    "have been correct."
                ),
            ))
            # When -32603 misuse is the headline, suppress the generic
            # rate finding — it would just say the same thing less precisely.
            return findings

        findings.append(Finding(
            risk_type=RiskType.R6,
            severity=Severity.MEDIUM,
            confidence=0.6,
            title=f"High error rate: {total_errors}/{total_calls} ({rate:.0%})",
            description=(
                f"{total_errors} out of {total_calls} server responses were errors. "
                f"This suggests poor input validation or unstable implementation."
            ),
            reproduction="Review error responses across all tool calls",
        ))
        return findings

    async def _check_response_indicators(self, reader: Any) -> list[Finding]:
        """Check stability-fuzz test_result events for OOM/crash/parser strings."""
        findings: list[Finding] = []
        # PASS 1 — group cascading client_timeout events. One pathological
        # payload puts a single-threaded server into an unresponsive state;
        # every subsequent fuzz input queues behind it and hits the same
        # 15 s client timeout. Without dedup that one underlying stall is
        # reported as N separate "timeout on category X" findings (one per
        # category that happened to be tested during the cascade). Grouping
        # by tool + tight time-gap collapses the cascade to its root cause.
        findings.extend(await self._check_client_timeouts(reader))

        async for evt in reader.events_by_type("test_result"):
            if evt.data.get("sequence") != "fuzz_stability":
                continue
            resp = evt.data.get("response_preview", "")
            outcome = evt.data.get("outcome")  # None for legacy events
            tool = evt.data.get("tool", "")
            cat = evt.data.get("category", "")

            # client_timeout handled in PASS 1 above with cascade-grouping.
            if outcome == "client_timeout":
                continue

            # Other client-side outcomes (serialisation failure, generic
            # exceptions) carry text we wrote ourselves. Indicator matching
            # would falsely fire on our wrapper, so skip them entirely. The
            # response argument lets legacy events (no ``outcome``) fall
            # back to prefix-based detection.
            if not is_server_outcome(outcome, resp):
                continue

            # Mask payload echoes so reflected payload syntax doesn't
            # falsely trigger OOM / stack-overflow indicators. A real
            # server-side failure leaves error text OUTSIDE the masked
            # echo region and still matches.
            payload_repr = evt.data.get("payload_repr", "")
            masked = strip_payload_echo(resp, payload_repr)

            # A clean, *successful* structured result is not a malfunction —
            # whatever error-looking strings the returned data happens to
            # contain (e.g. ``search_issues`` returning a GitHub issue titled
            # "Cannot read properties of undefined ..."). The malfunction
            # indicators below only make sense on error/non-data responses.
            if is_clean_success_envelope(resp):
                continue

            # A *handled* tool error (FastMCP ``{"isError": true, "...": "Error
            # executing tool X: <exc>"}``) means the server caught the failure
            # and returned it — the process is alive. An OOM / recursion /
            # abort message in such a wrapper is a resilience concern but NOT a
            # real process crash, so we de-rate it to LOW rather than
            # HIGH/CRITICAL — the process kept serving the next request, which
            # is the property that matters for *stability*. ses-45ee8108
            # surfaced two ``handled`` recursion errors on Ghidra's json_bomb
            # input as MEDIUM, but the description itself notes "process
            # survives, the call fails rather than the server"; that is by
            # definition a graceful-degradation outcome, not a stability bug.
            handled = is_handled_tool_error(resp)

            if looks_like_oom(masked):
                findings.append(Finding(
                    risk_type=RiskType.R6,
                    severity=Severity.LOW if handled else Severity.HIGH,
                    confidence=0.7 if handled else 0.85,
                    title=(
                        f"Handled out-of-memory error on category '{cat}' for tool '{tool}'"
                        if handled else
                        f"OOM indicator on category '{cat}' for tool '{tool}'"
                    ),
                    description=(
                        f"Pathological input in category '{cat}' drove the server into an "
                        f"out-of-memory condition; it was caught and returned as a tool "
                        f"error (the process survives), but the resource exhaustion is real."
                        if handled else
                        f"Stability payload in category '{cat}' triggered an out-of-memory condition."
                    ),
                    related_events=[evt.event_id],
                    tool_name=tool,
                    reproduction=f"Send '{cat}' payload to tool '{tool}'",
                ))
            elif looks_like_stack_overflow(masked):
                findings.append(Finding(
                    risk_type=RiskType.R6,
                    severity=Severity.LOW if handled else Severity.HIGH,
                    confidence=0.7 if handled else 0.85,
                    title=(
                        f"Handled recursion-depth error on category '{cat}' for tool '{tool}'"
                        if handled else
                        f"Stack overflow on category '{cat}' for tool '{tool}'"
                    ),
                    description=(
                        f"Deeply-nested input in category '{cat}' drove the server into a "
                        f"recursion-depth error; it was caught and returned as a tool error "
                        f"(the process survives), so the call fails rather than the server."
                        if handled else
                        f"Deeply-nested input in category '{cat}' caused a stack overflow."
                    ),
                    related_events=[evt.event_id],
                    tool_name=tool,
                    reproduction=f"Send deeply-nested '{cat}' payload to tool '{tool}'",
                ))
            elif looks_like_parser_failure(masked):
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
            elif looks_like_crash(masked):
                findings.append(Finding(
                    risk_type=RiskType.R6,
                    severity=Severity.LOW if handled else Severity.CRITICAL,
                    confidence=0.7 if handled else 0.9,
                    title=(
                        f"Handled crash-like error on category '{cat}' for tool '{tool}'"
                        if handled else
                        f"Process crash on category '{cat}' for tool '{tool}'"
                    ),
                    description=(
                        f"The response for category '{cat}' carries a crash-like message "
                        f"(segfault / abort) but came back as a handled tool error — likely a "
                        f"crashed helper subprocess rather than the MCP server itself."
                        if handled else
                        f"Payload in category '{cat}' caused the server process to crash (segfault / abort)."
                    ),
                    related_events=[evt.event_id],
                    tool_name=tool,
                    reproduction=f"Send '{cat}' payload to tool '{tool}'",
                ))
            elif not handled and looks_like_timeout(resp):
                # ``not handled``: a real hang is recorded as ``client_timeout``
                # (caught at the top of this loop) or as the legacy
                # ``CallTimeout:`` wrapper string (not a JSON envelope, so
                # ``handled`` is False). A *handled* tool error that merely
                # *mentions* "timeout" — e.g. a zod validation error listing a
                # ``timeout`` parameter (``chrome-devtools-mcp``'s
                # ``navigate_page`` / ``new_page``) — is not a hang.
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


def _payload_repr(arguments: dict[str, Any]) -> str:
    """Stable string of payload values for ``response_echoes_payload``.

    See ``r5_input_validation._payload_repr`` for rationale: we want only
    the *values* (what the server typically echoes), not the full
    ``{"<param>": ...}`` JSON wrapper.
    """
    parts: list[str] = []
    for v in arguments.values():
        if isinstance(v, str):
            parts.append(v)
        else:
            try:
                parts.append(json.dumps(v, ensure_ascii=False, default=str))
            except (TypeError, ValueError, OverflowError, RecursionError):
                parts.append(_REPR.repr(v))
    return "\n".join(parts)[:4000]


def _json_encoding_error(obj: Any) -> str | None:
    """Return an error message if *obj* cannot be sent on the JSON-RPC wire.

    Uses ``allow_nan=False`` so that ``float('inf')`` / ``float('-inf')`` /
    ``float('nan')`` are caught here instead of slipping through to the
    interceptor — which would emit ``Infinity`` / ``NaN`` literals (invalid
    per RFC 8259) and the server would fail to parse, producing a phantom
    15 s timeout that R6 used to misreport as a real hang.
    """
    try:
        json.dumps(obj, ensure_ascii=False, allow_nan=False)
        return None
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        return f"{type(exc).__name__}: {exc}"


def _truncate_preview(text: str, limit: int = _ARG_PREVIEW_LIMIT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "...<truncated>"
