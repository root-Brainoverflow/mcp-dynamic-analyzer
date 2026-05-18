"""Top-level orchestration: collection → analysis → export."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

import structlog

from mcp_dynamic_analyzer.config import AnalysisConfig
from mcp_dynamic_analyzer.correlation.event_store import EventStore
from mcp_dynamic_analyzer.infrastructure.honeypot import Honeypot
from mcp_dynamic_analyzer.infrastructure.netmon import NetworkMonitor
from mcp_dynamic_analyzer.infrastructure.sandbox import Sandbox, generate_env_variation
from mcp_dynamic_analyzer.infrastructure.sysmon import SystemMonitor, SysmonUnavailableError
from mcp_dynamic_analyzer.models import AnalysisContext, AnalysisOutput, Event, Finding, ServerCrashError, ToolInfo
from mcp_dynamic_analyzer.payloads.stability import (
    looks_like_missing_prerequisite,
    missing_prerequisite_name,
)
from mcp_dynamic_analyzer.protocol.client import McpClient
from mcp_dynamic_analyzer.protocol.http_interceptor import HttpInterceptor
from mcp_dynamic_analyzer.protocol.interceptor import StdioInterceptor
from mcp_dynamic_analyzer.protocol.sequencer import InitSequence, Sequencer
from mcp_dynamic_analyzer.scanners.base import BaseScanner, TestSequence
from mcp_dynamic_analyzer.scanners.chain_attack import ChainAttackScanner
from mcp_dynamic_analyzer.scanners.r1_data_access import R1DataAccessScanner
from mcp_dynamic_analyzer.scanners.r2_code_exec import R2CodeExecScanner
from mcp_dynamic_analyzer.scanners.r3_llm_manipulation import R3LlmManipulationScanner
from mcp_dynamic_analyzer.scanners.r4_behavior_drift import R4BehaviorDriftScanner
from mcp_dynamic_analyzer.scanners.r5_input_validation import FuzzingSequence, R5InputValidationScanner
from mcp_dynamic_analyzer.scanners.r6_stability import R6StabilityScanner, StabilityFuzzingSequence

log = structlog.get_logger()

# Events from the collection re-run that follows a "missing prerequisite" auto-
# install get this ``variation_tag`` so the post-retry "is it still broken?"
# check inspects *only that re-run* — a successful fix isn't masked by the
# degraded first run still sitting in the event log.
_PREREQ_RETRY_TAG = "prereq-retry"


class _TaggedWriter:
    """Injects variation_tag into events written during env-variation collection."""

    def __init__(self, base_writer: Any, variation_tag: str | None) -> None:
        self._base = base_writer
        self._tag = variation_tag

    async def write(self, event: Event) -> None:
        if self._tag and event.variation_tag is None:
            event = event.model_copy(update={"variation_tag": self._tag})
        await self._base.write(event)


def build_default_scanners(config: AnalysisConfig) -> list[BaseScanner]:
    """Instantiate all enabled scanners from config."""
    sc = config.scanners
    all_scanners: list[tuple[BaseScanner, bool]] = [
        (R1DataAccessScanner(), sc.r1_data_access.enabled),
        (R2CodeExecScanner(), sc.r2_code_exec.enabled),
        (R3LlmManipulationScanner(), sc.r3_llm_manipulation.enabled),
        (R4BehaviorDriftScanner(), sc.r4_behavior_drift.enabled),
        (R5InputValidationScanner(), sc.r5_input_validation.enabled),
        (R6StabilityScanner(), sc.r6_stability.enabled),
        (ChainAttackScanner(), True),
    ]
    return [s for s, enabled in all_scanners if enabled]


def build_default_sequences(
    config: AnalysisConfig,
    session_id: str,
    *,
    extra_sequences: list[TestSequence] | None = None,
) -> list[TestSequence]:
    """Build the default collection sequences for a scan session."""
    sequences: list[TestSequence] = [InitSequence(session_id)]
    if config.scanners.r5_input_validation.enabled:
        sequences.append(FuzzingSequence(session_id=session_id))
    if config.scanners.r6_stability.enabled:
        sequences.append(StabilityFuzzingSequence(session_id=session_id))
    if extra_sequences:
        sequences.extend(extra_sequences)
    return sequences


def _session_id() -> str:
    return f"ses-{uuid4()}"


async def run_analysis(
    config: AnalysisConfig,
    static_context: dict[str, Any] | None = None,
    *,
    use_docker: bool = True,
    extra_sequences: list[TestSequence] | None = None,
    scanners: list[BaseScanner] | None = None,
) -> AnalysisOutput:
    """Execute the full collection → analysis → export pipeline."""
    session_id = _session_id()
    output_dir = Path(config.output.output_dir) / session_id
    event_store = EventStore(output_dir)
    tools: list[ToolInfo] = []
    started_at = time.monotonic()

    log.info("orchestrator.collection.start", session_id=session_id)

    sequences = build_default_sequences(
        config,
        session_id,
        extra_sequences=extra_sequences,
    )

    # Sidecar IPs accumulate across all sandbox iterations so analysis-phase
    # scanners (R1) can recognise them as legitimate destinations rather than
    # SSRF attempts at RFC1918 addresses.
    trusted_internal_ips: set[str] = set()

    try:
        tools = await _collect(
            config=config,
            session_id=session_id,
            event_store=event_store,
            sequences=sequences,
            use_docker=use_docker,
            trusted_internal_ips=trusted_internal_ips,
        )
    except RuntimeError as exc:
        # Server process exited immediately (startup failure).
        log.error(
            "orchestrator.collection.startup_failure",
            error=str(exc),
            hint=(
                "The target server process terminated before the MCP handshake "
                "could complete. Check --server-path is correct and that any "
                "required backend services are running."
            ),
        )
        raise

    # If the first collection timed out before returning tools, recover from events.
    if not tools:
        tools = await _read_tools_from_events(event_store.reader)

    if not tools:
        log.warning(
            "orchestrator.no_tools",
            hint=(
                "0 tools were discovered. Scan results will be limited. "
                "If the server requires a backend service (e.g. --server-arg to pass "
                "a URL), ensure that service is reachable before scanning."
            ),
        )

    r4_cfg = config.scanners.r4_behavior_drift
    if r4_cfg.enabled and r4_cfg.env_variations > 0:
        for i in range(r4_cfg.env_variations):
            env_override = generate_env_variation(config.server.env, variation_index=i)
            tag = f"env_{i}"
            log.info("orchestrator.env_variation", tag=tag)
            try:
                await _collect(
                    config=config,
                    session_id=session_id,
                    event_store=event_store,
                    sequences=[InitSequence(session_id)],
                    use_docker=use_docker,
                    env_override=env_override,
                    variation_tag=tag,
                    trusted_internal_ips=trusted_internal_ips,
                )
            except RuntimeError as exc:
                log.warning(
                    "orchestrator.env_variation.skipped",
                    tag=tag,
                    reason=str(exc),
                    hint="Env-variation run failed to start — skipping this variation.",
                )

    log.info("orchestrator.collection.done", session_id=session_id)

    log.info("orchestrator.analysis.start")
    reader = event_store.reader

    # Hand the collected sidecar IPs to scanners through static_context so
    # they can distinguish legitimate sidecar traffic from SSRF candidates.
    merged_static = dict(static_context or {})
    if trusted_internal_ips:
        existing = set(merged_static.get("trusted_internal_ips") or [])
        merged_static["trusted_internal_ips"] = sorted(existing | trusted_internal_ips)

    # The server's self-declared identity (from its ``initialize`` reply) is
    # used by tool-capability classification — ``wikipedia-mcp`` should
    # classify its ``search`` tool as a retrieval tool even when the tool's
    # own description is terse. Pulled from event-store here rather than from
    # ``config.server.command`` so we get the *actual* serverInfo.name, not
    # the harness command (``uvx``, ``npx``, ``docker``).
    discovered_for_ctx = await _extract_server_info(reader)
    if discovered_for_ctx.get("name"):
        merged_static["server_name"] = discovered_for_ctx["name"]

    ctx = AnalysisContext(
        session_id=session_id,
        event_reader=reader,
        tools=tools,
        static_context=merged_static or None,
        config=config.model_dump(),
    )

    if scanners is None:
        scanners = build_default_scanners(config)

    findings: list[Finding] = []
    for scanner in scanners:
        scanner_cfg = config.model_dump().get("scanners", {}).get(scanner.name, {})
        if not scanner_cfg.get("enabled", True):
            continue
        try:
            result = await scanner.analyze(ctx)
            findings.extend(result)
            log.info("scanner.done", scanner=scanner.name, findings=len(result))
        except Exception:
            log.exception("scanner.error", scanner=scanner.name)

    from mcp_dynamic_analyzer.correlation.engine import CorrelationEngine
    from mcp_dynamic_analyzer.output.exporter import Exporter
    from mcp_dynamic_analyzer.output.reporter import Reporter
    from mcp_dynamic_analyzer.output.scorer import Scorer

    correlated = await CorrelationEngine(reader).correlate(findings)
    scoring_result = Scorer().score(correlated)
    event_count = await reader.count()

    # Prefer the server's self-declared identity from its `initialize` reply
    # (e.g. ``drawio-mcp``, ``chrome_devtools``, ``n8n-documentation-mcp``)
    # over the raw launch command (``npx``, ``docker``, ``uvx``) — the latter
    # is just the harness, not the server. Falls back to the command if the
    # initialize handshake never produced a serverInfo (server crashed at
    # startup, no tools discovered, ...).
    discovered = await _extract_server_info(reader)
    output = AnalysisOutput(
        session_id=session_id,
        server={
            "name": discovered.get("name") or config.server.command,
            "version": discovered.get("version", ""),
            "title": discovered.get("title", ""),
            "command": config.server.command,
            "args": config.server.args,
        },
        findings=correlated,
        event_log_path=str(event_store.events_path),
        dynamic_risk_scores=scoring_result.per_risk,
        metadata={
            "duration_sec": time.monotonic() - started_at,
            "tools_tested": len(tools),
            "total_events": event_count,
        },
    )

    exporter = Exporter()
    exporter.export(output, scoring_result, output_dir)
    exporter.print_summary(output, scoring_result)
    Reporter(output_dir).write(output, scoring_result)

    log.info("orchestrator.done", session_id=session_id, findings=len(correlated))
    return output


_MAX_CRASH_RESTARTS = 3


async def _collect(
    *,
    config: AnalysisConfig,
    session_id: str,
    event_store: EventStore,
    sequences: list[TestSequence],
    use_docker: bool,
    env_override: dict[str, str] | None = None,
    variation_tag: str | None = None,
    trusted_internal_ips: set[str] | None = None,
) -> list[ToolInfo]:
    """Run collection sequences inside a sandbox, return discovered tools.

    If the server crashes mid-sequence, the sandbox is restarted and the
    remaining sequences continue on the fresh container (up to
    ``_MAX_CRASH_RESTARTS`` times).
    """
    tools: list[ToolInfo] = []
    honeypot: Honeypot | None = None

    async with event_store.writer as base_writer:
        writer = _TaggedWriter(base_writer, variation_tag)

        honeypot_dir: str | None = None
        if config.scanners.r1_data_access.enabled:
            honeypot = Honeypot(writer, session_id)
            honeypot_dir = str(honeypot.create())

        remaining = list(sequences)
        crash_count = 0
        # Payload categories that have crashed the server in a prior
        # iteration. Re-applied to every fuzzing sequence before each
        # (re)run so a restarted sequence skips the whole category instead
        # of replaying it tool-by-tool — a process crash takes down all
        # tools, so re-firing the category elsewhere only burns more restart
        # budget for no new signal.
        crash_categories: set[str] = set()
        # When the collected tool responses reveal a missing runtime
        # prerequisite (the server stays up but is degraded — e.g.
        # chrome-devtools-mcp without Chrome), this carries the offending
        # response text to the *next* sandbox, which re-resolves it via the
        # recipe stderr-tokens / apt heuristic, rebuilds the image, and the
        # whole collection re-runs once. ``prereq_retry_done`` bounds it to one
        # such retry per collection.
        prereq_hint: str | None = None
        prereq_retry_done = False
        prereq_outcome_recorded = False
        sysmon_enabled = (
            config.scanners.r1_data_access.enabled
            or config.scanners.r2_code_exec.enabled
        )

        while remaining:
            # Every fresh sandbox spawn = fresh server process with no MCP
            # protocol state. The JSON-RPC ``initialize`` handshake must run
            # before any ``tools/call`` will be accepted (servers respond
            # with ``-32602 Invalid request parameters`` and ``Received
            # request before initialization was complete``). On retry after
            # a ServerCrashError, ``remaining`` typically starts with the
            # sequence that crashed (e.g. ``fuzz_input_validation``) —
            # prepend InitSequence so the new server gets re-initialised.
            if not isinstance(remaining[0], InitSequence):
                remaining = [InitSequence(session_id), *remaining]
            # Propagate known crash-trigger categories to every fuzzing
            # sequence so the restarted run skips them instead of replaying
            # the same payload class tool-by-tool.
            for seq in remaining:
                if hasattr(seq, "skip_categories"):
                    seq.skip_categories = set(crash_categories)
            monitors: list[Any] = []
            async with Sandbox(
                config.server,
                config.sandbox,
                env_override=env_override,
                honeypot_dir=honeypot_dir,
                use_docker=use_docker,
                sysmon_enabled=sysmon_enabled,
                prereq_hint=prereq_hint,
            ) as sandbox:
                # Capture sidecar IPs as soon as the sandbox is up — they
                # exist for the duration of the ``async with`` block and
                # disappear on cleanup, so reading after this point fails.
                if trusted_internal_ips is not None and sandbox.sidecar_ips:
                    trusted_internal_ips.update(sandbox.sidecar_ips)

                interceptor = await _create_interceptor(config, sandbox, writer, session_id)
                client = McpClient(interceptor)
                sequencer = Sequencer(session_id, client, writer, remaining)

                try:
                    monitors = await _start_monitors(config, session_id, writer, sandbox, honeypot)

                    await asyncio.wait_for(
                        sequencer.run_all(),
                        timeout=config.sandbox.timeout,
                    )
                    tools = await _read_tools_from_events(event_store.reader)
                    if not tools:
                        try:
                            tools = await client.list_tools()
                        except Exception as exc:
                            log.warning(
                                "orchestrator.list_tools_after_sequences_failed",
                                error=str(exc),
                            )
                    remaining = []  # all sequences done

                except ServerCrashError as exc:
                    crash_count += 1
                    remaining = getattr(exc, "remaining_sequences", [])
                    sig = getattr(exc, "crash_signature", None)
                    if sig:
                        crash_categories.add(sig[1])  # sig == (tool, category)
                    log.warning(
                        "orchestrator.server_crashed",
                        crash_count=crash_count,
                        crash_signature=sig,
                        remaining_sequences=[s.name for s in remaining],
                        hint=(
                            "Server process crashed mid-scan. "
                            f"Restarting sandbox to continue ({crash_count}/{_MAX_CRASH_RESTARTS})."
                            if remaining and crash_count < _MAX_CRASH_RESTARTS
                            else "Max crash restarts reached — skipping remaining sequences."
                        ),
                    )
                    tools = await _read_tools_from_events(event_store.reader)
                    if crash_count >= _MAX_CRASH_RESTARTS:
                        remaining = []

                except asyncio.TimeoutError:
                    log.warning(
                        "orchestrator.global_timeout",
                        timeout=config.sandbox.timeout,
                        hint="Increase sandbox.timeout in config if the server needs more time.",
                    )
                    tools = await _read_tools_from_events(event_store.reader)
                    remaining = []

                except ConnectionError as exc:
                    log.error(
                        "orchestrator.server_stream_closed",
                        error=str(exc),
                        is_running=sandbox.is_running,
                        hint=(
                            "Server stdout EOF — the process may have crashed. "
                            "Check sandbox.server_stderr log lines above for details."
                        ),
                    )
                    remaining = []

                finally:
                    if not sandbox.is_running:
                        proc = sandbox._proc  # noqa: SLF001
                        rc = proc.returncode if proc else None
                        log.warning("orchestrator.server_exited_early", rc=rc)
                    await _stop_monitors(monitors, honeypot)
                    await interceptor.close()

            # The server stayed up, but its tool responses look degraded by a
            # missing runtime prerequisite (chrome-devtools-mcp without Chrome,
            # a server whose tool shells out to a binary that isn't installed,
            # …). Detect that *generically* from the collected responses, hand
            # the offending text to the next sandbox (which re-resolves it via
            # recipe ``stderr_tokens_any`` / the apt heuristic, rebuilds the
            # image), and re-run the whole collection once.
            if use_docker and not remaining and not prereq_retry_done:
                hint = await _detect_missing_prerequisite(event_store.reader)
                if hint:
                    prereq_hint = hint
                    prereq_retry_done = True
                    remaining = list(sequences)
                    # Tag the re-run's events so the post-retry check below can
                    # tell "fixed" (the rebuilt-image re-run is clean) from
                    # "still broken" (the re-run still fails for the same reason).
                    writer = _TaggedWriter(base_writer, _PREREQ_RETRY_TAG)
                    log.warning(
                        "orchestrator.prerequisite_missing_retry",
                        hint=hint[:240],
                        note=(
                            "Tool responses indicate a missing runtime prerequisite — "
                            "rebuilding the sandbox image with the fix and re-running "
                            "collection once."
                        ),
                    )

            # The auto-install pass has run. If the *re-run* (tagged
            # ``prereq-retry``) still shows the missing-prerequisite pattern —
            # no recipe/apt fix was applicable, or it didn't take — record a
            # ``prerequisite_missing`` event so the report carries a clear
            # caveat. The scan still completes; it just couldn't exercise the
            # tools that need the missing component, so the user knows exactly
            # what's missing and that the verdict is partial.
            if use_docker and prereq_retry_done and not remaining and not prereq_outcome_recorded:
                prereq_outcome_recorded = True
                still = await _detect_missing_prerequisite(
                    event_store.reader, only_tag=_PREREQ_RETRY_TAG,
                )
                if still:
                    name = missing_prerequisite_name(prereq_hint or still)
                    await writer.write(Event(
                        session_id=session_id,
                        source="orchestrator",
                        type="prerequisite_missing",
                        data={"name": name, "hint": (prereq_hint or still)[:600]},
                    ))
                    log.warning(
                        "orchestrator.prerequisite_unmet",
                        name=name,
                        note=(
                            "Server tools still fail for a missing runtime prerequisite "
                            "after the auto-install pass — scan ran with reduced coverage; "
                            "report carries a caveat finding."
                        ),
                    )

        if honeypot is not None:
            honeypot.cleanup()

    return tools


async def _detect_missing_prerequisite(
    reader: Any,
    *,
    fraction: float = 0.25,
    min_distinct_tools: int = 3,
    only_tag: str | None = None,
) -> str | None:
    """Return one tool-response text revealing a missing runtime prerequisite,
    or ``None``. Conservative: only fires when many responses across several
    tools match, so one stray ``ModuleNotFoundError`` from a weird fuzz payload
    doesn't trigger a wasteful image rebuild.

    ``only_tag`` restricts the scan to ``test_result`` events carrying that
    ``variation_tag`` — used for the *post-retry* "is it still broken?" check,
    which inspects only the rebuilt-image re-run (tagged ``prereq-retry``) so a
    successful fix isn't masked by the degraded first run still in the log.
    """
    total = 0
    matched_count = 0
    matched_tools: set[str] = set()
    sample: str | None = None
    async for evt in reader.events_by_type("test_result"):
        if only_tag is not None and getattr(evt, "variation_tag", None) != only_tag:
            continue
        text = str(evt.data.get("response_preview", "") or "")
        if not text:
            continue
        total += 1
        if looks_like_missing_prerequisite(text):
            matched_count += 1
            matched_tools.add(str(evt.data.get("tool") or ""))
            if sample is None:
                sample = text[:600]
    if total < 10 or sample is None:
        return None
    if len(matched_tools - {""}) >= min_distinct_tools or matched_count / total >= fraction:
        return sample
    return None


async def _extract_server_info(reader: Any) -> dict[str, str]:
    """Return the MCP server's self-declared identity from the first
    ``initialize`` reply seen in the event log.

    MCP servers populate ``result.serverInfo`` in their ``initialize``
    response with ``{name, version, title?}``. We surface those in the final
    report's ``Server:`` line so it reads like
    ``drawio-mcp 1.0.0`` instead of ``npx`` (which is just the launcher).
    Returns an empty dict if the handshake never produced a serverInfo —
    callers should fall back to the launch command for the ``name`` field.
    """
    async for evt in reader.events_by_type("mcp_response"):
        msg = evt.data.get("message")
        if not isinstance(msg, dict):
            continue
        info = (msg.get("result") or {}).get("serverInfo")
        if not isinstance(info, dict):
            continue
        out: dict[str, str] = {}
        for key in ("name", "version", "title"):
            value = info.get(key)
            if isinstance(value, str) and value:
                out[key] = value
        if out.get("name"):
            return out
    return {}


async def _read_tools_from_events(reader: Any) -> list[ToolInfo]:
    """Recover the tools list from the event log.

    Primary source: the ``init_enumerate`` test_result event written by
    ``InitSequence``. If that sequence timed out before completing, fall back
    to scanning ``mcp_response`` events for any successful ``tools/list``
    response — the FuzzingSequence and other sequences also call list_tools()
    directly, leaving a usable response in the log.
    """
    async for evt in reader.events_by_type("test_result"):
        data = evt.data
        if data.get("sequence") == "init_enumerate" and "tools" in data:
            return [ToolInfo(**t) for t in data["tools"]]

    async for evt in reader.events_by_type("mcp_response"):
        msg = evt.data.get("message", {}) if isinstance(evt.data, dict) else {}
        result = msg.get("result", {}) if isinstance(msg, dict) else {}
        tools_raw = result.get("tools") if isinstance(result, dict) else None
        if isinstance(tools_raw, list) and tools_raw:
            recovered: list[ToolInfo] = []
            for t in tools_raw:
                if not isinstance(t, dict) or "name" not in t:
                    continue
                try:
                    recovered.append(ToolInfo(**t))
                except Exception:
                    continue
            if recovered:
                return recovered
    return []


async def _create_interceptor(
    config: AnalysisConfig,
    sandbox: Sandbox,
    writer: Any,
    session_id: str,
) -> Any:
    """Create and start transport-specific interceptor (stdio or HTTP)."""
    if config.server.transport == "http":
        base_url = sandbox.http_base_url
        if not base_url:
            raise ValueError("HTTP transport requires server.http_port")
        interceptor = HttpInterceptor(base_url=base_url, writer=writer, session_id=session_id)
        await interceptor.start()
        await asyncio.sleep(0.2)
        return interceptor

    interceptor = StdioInterceptor(
        proc_stdin=sandbox.stdin,
        proc_stdout=sandbox.stdout,
        writer=writer,
        session_id=session_id,
    )
    await interceptor.start()
    return interceptor


async def _start_monitors(
    config: AnalysisConfig,
    session_id: str,
    writer: Any,
    sandbox: Sandbox,
    honeypot: Honeypot | None,
) -> list[Any]:
    """Start optional monitors; continue even if some are unavailable."""
    started: list[Any] = []

    if honeypot is not None:
        try:
            await honeypot.start_monitoring()
            started.append(honeypot)
        except Exception:
            log.exception("monitor.honeypot_start_failed")

    if config.scanners.r1_data_access.enabled or config.scanners.r2_code_exec.enabled:
        sysmon = SystemMonitor(
            target_pid=sandbox.pid,
            writer=writer,
            session_id=session_id,
            # In Docker mode: strace runs inside the container via docker exec.
            # container_name is set before docker run so the name is known here.
            docker_container=sandbox.container_name,
        )
        try:
            await sysmon.start()
            started.append(sysmon)
        except SysmonUnavailableError as exc:
            # strace not installed (common on macOS). Degrade gracefully without
            # printing a full traceback — this is expected in local/dev mode.
            log.warning(
                "monitor.sysmon_unavailable",
                reason=str(exc),
                impact="R1/R2 syscall-level events will not be collected.",
            )
        except Exception:
            log.exception("monitor.sysmon_start_failed")

    net_cfg = config.sandbox.network
    if net_cfg.log_all_traffic or net_cfg.mode == "allowlist":
        # On sidecar networks (``--internal``), every reachable address is
        # intra-network by construction; the host bridge and external
        # routing don't exist for the MCP container. Disable the RFC1918
        # heuristic in that case so legitimate sidecar traffic isn't
        # reported as a blocked SSRF attempt.
        block_internal = net_cfg.block_internal and not sandbox.has_sidecars
        netmon = NetworkMonitor(
            writer=writer,
            session_id=session_id,
            allowlist=net_cfg.allowlist,
            block_internal=block_internal,
            docker_container=sandbox.container_name,
        )
        try:
            await netmon.start()
            started.append(netmon)
        except Exception:
            log.exception("monitor.netmon_start_failed")

    return started


async def _stop_monitors(monitors: list[Any], honeypot: Honeypot | None) -> None:
    """Stop monitor instances best-effort (errors are logged and ignored)."""
    for mon in reversed(monitors):
        if mon is honeypot:
            continue
        stop = getattr(mon, "stop", None)
        if stop is None:
            continue
        try:
            await stop()
        except Exception:
            log.exception("monitor.stop_failed", monitor=type(mon).__name__)

    if honeypot is not None:
        try:
            await honeypot.stop_monitoring()
        except Exception:
            log.exception("monitor.honeypot_stop_failed")
