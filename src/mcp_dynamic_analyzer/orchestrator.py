"""Top-level orchestration: collection → analysis → export."""

from __future__ import annotations

import asyncio
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
from mcp_dynamic_analyzer.models import AnalysisContext, AnalysisOutput, Event, Finding, ToolInfo
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
from mcp_dynamic_analyzer.scanners.r6_stability import R6StabilityScanner

log = structlog.get_logger()


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

    log.info("orchestrator.collection.start", session_id=session_id)

    sequences: list[TestSequence] = [InitSequence(session_id)]
    if config.scanners.r5_input_validation.enabled:
        sequences.append(
            FuzzingSequence(
                session_id=session_id,
                fuzz_rounds=config.scanners.r5_input_validation.fuzz_rounds,
            ),
        )
    if extra_sequences:
        sequences.extend(extra_sequences)

    try:
        tools = await _collect(
            config=config,
            session_id=session_id,
            event_store=event_store,
            sequences=sequences,
            use_docker=use_docker,
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
    ctx = AnalysisContext(
        session_id=session_id,
        event_reader=reader,
        tools=tools,
        static_context=static_context,
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

    output = AnalysisOutput(
        session_id=session_id,
        server={"name": config.server.command, "version": "", "args": config.server.args},
        findings=correlated,
        event_log_path=str(event_store.events_path),
        dynamic_risk_scores=scoring_result.per_risk,
        metadata={
            "duration_sec": 0,
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


async def _collect(
    *,
    config: AnalysisConfig,
    session_id: str,
    event_store: EventStore,
    sequences: list[TestSequence],
    use_docker: bool,
    env_override: dict[str, str] | None = None,
    variation_tag: str | None = None,
) -> list[ToolInfo]:
    """Run collection sequences inside a sandbox, return discovered tools."""
    tools: list[ToolInfo] = []
    monitors: list[Any] = []
    honeypot: Honeypot | None = None

    async with event_store.writer as base_writer:
        writer = _TaggedWriter(base_writer, variation_tag)

        honeypot_dir: str | None = None
        if config.scanners.r1_data_access.enabled:
            honeypot = Honeypot(writer, session_id)
            honeypot_dir = str(honeypot.create())

        async with Sandbox(
            config.server,
            config.sandbox,
            env_override=env_override,
            honeypot_dir=honeypot_dir,
            use_docker=use_docker,
        ) as sandbox:
            interceptor = await _create_interceptor(config, sandbox, writer, session_id)
            client = McpClient(interceptor)
            sequencer = Sequencer(session_id, client, writer, sequences)

            try:
                monitors = await _start_monitors(config, session_id, writer, sandbox, honeypot)

                await asyncio.wait_for(
                    sequencer.run_all(),
                    timeout=config.sandbox.timeout,
                )
                # Prefer tools already discovered during InitSequence (stored in
                # the event log) rather than making a second list_tools call after
                # sequences complete — by that point the server may have shut down.
                tools = await _read_tools_from_events(event_store.reader)
                if not tools:
                    # Fallback: server still running, try one more list_tools call.
                    try:
                        tools = await client.list_tools()
                    except Exception as exc:
                        log.warning(
                            "orchestrator.list_tools_after_sequences_failed",
                            error=str(exc),
                        )

            except asyncio.TimeoutError:
                log.warning(
                    "orchestrator.global_timeout",
                    timeout=config.sandbox.timeout,
                    hint="Increase sandbox.timeout in config if the server needs more time.",
                )
            except ConnectionError as exc:
                # The server's stdout stream closed unexpectedly — the process
                # likely crashed or the backend killed it.
                log.error(
                    "orchestrator.server_stream_closed",
                    error=str(exc),
                    is_running=sandbox.is_running,
                    hint=(
                        "Server stdout EOF — the process may have crashed. "
                        "Check sandbox.server_stderr log lines above for details."
                    ),
                )
            finally:
                # Log the server's exit code if it already terminated.
                if not sandbox.is_running:
                    proc = sandbox._proc  # noqa: SLF001
                    rc = proc.returncode if proc else None
                    log.warning("orchestrator.server_exited_early", rc=rc)
                await _stop_monitors(monitors, honeypot)
                await interceptor.close()

        if honeypot is not None:
            honeypot.cleanup()

    return tools


async def _read_tools_from_events(reader: Any) -> list[ToolInfo]:
    """Recover the tools list from the init_enumerate test_result event.

    InitSequence writes a ``test_result`` event containing the full tools list.
    Reading it back avoids a second ``tools/list`` call after the sequences
    complete (by which time the server may have exited).
    """
    async for evt in reader.events_by_type("test_result"):
        data = evt.data
        if data.get("sequence") == "init_enumerate" and "tools" in data:
            return [ToolInfo(**t) for t in data["tools"]]
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
        netmon = NetworkMonitor(
            writer=writer,
            session_id=session_id,
            allowlist=net_cfg.allowlist,
            block_internal=net_cfg.block_internal,
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


