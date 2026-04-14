"""CLI entry point: ``mcp-dynamic-analyzer scan`` / ``analyze``."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
import structlog
from rich.console import Console
from rich.table import Table

from mcp_dynamic_analyzer.config import AnalysisConfig, load_config
from mcp_dynamic_analyzer.discovery import (
    DiscoveredServer,
    discover_servers,
    select_server,
)
from mcp_dynamic_analyzer.models import AnalysisOutput

log = structlog.get_logger()
console = Console(stderr=True)


@click.group()
def main() -> None:
    """MCP Dynamic Analyzer — dynamic security analysis for MCP servers."""
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
    )


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@main.command()
def discover() -> None:
    """List MCP servers already configured on this machine.

    Scans Claude Desktop, Claude Code, Cursor, and VSCode config files.
    Use the server name shown here with ``scan --target <name>``.
    """
    servers = discover_servers()
    if not servers:
        console.print(
            "[yellow]No MCP servers found in any known config location.[/yellow]\n"
            "Checked: claude-desktop, claude-code, cursor, vscode."
        )
        return
    _print_discovered(servers)


@main.command()
@click.option(
    "--target",
    required=True,
    help="Name of a discovered MCP server (see `discover`)",
)
@click.option(
    "--source",
    default=None,
    help="Restrict selection to one source (claude-desktop|claude-code|cursor|vscode)",
)
@click.option("--config", "config_path", type=click.Path(exists=True), default=None)
@click.option("--quick", is_flag=True, help="Quick scan (R1 + R3 + R5 only)")
@click.option("--format", "fmt", type=click.Choice(["json", "summary"]), default="summary")
@click.option("--no-docker", is_flag=True, help="Run server locally without Docker")
def scan(
    target: str,
    source: str | None,
    config_path: str | None,
    quick: bool,
    fmt: str,
    no_docker: bool,
) -> None:
    """Run a full dynamic analysis on a discovered MCP server."""
    if config_path:
        cfg = load_config(config_path)
    elif quick:
        cfg = load_config(Path(__file__).parent.parent.parent / "configs" / "quick.yaml")
    else:
        cfg = AnalysisConfig()

    servers = discover_servers()
    if not servers:
        click.echo(
            "Error: no MCP servers found. Run `mcp-dynamic-analyzer discover` "
            "to see what's available, or configure one in Claude Desktop/Code first.",
            err=True,
        )
        sys.exit(1)
    try:
        picked = select_server(servers, target, source)
    except ValueError as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    # Pydantic models are immutable-by-convention here; replace the whole
    # server block with the discovered config so all fields transfer cleanly.
    cfg.server = picked.server
    console.print(
        f"[green]Target:[/green] {picked.name}  "
        f"[dim]({picked.source} — {picked.source_path})[/dim]"
    )

    from mcp_dynamic_analyzer.orchestrator import run_analysis, build_default_scanners

    output = asyncio.run(
        run_analysis(cfg, use_docker=not no_docker, scanners=build_default_scanners(cfg)),
    )

    if fmt == "json":
        click.echo(output.model_dump_json(indent=2))
    else:
        _print_summary(output)


def _print_discovered(servers: list[DiscoveredServer]) -> None:
    """Render discovered servers as a rich table."""
    table = Table(title="Discovered MCP Servers", show_lines=False)
    table.add_column("#", style="dim", justify="right")
    table.add_column("name", style="bold")
    table.add_column("source")
    table.add_column("command", overflow="fold")
    for i, s in enumerate(servers, 1):
        preview = s.server.command
        if s.server.args:
            preview += " " + " ".join(s.server.args[:3])
            if len(s.server.args) > 3:
                preview += " ..."
        table.add_row(str(i), s.name, s.source, preview)
    console.print(table)
    console.print(
        "\n[dim]Run:[/dim] mcp-dynamic-analyzer scan --target <name>"
    )


# ---------------------------------------------------------------------------
# analyze (re-analysis)
# ---------------------------------------------------------------------------

@main.command()
@click.option("--session", required=True, type=click.Path(exists=True), help="Session directory")
@click.option("--config", "config_path", type=click.Path(exists=True), default=None)
def analyze(session: str, config_path: str | None) -> None:
    """Re-analyze a previously collected session with new scanners/config."""
    session_dir = Path(session)
    events_file = session_dir / "events.jsonl"
    if not events_file.exists():
        click.echo(f"Error: {events_file} not found", err=True)
        sys.exit(1)

    cfg = load_config(config_path) if config_path else AnalysisConfig()

    from mcp_dynamic_analyzer.correlation.event_store import EventStore
    from mcp_dynamic_analyzer.models import AnalysisContext
    from mcp_dynamic_analyzer.orchestrator import build_default_scanners
    from mcp_dynamic_analyzer.output.scorer import Scorer
    from mcp_dynamic_analyzer.output.exporter import Exporter
    from mcp_dynamic_analyzer.output.reporter import Reporter

    store = EventStore(session_dir)
    reader = store.reader

    async def _run() -> None:
        count = await reader.count()
        console.print(f"Re-analyzing session {session_dir.name} ({count} events)")

        ctx = AnalysisContext(
            session_id=session_dir.name,
            event_reader=reader,
            tools=[],
            config=cfg.model_dump(),
        )
        findings = []
        for scanner in build_default_scanners(cfg):
            scanner_cfg = cfg.model_dump().get("scanners", {}).get(scanner.name, {})
            if not scanner_cfg.get("enabled", True):
                continue
            try:
                result = await scanner.analyze(ctx)
                findings.extend(result)
                console.print(f"  {scanner.name}: {len(result)} findings")
            except Exception as exc:
                console.print(f"  [red]{scanner.name} error: {exc}[/red]")

        scores = Scorer().score(findings)
        exporter = Exporter()
        exporter.print_summary(
            type("_Out", (), {
                "session_id": session_dir.name,
                "findings": findings,
                "metadata": {"tools_tested": 0, "total_events": count},
                "event_log_path": str(store.events_path),
            })(),
            scores,
        )
        Reporter(session_dir).write(
            type("_Out", (), {
                "session_id": session_dir.name,
                "server": {},
                "findings": findings,
                "metadata": {"tools_tested": 0, "total_events": count, "duration_sec": 0},
                "event_log_path": str(store.events_path),
            })(),
            scores,
        )

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# Summary display
# ---------------------------------------------------------------------------

def _print_summary(output: AnalysisOutput) -> None:
    """Print a human-readable summary to stderr using rich."""
    from rich.panel import Panel

    tools_tested = output.metadata.get("tools_tested", 0)
    total_events = output.metadata.get("total_events", 0)

    # ── Pre-scan warnings ────────────────────────────────────────────────────
    if tools_tested == 0:
        console.print(
            Panel(
                "[bold yellow]No tools were discovered on the target server.[/bold yellow]\n\n"
                "Possible causes:\n"
                "  • The backend service required by the server is not running\n"
                "    (e.g. Ghidra HTTP API, database, external API endpoint).\n"
                "  • The server failed to start up correctly — check stderr output above.\n"
                "  • The server intentionally exposes no tools.\n\n"
                "Tip: re-run with [bold]--server-arg[/bold] to pass the backend URL, or\n"
                "     ensure the required service is reachable before scanning.",
                title="[yellow]⚠  0 Tools Discovered[/yellow]",
                border_style="yellow",
            )
        )
    elif total_events < 10:
        console.print(
            Panel(
                f"[yellow]Only {total_events} events were recorded.[/yellow]\n"
                "The server may have exited early or failed to respond to test sequences.\n"
                "Check the structured log output above for sandbox.server_stderr lines.",
                title="[yellow]⚠  Low Event Count[/yellow]",
                border_style="yellow",
            )
        )

    table = Table(title=f"MCP Dynamic Analysis — {output.session_id}", show_lines=True)
    table.add_column("Risk", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Findings", justify="right")

    risk_names = {
        "R1": "Data Access",
        "R2": "Code Exec",
        "R3": "LLM Manipulation",
        "R4": "Behavior Drift",
        "R5": "Input Validation",
        "R6": "Stability",
    }

    for risk, score in output.dynamic_risk_scores.items():
        count = sum(1 for f in output.findings if f.risk_type.value == risk)
        style = "red" if score >= 0.75 else "yellow" if score >= 0.5 else "green"
        table.add_row(
            f"{risk}: {risk_names.get(risk, '')}",
            f"[{style}]{score:.2f}[/{style}]",
            str(count),
        )

    console.print(table)
    meta = output.metadata
    console.print(
        f"\n  Tools tested: {meta.get('tools_tested', 0)}  |  "
        f"Events: {meta.get('total_events', 0)}  |  "
        f"Findings: {len(output.findings)}",
    )
    console.print(f"  Results: {output.event_log_path}\n")
