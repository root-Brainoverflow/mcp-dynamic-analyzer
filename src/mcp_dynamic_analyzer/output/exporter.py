"""Export analysis results as JSON and print a human-readable summary.

* ``findings.json`` — full ``AnalysisOutput`` for the reporting module.
* stderr summary — a rich table showing per-risk scores and verdict.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from mcp_dynamic_analyzer.models import AnalysisOutput, Finding
from mcp_dynamic_analyzer.output.scorer import ScoringResult

_RISK_LABELS: dict[str, str] = {
    "R1": "Data Access / Exfil",
    "R2": "Code Execution",
    "R3": "LLM Manipulation",
    "R4": "Behavior Drift",
    "R5": "Input Validation",
    "R6": "Stability",
}


class Exporter:
    """Write findings JSON and render terminal summary."""

    def export(
        self,
        output: AnalysisOutput,
        scores: ScoringResult,
        output_dir: Path,
    ) -> Path:
        """Write ``findings.json`` into *output_dir* and return its path."""
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / "findings.json"
        enriched = output.model_copy(update={
            "dynamic_risk_scores": scores.per_risk,
            "metadata": {
                **output.metadata,
                "overall_score": scores.overall,
                "verdict": scores.verdict,
                "by_severity": scores.by_severity,
            },
        })
        path.write_text(enriched.model_dump_json(indent=2))
        return path

    def print_summary(
        self,
        output: AnalysisOutput,
        scores: ScoringResult,
    ) -> None:
        """Print a coloured table to stderr (human-readable)."""
        console = Console(stderr=True)

        # verdict banner
        verdict_style = {
            "REJECT": "bold red",
            "CONDITIONAL": "bold yellow",
            "APPROVE": "bold green",
        }.get(scores.verdict, "bold")
        console.print(
            f"\n  Verdict: [{verdict_style}]{scores.verdict}[/{verdict_style}]"
            f"  (overall score: {scores.overall:.2f})\n",
        )

        # risk table
        table = Table(
            title=f"MCP Dynamic Analysis — {output.session_id}",
            show_lines=True,
        )
        table.add_column("Risk Type", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Findings", justify="right")

        for risk, score in scores.per_risk.items():
            count = sum(1 for f in output.findings if f.risk_type.value == risk)
            style = "red" if score >= 0.75 else "yellow" if score >= 0.4 else "green"
            label = _RISK_LABELS.get(risk, risk)
            table.add_row(
                f"{risk}: {label}",
                f"[{style}]{score:.2f}[/{style}]",
                str(count),
            )
        console.print(table)

        # severity breakdown
        if scores.by_severity:
            parts = [f"{k}: {v}" for k, v in sorted(scores.by_severity.items())]
            console.print(f"  Severity breakdown: {', '.join(parts)}")

        # metadata
        meta = output.metadata
        console.print(
            f"  Tools tested: {meta.get('tools_tested', 0)}  |  "
            f"Events: {meta.get('total_events', 0)}  |  "
            f"Findings: {len(output.findings)}\n",
        )

        # top critical/high findings
        critical = [f for f in output.findings if f.severity.value in ("CRITICAL", "HIGH")]
        if critical:
            console.print("  [bold]Top findings:[/bold]")
            for f in critical[:5]:
                icon = "🔴" if f.severity.value == "CRITICAL" else "🟠"
                console.print(f"    {icon} [{f.risk_type.value}] {f.title}")
            if len(critical) > 5:
                console.print(f"    ... and {len(critical) - 5} more")
            console.print()
