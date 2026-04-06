"""Markdown report generation for MCP Dynamic Analyzer findings.

Produces a human-readable ``report.md`` alongside the machine-readable
``findings.json`` already written by :class:`~mcp_dynamic_analyzer.output.exporter.Exporter`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from mcp_dynamic_analyzer.models import AnalysisOutput, Finding, RiskType, Severity
from mcp_dynamic_analyzer.output.scorer import ScoringResult

_RISK_LABELS: dict[str, str] = {
    "R1": "Unauthorized Data Access / Exfiltration",
    "R2": "Unauthorized Code / Command Execution",
    "R3": "LLM Behavior Manipulation",
    "R4": "Behavioral Inconsistency / Deception",
    "R5": "Input Handling Vulnerabilities",
    "R6": "Service Stability Threats",
}

_SEVERITY_EMOJI: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


class Reporter:
    """Generate a Markdown analysis report from findings and scoring results.

    Args:
        output_dir: Directory where ``report.md`` is written.
    """

    def __init__(self, output_dir: Path) -> None:
        self._output_dir = Path(output_dir)

    def write(
        self,
        output: AnalysisOutput,
        scores: ScoringResult,
    ) -> Path:
        """Write ``report.md`` and return its path.

        Args:
            output: Full analysis output (session metadata + findings).
            scores: Pre-computed scoring result.

        Returns:
            Path to the written Markdown file.
        """
        self._output_dir.mkdir(parents=True, exist_ok=True)
        report_path = self._output_dir / "report.md"
        report_path.write_text(self._render(output, scores), encoding="utf-8")
        return report_path

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render(self, output: AnalysisOutput, scores: ScoringResult) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines: list[str] = []

        # ── Header ────────────────────────────────────────────────────
        lines += [
            "# MCP Dynamic Analyzer — Security Report",
            "",
            f"**Session:** `{output.session_id}`  ",
            f"**Generated:** {now}  ",
            f"**Server:** `{output.server.get('name', 'unknown')} {output.server.get('version', '')}`  ",
            f"**Event log:** `{output.event_log_path}`  ",
            "",
        ]

        # ── Verdict banner ────────────────────────────────────────────
        verdict_icon = {"REJECT": "🚫", "CONDITIONAL": "⚠️", "APPROVE": "✅"}.get(
            scores.verdict, "❓"
        )
        lines += [
            "## Verdict",
            "",
            f"> {verdict_icon} **{scores.verdict}** — overall risk score: `{scores.overall:.2f}`",
            "",
        ]

        # ── Risk score summary table ───────────────────────────────────
        lines += [
            "## Risk Score Summary",
            "",
            "| Risk Type | Description | Score | Findings |",
            "|-----------|-------------|------:|--------:|",
        ]
        for risk, score in sorted(scores.per_risk.items()):
            count = sum(1 for f in output.findings if f.risk_type.value == risk)
            bar = _score_bar(score)
            label = _RISK_LABELS.get(risk, risk)
            lines.append(f"| **{risk}** | {label} | {score:.2f} {bar} | {count} |")
        lines.append("")

        # ── Severity breakdown ────────────────────────────────────────
        if scores.by_severity:
            lines += ["## Severity Breakdown", ""]
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = scores.by_severity.get(sev, 0)
                if count:
                    icon = _SEVERITY_EMOJI.get(sev, "")
                    lines.append(f"- {icon} **{sev}**: {count}")
            lines.append("")

        # ── Metadata ─────────────────────────────────────────────────
        meta = output.metadata
        lines += [
            "## Scan Metadata",
            "",
            f"- **Tools tested:** {meta.get('tools_tested', 0)}",
            f"- **Total events recorded:** {meta.get('total_events', 0)}",
            f"- **Scan duration:** {meta.get('duration_sec', 0):.1f}s",
            f"- **Total findings:** {scores.total_findings}",
            "",
        ]

        # ── Findings ──────────────────────────────────────────────────
        if output.findings:
            lines += ["## Findings", ""]
            # Group by risk type
            by_risk: dict[str, list[Finding]] = {rt.value: [] for rt in RiskType}
            for f in output.findings:
                by_risk[f.risk_type.value].append(f)

            for risk in RiskType:
                group = by_risk.get(risk.value, [])
                if not group:
                    continue
                label = _RISK_LABELS.get(risk.value, risk.value)
                lines += [f"### {risk.value}: {label}", ""]

                for f in sorted(group, key=lambda x: _severity_order(x.severity.value)):
                    icon = _SEVERITY_EMOJI.get(f.severity.value, "")
                    lines += [
                        f"#### {icon} {f.title}",
                        "",
                        f"| Field | Value |",
                        f"|-------|-------|",
                        f"| **Finding ID** | `{f.finding_id}` |",
                        f"| **Severity** | {f.severity.value} |",
                        f"| **Confidence** | {f.confidence:.0%} |",
                        f"| **Tool** | {f.tool_name or '—'} |",
                        f"| **Detected at** | {f.detected_at.strftime('%Y-%m-%dT%H:%M:%SZ')} |",
                        "",
                        f.description,
                        "",
                    ]
                    if f.related_events:
                        events_str = ", ".join(f"`{e}`" for e in f.related_events[:5])
                        if len(f.related_events) > 5:
                            events_str += f" _(+{len(f.related_events) - 5} more)_"
                        lines += [f"**Related events:** {events_str}", ""]
                    lines += [
                        "**Reproduction:**",
                        "",
                        f"```",
                        f.reproduction,
                        f"```",
                        "",
                    ]
        else:
            lines += ["## Findings", "", "_No findings detected._", ""]

        # ── Footer ───────────────────────────────────────────────────
        lines += [
            "---",
            "",
            "_Generated by [MCP Dynamic Analyzer](https://github.com/anthropics/mcp-dynamic-analyzer)_",
        ]

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _score_bar(score: float) -> str:
    """Return a simple ASCII progress bar for the score."""
    filled = round(score * 10)
    return "█" * filled + "░" * (10 - filled)


def _severity_order(severity: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(severity, 5)
