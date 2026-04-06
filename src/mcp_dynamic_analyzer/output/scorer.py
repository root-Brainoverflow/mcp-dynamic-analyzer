"""Risk scoring: findings → per-risk-type normalised scores.

Each risk type (R1–R6) receives a score in [0.0, 1.0] computed from the
severity, confidence, and count of its findings.  The overall score is
the max across all risk types.

Scoring formula per risk type:
    raw = Σ (severity_weight × confidence) for each finding
    score = min(raw / normaliser, 1.0)
"""

from __future__ import annotations

from mcp_dynamic_analyzer.models import Finding, RiskType, Severity

_SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.05,
}

_NORMALISER = 2.0  # raw score of 2.0 → normalised 1.0


class Scorer:
    """Compute per-risk-type and overall scores from a findings list."""

    def score(self, findings: list[Finding]) -> ScoringResult:
        per_risk: dict[str, float] = {rt.value: 0.0 for rt in RiskType}

        for f in findings:
            weight = _SEVERITY_WEIGHT.get(f.severity, 0.0)
            raw = weight * f.confidence
            per_risk[f.risk_type.value] += raw

        normalised = {k: min(v / _NORMALISER, 1.0) for k, v in per_risk.items()}
        overall = max(normalised.values()) if normalised else 0.0

        verdict: str
        if overall >= 0.75:
            verdict = "REJECT"
        elif overall >= 0.4:
            verdict = "CONDITIONAL"
        else:
            verdict = "APPROVE"

        return ScoringResult(
            per_risk=normalised,
            overall=overall,
            verdict=verdict,
            total_findings=len(findings),
            by_severity=_count_by_severity(findings),
        )


class ScoringResult:
    """Structured scoring output."""

    __slots__ = ("per_risk", "overall", "verdict", "total_findings", "by_severity")

    def __init__(
        self,
        per_risk: dict[str, float],
        overall: float,
        verdict: str,
        total_findings: int,
        by_severity: dict[str, int],
    ) -> None:
        self.per_risk = per_risk
        self.overall = overall
        self.verdict = verdict
        self.total_findings = total_findings
        self.by_severity = by_severity

    def to_dict(self) -> dict:
        return {
            "per_risk": self.per_risk,
            "overall": self.overall,
            "verdict": self.verdict,
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
        }


def _count_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts
