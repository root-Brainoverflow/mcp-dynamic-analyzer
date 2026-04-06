"""Tests for correlation engine and scorer."""

import pytest

from mcp_dynamic_analyzer.correlation.engine import CorrelationEngine
from mcp_dynamic_analyzer.correlation.event_store import EventStore
from mcp_dynamic_analyzer.models import Finding, RiskType, Severity
from mcp_dynamic_analyzer.output.scorer import Scorer

from tests.conftest import make_event


def _finding(risk: str = "R1", sev: str = "HIGH", conf: float = 0.9, events: list[str] | None = None) -> Finding:
    return Finding(
        risk_type=RiskType(risk),
        severity=Severity(sev),
        confidence=conf,
        title=f"Test {risk}",
        description="test",
        related_events=events or [],
        reproduction="test",
    )


class TestCorrelationEngine:
    async def test_enrich_adds_nearby_events(self, event_store: EventStore) -> None:
        async with event_store.writer as w:
            e1 = make_event("protocol", "mcp_request", ts_offset_sec=0)
            e2 = make_event("syscall", "file_open", ts_offset_sec=1)
            await w.write(e1)
            await w.write(e2)

        f = _finding(events=[e1.event_id])
        engine = CorrelationEngine(event_store.reader)
        result = await engine.correlate([f])
        assert len(result) == 1
        assert e2.event_id in result[0].related_events

    async def test_deduplicate(self, event_store: EventStore) -> None:
        async with event_store.writer as w:
            await w.write(make_event())

        f1 = _finding(risk="R1", events=[])
        f2 = _finding(risk="R1", events=[])  # same title + risk
        engine = CorrelationEngine(event_store.reader)
        result = await engine.correlate([f1, f2])
        assert len(result) == 1

    async def test_empty_findings(self, event_store: EventStore) -> None:
        engine = CorrelationEngine(event_store.reader)
        result = await engine.correlate([])
        assert result == []


class TestScorer:
    def test_critical_conditional(self) -> None:
        findings = [_finding("R1", "CRITICAL", 0.95)]
        result = Scorer().score(findings)
        # 1.0 × 0.95 / 2.0 = 0.475 → CONDITIONAL
        assert result.verdict == "CONDITIONAL"
        assert result.overall >= 0.4

    def test_multiple_critical_reject(self) -> None:
        findings = [_finding("R1", "CRITICAL", 0.95), _finding("R1", "CRITICAL", 0.9)]
        result = Scorer().score(findings)
        # (0.95 + 0.9) / 2.0 = 0.925 → REJECT
        assert result.verdict == "REJECT"

    def test_low_approve(self) -> None:
        findings = [_finding("R5", "LOW", 0.5)]
        result = Scorer().score(findings)
        assert result.verdict == "APPROVE"

    def test_empty(self) -> None:
        result = Scorer().score([])
        assert result.verdict == "APPROVE"
        assert result.overall == 0.0
        assert result.total_findings == 0

    def test_multi_risk(self) -> None:
        findings = [
            _finding("R1", "HIGH", 0.8),
            _finding("R3", "MEDIUM", 0.6),
            _finding("R5", "HIGH", 0.9),
        ]
        result = Scorer().score(findings)
        assert result.per_risk["R1"] > 0
        assert result.per_risk["R3"] > 0
        assert result.per_risk["R5"] > 0
        assert result.per_risk["R2"] == 0.0

    def test_by_severity(self) -> None:
        findings = [_finding(sev="CRITICAL"), _finding(sev="HIGH"), _finding(sev="HIGH")]
        result = Scorer().score(findings)
        assert result.by_severity["CRITICAL"] == 1
        assert result.by_severity["HIGH"] == 2
