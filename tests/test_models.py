"""Tests for mcp_dynamic_analyzer.models."""

from mcp_dynamic_analyzer.models import (
    AnalysisOutput,
    Event,
    Finding,
    RiskType,
    Severity,
    ToolInfo,
)


class TestEvent:
    def test_auto_id(self) -> None:
        e = Event(session_id="s1", source="test", type="test_input")
        assert e.event_id.startswith("evt-")

    def test_utc_timestamp(self) -> None:
        e = Event(session_id="s1", source="test", type="test_input")
        assert e.ts.tzinfo is not None

    def test_data_default_empty(self) -> None:
        e = Event(session_id="s1", source="test", type="test_input")
        assert e.data == {}

    def test_serialisation_roundtrip(self) -> None:
        e = Event(session_id="s1", source="protocol", type="mcp_request", data={"method": "initialize"})
        raw = e.model_dump_json()
        restored = Event.model_validate_json(raw)
        assert restored.event_id == e.event_id
        assert restored.data["method"] == "initialize"


class TestFinding:
    def test_auto_id(self) -> None:
        f = self._make()
        assert f.finding_id.startswith("fnd-")

    def test_confidence_bounds(self) -> None:
        import pytest
        with pytest.raises(Exception):
            self._make(confidence=1.5)

    def test_severity_enum(self) -> None:
        f = self._make()
        assert f.severity == Severity.HIGH
        assert f.severity.value == "HIGH"

    def _make(self, **overrides) -> Finding:
        defaults = dict(
            risk_type=RiskType.R1,
            severity=Severity.HIGH,
            confidence=0.9,
            title="test",
            description="test desc",
            reproduction="steps",
        )
        defaults.update(overrides)
        return Finding(**defaults)


class TestToolInfo:
    def test_minimal(self) -> None:
        t = ToolInfo(name="foo")
        assert t.description is None
        assert t.input_schema is None

    def test_with_schema(self) -> None:
        t = ToolInfo(name="bar", input_schema={"properties": {"x": {"type": "string"}}})
        assert "x" in t.input_schema["properties"]


class TestAnalysisOutput:
    def test_serialise(self) -> None:
        o = AnalysisOutput(
            session_id="ses-1",
            server={"name": "test"},
            findings=[],
            event_log_path="./events.jsonl",
            dynamic_risk_scores={"R1": 0.0},
            metadata={"tools_tested": 0},
        )
        raw = o.model_dump_json()
        assert "ses-1" in raw
