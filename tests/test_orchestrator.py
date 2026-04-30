"""Tests for default sequence selection in the orchestrator."""

from __future__ import annotations

from mcp_dynamic_analyzer.config import AnalysisConfig
from mcp_dynamic_analyzer.orchestrator import build_default_sequences
from mcp_dynamic_analyzer.scanners.r5_input_validation import FuzzingSequence
from mcp_dynamic_analyzer.scanners.r6_stability import StabilityFuzzingSequence


class TestBuildDefaultSequences:
    def test_default_sequences_include_r5_and_r6(self) -> None:
        cfg = AnalysisConfig()
        sequences = build_default_sequences(cfg, "ses-test")
        assert any(isinstance(seq, FuzzingSequence) for seq in sequences)
        assert any(isinstance(seq, StabilityFuzzingSequence) for seq in sequences)

    def test_default_sequences_respect_disabled_scanners(self) -> None:
        cfg = AnalysisConfig.model_validate(
            {
                "scanners": {
                    "r5_input_validation": {"enabled": False},
                    "r6_stability": {"enabled": False},
                }
            }
        )
        sequences = build_default_sequences(cfg, "ses-test")
        assert not any(isinstance(seq, FuzzingSequence) for seq in sequences)
        assert not any(isinstance(seq, StabilityFuzzingSequence) for seq in sequences)
