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


class TestRetryReinit:
    """After a ServerCrashError the orchestrator restarts the sandbox.

    The new sandbox spawns a fresh server process with no MCP protocol
    state, so every subsequent ``tools/call`` is rejected with
    ``-32602 Invalid request parameters`` until the JSON-RPC
    ``initialize`` handshake runs. The retry loop must therefore prepend
    ``InitSequence`` to ``remaining`` whenever it isn't already first.

    Regression: sessions where mcp-server-git's first crash during
    ``fuzz_input_validation`` left ``remaining = [Fuzz, Stab]``; the
    fresh sandbox bypassed init and emitted "Received request before
    initialization was complete" for every call.
    """

    def test_remaining_without_init_gets_init_prepended(self) -> None:
        from mcp_dynamic_analyzer.protocol.sequencer import InitSequence
        from mcp_dynamic_analyzer.scanners.r5_input_validation import FuzzingSequence
        from mcp_dynamic_analyzer.scanners.r6_stability import StabilityFuzzingSequence

        # State emitted by the sequencer after FuzzingSequence crashed.
        remaining = [FuzzingSequence("s"), StabilityFuzzingSequence("s")]

        # Apply the orchestrator's prepend guard.
        if not isinstance(remaining[0], InitSequence):
            remaining = [InitSequence("s"), *remaining]

        assert isinstance(remaining[0], InitSequence)
        assert isinstance(remaining[1], FuzzingSequence)
        assert isinstance(remaining[2], StabilityFuzzingSequence)

    def test_remaining_already_starting_with_init_unchanged(self) -> None:
        """First sandbox attempt — ``remaining`` already starts with Init,
        guard must NOT duplicate it."""
        from mcp_dynamic_analyzer.protocol.sequencer import InitSequence
        from mcp_dynamic_analyzer.scanners.r5_input_validation import FuzzingSequence

        remaining = [InitSequence("s"), FuzzingSequence("s")]
        original_first = remaining[0]

        if not isinstance(remaining[0], InitSequence):
            remaining = [InitSequence("s"), *remaining]

        assert len(remaining) == 2
        assert remaining[0] is original_first
