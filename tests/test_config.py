"""Tests for mcp_dynamic_analyzer.config."""

from pathlib import Path

import pytest

from mcp_dynamic_analyzer.config import AnalysisConfig, load_config, load_config_from_dict

_CONFIGS_DIR = Path(__file__).parent.parent / "configs"


class TestLoadConfig:
    def test_default_yaml(self) -> None:
        cfg = load_config(_CONFIGS_DIR / "default.yaml")
        assert cfg.server.transport == "stdio"
        assert cfg.sandbox.timeout == 300
        assert cfg.sandbox.network.mode == "allowlist"
        assert cfg.scanners.r3_llm_manipulation.llm_api is None
        assert cfg.scanners.r4_behavior_drift.repeat_count == 3

    def test_quick_yaml(self) -> None:
        cfg = load_config(_CONFIGS_DIR / "quick.yaml")
        assert cfg.sandbox.timeout == 60
        assert cfg.scanners.r2_code_exec.enabled is False
        assert cfg.scanners.r5_input_validation.fuzz_rounds == 3

    def test_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path.yaml")


class TestLoadFromDict:
    def test_minimal(self) -> None:
        cfg = load_config_from_dict({"server": {"command": "echo"}})
        assert cfg.server.command == "echo"
        assert cfg.sandbox.memory_limit == "512m"  # default

    def test_invalid_transport(self) -> None:
        with pytest.raises(Exception):
            load_config_from_dict({"server": {"transport": "grpc"}})

    def test_invalid_network_mode(self) -> None:
        with pytest.raises(Exception):
            load_config_from_dict({"sandbox": {"network": {"mode": "open"}}})


class TestDefaults:
    def test_all_defaults(self) -> None:
        cfg = AnalysisConfig()
        assert cfg.server.command == ""
        assert cfg.sandbox.network.mode == "allowlist"
        assert cfg.sandbox.cpu_limit == 0.5
        assert cfg.scanners.r1_data_access.enabled is True
        assert cfg.output.output_dir == "./results"
