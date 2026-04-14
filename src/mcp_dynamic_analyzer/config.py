"""YAML configuration loader with Pydantic validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class ServerConfig(BaseModel):
    """Target MCP server to analyze."""

    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    transport: str = "stdio"
    http_port: int | None = None

    @field_validator("transport")
    @classmethod
    def _validate_transport(cls, v: str) -> str:
        if v not in ("stdio", "http"):
            msg = f"transport must be 'stdio' or 'http', got '{v}'"
            raise ValueError(msg)
        return v


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

class NetworkConfig(BaseModel):
    """Sandbox network policy."""

    # Default allowlist mode: Docker uses bridge (not host) so npx/npm can reach
    # the registry; set mode "none" in YAML for air-gapped runs.
    mode: str = "allowlist"
    allowlist: list[str] = Field(default_factory=list)
    block_internal: bool = True
    log_all_traffic: bool = True

    @field_validator("mode")
    @classmethod
    def _validate_mode(cls, v: str) -> str:
        if v not in ("none", "allowlist"):
            msg = f"network mode must be 'none' or 'allowlist', got '{v}'"
            raise ValueError(msg)
        return v


class SandboxConfig(BaseModel):
    """Docker sandbox resource limits and policies."""

    memory_limit: str = "512m"
    cpu_limit: float = 0.5
    timeout: int = 300
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    # "strict"    : read-only rootfs, no-new-privileges, minimal caps.
    # "permissive": give the MCP server maximum freedom *inside* the sandbox
    #               (writable rootfs, all caps, seccomp unconfined) while
    #               still preventing host escape (no --privileged, no host
    #               network, no host PID/IPC). Use when analysing public
    #               registry servers whose requirements are unknown.
    isolation: str = "strict"

    @field_validator("isolation")
    @classmethod
    def _validate_isolation(cls, v: str) -> str:
        if v not in ("strict", "permissive"):
            msg = f"isolation must be 'strict' or 'permissive', got '{v}'"
            raise ValueError(msg)
        return v


# ---------------------------------------------------------------------------
# Scanners
# ---------------------------------------------------------------------------

class ScannerToggle(BaseModel):
    """Base scanner config — at minimum an enabled flag."""

    enabled: bool = True


class R3Config(ScannerToggle):
    llm_api: str | None = None


class R4Config(ScannerToggle):
    repeat_count: int = 3
    env_variations: int = 2


class R5Config(ScannerToggle):
    fuzz_rounds: int = 10


class R6Config(ScannerToggle):
    stress_duration: int = 30


class ScannersConfig(BaseModel):
    """Per-scanner configuration."""

    r1_data_access: ScannerToggle = Field(default_factory=ScannerToggle)
    r2_code_exec: ScannerToggle = Field(default_factory=ScannerToggle)
    r3_llm_manipulation: R3Config = Field(default_factory=R3Config)
    r4_behavior_drift: R4Config = Field(default_factory=R4Config)
    r5_input_validation: R5Config = Field(default_factory=R5Config)
    r6_stability: R6Config = Field(default_factory=R6Config)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

class OutputConfig(BaseModel):
    output_dir: str = "./results"


# ---------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------

class AnalysisConfig(BaseModel):
    """Complete analysis configuration loaded from YAML."""

    server: ServerConfig = Field(default_factory=ServerConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def load_config(path: Path | str) -> AnalysisConfig:
    """Load and validate an analysis config from a YAML file.

    Args:
        path: Path to YAML configuration file.

    Returns:
        Validated AnalysisConfig instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the file is not valid YAML.
        pydantic.ValidationError: If the config fails validation.
    """
    path = Path(path)
    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    return AnalysisConfig.model_validate(raw)


def load_config_from_dict(raw: dict[str, Any]) -> AnalysisConfig:
    """Validate an analysis config from a raw dictionary (e.g. from input interface JSON)."""
    return AnalysisConfig.model_validate(raw)
