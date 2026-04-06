"""Shared Pydantic models used across collection and analysis phases."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RiskType(str, Enum):
    """6 unified risk types for MCP server security analysis."""

    R1 = "R1"  # Unauthorized Data Access / Exfiltration
    R2 = "R2"  # Unauthorized Code / Command Execution
    R3 = "R3"  # LLM Behavior Manipulation
    R4 = "R4"  # Behavioral Inconsistency / Deception
    R5 = "R5"  # Input Handling Vulnerabilities
    R6 = "R6"  # Service Stability Threats


class Severity(str, Enum):
    """Finding severity levels, highest to lowest."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ---------------------------------------------------------------------------
# MCP metadata
# ---------------------------------------------------------------------------

class ToolInfo(BaseModel):
    """Metadata for a single MCP tool exposed by the target server."""

    name: str
    description: str | None = None
    input_schema: dict | None = None
    annotations: dict | None = None


# ---------------------------------------------------------------------------
# Event (unit record written by EventWriter, read by EventReader)
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _evt_id() -> str:
    return f"evt-{uuid4()}"


class Event(BaseModel):
    """Single event recorded in the JSONL event store."""

    event_id: str = Field(default_factory=_evt_id)
    session_id: str
    ts: datetime = Field(default_factory=_utcnow)
    source: str
    type: str
    direction: str | None = None
    variation_tag: str | None = None
    data: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Finding (produced by scanners during analysis phase)
# ---------------------------------------------------------------------------

def _fnd_id() -> str:
    return f"fnd-{uuid4()}"


class Finding(BaseModel):
    """A security risk discovered by a scanner."""

    finding_id: str = Field(default_factory=_fnd_id)
    risk_type: RiskType
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    title: str
    description: str
    related_events: list[str] = Field(default_factory=list)
    tool_name: str | None = None
    reproduction: str
    detected_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Analysis context (injected into scanners)
# ---------------------------------------------------------------------------

class AnalysisContext(BaseModel):
    """Read-only context injected into every scanner's ``analyze`` method."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str
    event_reader: object  # correlation.event_store.EventReader (avoids circular import)
    tools: list[ToolInfo]
    static_context: dict | None = None
    config: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Analysis output (final export schema)
# ---------------------------------------------------------------------------

class AnalysisOutput(BaseModel):
    """Top-level output handed to the reporting module."""

    session_id: str
    server: dict
    findings: list[Finding]
    event_log_path: str
    dynamic_risk_scores: dict[str, float]
    metadata: dict


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ServerCrashError(Exception):
    """Raised when the sequencer detects that the MCP server process has terminated."""
