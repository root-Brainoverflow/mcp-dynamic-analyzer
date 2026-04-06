"""Shared pytest fixtures for MCP Dynamic Analyzer tests."""

from __future__ import annotations

import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mcp_dynamic_analyzer.correlation.event_store import EventStore
from mcp_dynamic_analyzer.models import AnalysisContext, Event, ToolInfo


@pytest.fixture()
def tmp_dir(tmp_path: Path) -> Path:
    """Return a fresh temporary directory (cleaned up by pytest)."""
    return tmp_path


@pytest.fixture()
def event_store(tmp_dir: Path) -> EventStore:
    """Return an EventStore backed by a temp directory."""
    return EventStore(tmp_dir / "test-session")


@pytest.fixture()
def sample_tools() -> list[ToolInfo]:
    """A small set of representative MCP tools."""
    return [
        ToolInfo(
            name="read_file",
            description="Read contents of a file from disk",
            input_schema={"properties": {"path": {"type": "string"}}},
        ),
        ToolInfo(
            name="write_file",
            description="Write contents to a file",
            input_schema={
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
            },
        ),
        ToolInfo(
            name="execute_command",
            description="Run a shell command and return output",
            input_schema={"properties": {"command": {"type": "string"}}},
        ),
        ToolInfo(
            name="search",
            description="Search for files by name",
            input_schema={"properties": {"query": {"type": "string"}}},
        ),
    ]


def make_event(
    source: str = "test",
    type_: str = "test_input",
    *,
    session_id: str = "ses-test",
    direction: str | None = None,
    variation_tag: str | None = None,
    ts_offset_sec: float = 0.0,
    **data_kwargs: object,
) -> Event:
    """Helper to quickly build an Event with sane defaults."""
    return Event(
        session_id=session_id,
        ts=datetime.now(timezone.utc) + timedelta(seconds=ts_offset_sec),
        source=source,
        type=type_,
        direction=direction,
        variation_tag=variation_tag,
        data=dict(data_kwargs),
    )


@pytest.fixture()
def analysis_context(event_store: EventStore, sample_tools: list[ToolInfo]) -> AnalysisContext:
    """A ready-to-use AnalysisContext for scanner tests."""
    return AnalysisContext(
        session_id="ses-test",
        event_reader=event_store.reader,
        tools=sample_tools,
        config={},
    )
