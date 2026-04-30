"""Tests for mcp_dynamic_analyzer.correlation.event_store."""

import pytest

from mcp_dynamic_analyzer.correlation.event_store import EventStore
from mcp_dynamic_analyzer.models import Event

from tests.conftest import make_event


@pytest.fixture()
async def populated_store(event_store: EventStore) -> EventStore:
    """Store with 5 events from mixed sources."""
    async with event_store.writer as w:
        await w.write(make_event("protocol", "mcp_request", direction="c2s", method="initialize"))
        await w.write(make_event("protocol", "mcp_response", direction="s2c", ts_offset_sec=0.1))
        await w.write(make_event("syscall", "file_open", ts_offset_sec=0.2, path="/etc/passwd"))
        await w.write(make_event("test", "test_input", ts_offset_sec=0.3, payload="x"))
        await w.write(make_event("network", "outbound_connection", ts_offset_sec=0.4, destination="1.2.3.4"))
    return event_store


class TestEventWriter:
    async def test_write_creates_file(self, event_store: EventStore) -> None:
        async with event_store.writer as w:
            await w.write(make_event())
        assert event_store.events_path.exists()

    async def test_write_not_open_raises(self, event_store: EventStore) -> None:
        w = event_store.writer
        with pytest.raises(RuntimeError, match="not open"):
            await w.write(make_event())

    async def test_write_escapes_lone_surrogates(self, event_store: EventStore) -> None:
        event = make_event(payload="\ud800")
        async with event_store.writer as w:
            await w.write(event)

        raw = event_store.events_path.read_text(encoding="utf-8")
        assert "\\ud800" in raw


class TestEventReader:
    async def test_count(self, populated_store: EventStore) -> None:
        assert await populated_store.reader.count() == 5

    async def test_all_events(self, populated_store: EventStore) -> None:
        events = [e async for e in populated_store.reader.all_events()]
        assert len(events) == 5

    async def test_by_source(self, populated_store: EventStore) -> None:
        proto = [e async for e in populated_store.reader.events_by_source("protocol")]
        assert len(proto) == 2

    async def test_by_type(self, populated_store: EventStore) -> None:
        opens = [e async for e in populated_store.reader.events_by_type("file_open")]
        assert len(opens) == 1
        assert opens[0].data["path"] == "/etc/passwd"

    async def test_find_by_id(self, populated_store: EventStore) -> None:
        events = [e async for e in populated_store.reader.all_events()]
        found = await populated_store.reader.find_by_id(events[0].event_id)
        assert found is not None
        assert found.event_id == events[0].event_id

    async def test_find_by_id_missing(self, populated_store: EventStore) -> None:
        assert await populated_store.reader.find_by_id("evt-nonexistent") is None

    async def test_empty_store(self, event_store: EventStore) -> None:
        assert await event_store.reader.count() == 0

    async def test_by_variation(self, event_store: EventStore) -> None:
        async with event_store.writer as w:
            await w.write(make_event(variation_tag="base"))
            await w.write(make_event(variation_tag="env_0"))
            await w.write(make_event(variation_tag="env_0"))
        env0 = [e async for e in event_store.reader.events_by_variation("env_0")]
        assert len(env0) == 2
