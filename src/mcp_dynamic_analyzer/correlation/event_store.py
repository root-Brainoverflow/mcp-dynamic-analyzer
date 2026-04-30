"""JSONL-based event store with separated write (collection) and read (analysis) paths."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator

import aiofiles
import aiofiles.os

from mcp_dynamic_analyzer.models import Event


# ---------------------------------------------------------------------------
# EventWriter — used during the collection phase (append-only)
# ---------------------------------------------------------------------------

class EventWriter:
    """Append-only writer that serialises ``Event`` objects to a JSONL file.

    Thread/coroutine safety: an ``asyncio.Lock`` serialises all ``write``
    calls so that concurrent coroutines (interceptor reader task, sequencer,
    monitor tasks) cannot interleave partial writes.  Without the lock,
    Python's ``io.TextIOWrapper`` — used internally by aiofiles — is *not*
    safe for concurrent writes from multiple thread-pool workers, which
    manifests as corrupted (split) JSONL lines when large events and small
    events are written simultaneously.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._handle: aiofiles.threadpool.text.AsyncTextIOWrapper | None = None
        self._lock: asyncio.Lock | None = None

    async def open(self) -> None:
        """Open the backing JSONL file for writing."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = await aiofiles.open(self._path, mode="a", encoding="utf-8")
        # Lock must be created inside a running event loop.
        self._lock = asyncio.Lock()

    async def write(self, event: Event) -> None:
        """Append a single event.  The file must be opened first."""
        if self._handle is None:
            msg = "EventWriter is not open — call open() first"
            raise RuntimeError(msg)
        assert self._lock is not None
        # ``model_dump_json()`` fails on lone-surrogate fuzz payloads because it
        # emits UTF-8 directly. Dump through stdlib json with ensure_ascii=True
        # so invalid Unicode code points stay escaped in the JSONL file.
        line = json.dumps(event.model_dump(mode="json"), ensure_ascii=True) + "\n"
        # Serialize writes: prevents interleaved bytes when concurrent coroutines
        # (interceptor, sequencer, monitors) write large and small events at the
        # same time through aiofiles' thread-pool executor.
        async with self._lock:
            await self._handle.write(line)

    async def flush(self) -> None:
        if self._handle is not None:
            await self._handle.flush()

    async def close(self) -> None:
        if self._handle is not None:
            await self._handle.close()
            self._handle = None

    # async context-manager support
    async def __aenter__(self) -> EventWriter:
        await self.open()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()


# ---------------------------------------------------------------------------
# EventReader — used during the analysis phase (read-only)
# ---------------------------------------------------------------------------

class EventReader:
    """Read-only access to a previously collected JSONL event file.

    Every query method returns an ``AsyncIterator`` that streams events
    one-by-one so that memory usage stays constant regardless of file size.
    """

    def __init__(self, path: Path) -> None:
        self._path = path

    # -- full scan helpers ---------------------------------------------------

    async def all_events(self) -> AsyncIterator[Event]:
        """Yield every event in chronological order."""
        async for evt in self._iter_events():
            yield evt

    async def events_by_source(self, source: str) -> AsyncIterator[Event]:
        async for evt in self._iter_events():
            if evt.source == source:
                yield evt

    async def events_by_type(self, type_: str) -> AsyncIterator[Event]:
        async for evt in self._iter_events():
            if evt.type == type_:
                yield evt

    async def events_in_window(
        self,
        start: datetime,
        end: datetime,
    ) -> AsyncIterator[Event]:
        async for evt in self._iter_events():
            if start <= evt.ts <= end:
                yield evt

    async def events_by_variation(self, tag: str) -> AsyncIterator[Event]:
        async for evt in self._iter_events():
            if evt.variation_tag == tag:
                yield evt

    async def find_by_id(self, event_id: str) -> Event | None:
        async for evt in self._iter_events():
            if evt.event_id == event_id:
                return evt
        return None

    # -- compound queries ----------------------------------------------------

    async def protocol_events(self) -> AsyncIterator[Event]:
        """Shortcut for ``events_by_source("protocol")``."""
        async for evt in self.events_by_source("protocol"):
            yield evt

    async def syscall_events(self) -> AsyncIterator[Event]:
        async for evt in self.events_by_source("syscall"):
            yield evt

    async def test_events(self) -> AsyncIterator[Event]:
        async for evt in self.events_by_source("test"):
            yield evt

    # -- internal ------------------------------------------------------------

    async def _iter_events(self) -> AsyncIterator[Event]:
        """Low-level line-by-line JSONL parser.

        Malformed lines (caused by concurrent-write corruption in previous
        runs, or truncated writes) are silently skipped so that the analysis
        phase can still process the healthy portion of the event log.
        """
        if not self._path.exists():
            return
        skipped = 0
        async with aiofiles.open(self._path, mode="r", encoding="utf-8", errors="replace") as f:
            async for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    raw = json.loads(stripped)
                    yield Event.model_validate(raw)
                except (json.JSONDecodeError, Exception):
                    skipped += 1
        if skipped:
            import structlog
            structlog.get_logger().warning(
                "event_store.skipped_malformed_lines",
                count=skipped,
                path=str(self._path),
                hint=(
                    "Malformed JSONL lines indicate concurrent-write corruption "
                    "from a previous run. The EventWriter now uses asyncio.Lock "
                    "to prevent this in future sessions."
                ),
            )

    async def count(self) -> int:
        """Return total number of events (full scan)."""
        n = 0
        async for _ in self._iter_events():
            n += 1
        return n


# ---------------------------------------------------------------------------
# EventStore — factory that vends a writer and a reader for the same session
# ---------------------------------------------------------------------------

EVENTS_FILENAME = "events.jsonl"


class EventStore:
    """Owns the session directory and provides ``writer`` / ``reader`` access.

    Usage::

        store = EventStore(Path("./results/ses-abc"))
        async with store.writer as w:
            await w.write(event)

        reader = store.reader
        async for evt in reader.all_events():
            ...
    """

    def __init__(self, base_dir: Path) -> None:
        self._base_dir = base_dir
        self._events_path = base_dir / EVENTS_FILENAME

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    @property
    def events_path(self) -> Path:
        return self._events_path

    @property
    def writer(self) -> EventWriter:
        """Create a new ``EventWriter`` (caller must ``open`` or use as context manager)."""
        return EventWriter(self._events_path)

    @property
    def reader(self) -> EventReader:
        """Create an ``EventReader`` over the stored JSONL file."""
        return EventReader(self._events_path)
