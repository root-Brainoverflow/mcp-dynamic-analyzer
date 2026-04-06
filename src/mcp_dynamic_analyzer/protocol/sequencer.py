"""Test sequence runner with per-sequence timeout and error isolation.

The sequencer drives the *collection phase* by executing a list of
``TestSequence`` objects against a live MCP server.  Each sequence is
isolated: a timeout or server crash is recorded as an event and does
**not** abort the remaining sequences.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from mcp_dynamic_analyzer.correlation.event_store import EventWriter
from mcp_dynamic_analyzer.models import Event, ServerCrashError
from mcp_dynamic_analyzer.protocol.client import McpClient
from mcp_dynamic_analyzer.scanners.base import TestSequence

log = structlog.get_logger()


class Sequencer:
    """Runs ``TestSequence`` objects with error isolation.

    Usage::

        seq = Sequencer(session_id, client, writer, sequences)
        await seq.run_all()
    """

    def __init__(
        self,
        session_id: str,
        client: McpClient,
        writer: EventWriter,
        sequences: list[TestSequence],
    ) -> None:
        self._session_id = session_id
        self._client = client
        self._writer = writer
        self._sequences = sequences

    async def run_all(self) -> None:
        """Execute every registered sequence, isolating failures."""
        for seq in self._sequences:
            await self._run_one(seq)

    async def _run_one(self, seq: TestSequence) -> None:
        log.info("sequencer.start", sequence=seq.name, timeout=seq.timeout)
        try:
            await asyncio.wait_for(
                seq.execute(self._client, self._writer),
                timeout=seq.timeout,
            )
            log.info("sequencer.done", sequence=seq.name)

        except asyncio.TimeoutError:
            log.warning("sequencer.timeout", sequence=seq.name)
            await self._record("sequence_timeout", {"sequence": seq.name})

        except ServerCrashError:
            log.error("sequencer.crash", sequence=seq.name)
            await self._record("server_crash", {"sequence": seq.name})

        except Exception as exc:
            log.error("sequencer.error", sequence=seq.name, error=str(exc))
            await self._record("sequence_error", {"sequence": seq.name, "error": str(exc)})

    # -- helpers -------------------------------------------------------------

    async def _record(self, type_: str, data: dict[str, Any]) -> None:
        await self._writer.write(
            Event(
                session_id=self._session_id,
                source="test",
                type=type_,
                data=data,
            ),
        )


# ---------------------------------------------------------------------------
# Built-in sequences — basic MCP enumeration (always runs first)
# ---------------------------------------------------------------------------

class InitSequence(TestSequence):
    """Initialize the MCP session and enumerate tools / resources / prompts."""

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id

    @property
    def name(self) -> str:
        return "init_enumerate"

    async def execute(self, client: Any, writer: EventWriter) -> None:
        cli: McpClient = client
        await cli.initialize()

        tools = await cli.list_tools()
        tools_count = len(tools)
        if tools_count == 0:
            log.warning(
                "sequencer.no_tools_discovered",
                hint=(
                    "Server returned 0 tools. This may mean the backend service is "
                    "unavailable (e.g. Ghidra not running), the server failed to "
                    "initialize, or the server genuinely exposes no tools."
                ),
            )
        else:
            log.info("sequencer.tools_discovered", count=tools_count, names=[t.name for t in tools])

        await writer.write(
            Event(
                session_id=self._session_id,
                source="test",
                type="test_result",
                data={
                    "sequence": self.name,
                    "tools_count": tools_count,
                    "tools": [t.model_dump() for t in tools],
                },
            ),
        )

        try:
            resources = await cli.list_resources()
            log.info("sequencer.resources_discovered", count=len(resources))
            await writer.write(
                Event(
                    session_id=self._session_id,
                    source="test",
                    type="test_result",
                    data={"sequence": self.name, "resources_count": len(resources)},
                ),
            )
        except Exception as exc:
            log.debug("sequencer.resources_not_supported", reason=str(exc))

        try:
            prompts = await cli.list_prompts()
            log.info("sequencer.prompts_discovered", count=len(prompts))
            await writer.write(
                Event(
                    session_id=self._session_id,
                    source="test",
                    type="test_result",
                    data={"sequence": self.name, "prompts_count": len(prompts)},
                ),
            )
        except Exception as exc:
            log.debug("sequencer.prompts_not_supported", reason=str(exc))
