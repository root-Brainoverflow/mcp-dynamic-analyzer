"""stdio JSON-RPC interceptor that captures all MCP messages to EventWriter.

The interceptor sits between the test client and the MCP server, forwarding
every JSON-RPC message while recording it as an ``Event`` in the store.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog

from mcp_dynamic_analyzer.correlation.event_store import EventWriter
from mcp_dynamic_analyzer.models import Event, ServerCrashError

log = structlog.get_logger()


class StdioInterceptor:
    """Bidirectional JSON-RPC proxy over a subprocess's stdin/stdout.

    The interceptor spawns a background reader task that continuously
    reads the server's stdout and dispatches messages:

    * **Responses** (have ``id``, no ``method``) are routed to the
      ``asyncio.Future`` that is waiting for that ``id``.
    * **Notifications** (have ``method``, no ``id``) are placed on the
      ``notifications`` queue for callers that need them.
    """

    def __init__(
        self,
        proc_stdin: asyncio.StreamWriter,
        proc_stdout: asyncio.StreamReader,
        writer: EventWriter,
        session_id: str,
    ) -> None:
        self._stdin = proc_stdin
        self._stdout = proc_stdout
        self._writer = writer
        self._session_id = session_id

        self._next_req_id = 0
        self._pending: dict[int | str, asyncio.Future[dict[str, Any]]] = {}
        self._reader_task: asyncio.Task[None] | None = None
        self.notifications: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._closed = False
        self.server_died = False

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Begin reading from the server's stdout."""
        self._reader_task = asyncio.create_task(self._read_loop(), name="interceptor-reader")

    async def close(self) -> None:
        """Cancel the reader task and reject all pending futures."""
        self._closed = True
        if self._reader_task is not None:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(ConnectionError("interceptor closed"))
        self._pending.clear()

    # -- sending (client → server) -------------------------------------------

    async def send_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Send a JSON-RPC request and wait for the matching response."""
        self._next_req_id += 1
        req_id = self._next_req_id
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params

        if self.server_died:
            raise ServerCrashError("server has already crashed")

        fut: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
        self._pending[req_id] = fut

        await self._write_to_server(msg, direction="c2s")
        return await fut

    async def send_notification(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        await self._write_to_server(msg, direction="c2s")

    # -- internal I/O --------------------------------------------------------

    async def _write_to_server(self, msg: dict[str, Any], *, direction: str) -> None:
        # Keep wire payload ASCII-safe so lone-surrogate fuzz strings survive
        # transport as ``\uXXXX`` escapes instead of crashing UTF-8 encoding.
        raw = json.dumps(msg, ensure_ascii=True)
        self._stdin.write((raw + "\n").encode())
        await self._stdin.drain()
        await self._record(msg, direction=direction)

    async def _read_loop(self) -> None:
        """Continuously read lines from stdout and dispatch."""
        try:
            while not self._closed:
                line = await self._stdout.readline()
                if not line:
                    log.warning("interceptor.eof", hint="Server stdout closed — process likely crashed.")
                    self.server_died = True
                    break
                text = line.decode().strip()
                if not text:
                    continue
                try:
                    msg = json.loads(text)
                except json.JSONDecodeError:
                    log.warning("interceptor.bad_json", raw=text[:200])
                    continue

                await self._record(msg, direction="s2c")
                self._dispatch(msg)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("interceptor.read_loop_error")
        finally:
            exc = ServerCrashError("server stream ended") if self.server_died else ConnectionError("server stream ended")
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(exc)
            self._pending.clear()

    def _dispatch(self, msg: dict[str, Any]) -> None:
        msg_id = msg.get("id")
        has_method = "method" in msg

        if msg_id is not None and not has_method:
            # JSON-RPC response
            fut = self._pending.pop(msg_id, None)
            if fut is not None and not fut.done():
                fut.set_result(msg)
        else:
            # Server-initiated notification
            self.notifications.put_nowait(msg)

    # -- event recording -----------------------------------------------------

    async def _record(self, msg: dict[str, Any], *, direction: str) -> None:
        method = msg.get("method")
        msg_id = msg.get("id")

        if method:
            evt_type = "mcp_request" if direction == "c2s" else "mcp_notification"
        else:
            evt_type = "mcp_response"

        await self._writer.write(
            Event(
                session_id=self._session_id,
                source="protocol",
                type=evt_type,
                direction=direction,
                data={"method": method, "id": msg_id, "message": msg},
            ),
        )
