"""HTTP/SSE reverse-proxy interceptor for MCP servers using Streamable HTTP.

Provides the same ``send_request`` / ``send_notification`` interface as
``StdioInterceptor`` so that ``McpClient`` works with either transport.
Internally uses ``httpx.AsyncClient`` to relay JSON-RPC messages to the
target server, recording every request/response pair as protocol events.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

from mcp_dynamic_analyzer.correlation.event_store import EventWriter
from mcp_dynamic_analyzer.models import Event

log = structlog.get_logger()


class HttpInterceptor:
    """HTTP-based JSON-RPC interceptor for MCP Streamable HTTP transport.

    The MCP Streamable HTTP transport uses a single POST endpoint:
    client sends JSON-RPC requests, server responds with JSON-RPC
    responses (or SSE stream for server-initiated messages).
    """

    def __init__(
        self,
        base_url: str,
        writer: EventWriter,
        session_id: str,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._writer = writer
        self._session_id = session_id
        self._next_req_id = 0
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(base_url=self._base_url, timeout=30.0)

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def send_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST a JSON-RPC request and return the response."""
        self._next_req_id += 1
        req_id = self._next_req_id
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params

        await self._record(msg, direction="c2s")

        assert self._client is not None
        resp = await self._client.post(
            "/mcp/v1",
            json=msg,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        resp.raise_for_status()
        body = resp.json()

        await self._record(body, direction="s2c")
        return body

    async def send_notification(
        self,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> None:
        """POST a JSON-RPC notification (no response expected)."""
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params

        await self._record(msg, direction="c2s")

        assert self._client is not None
        await self._client.post(
            "/mcp/v1",
            json=msg,
            headers={"Content-Type": "application/json"},
        )

    async def _record(self, msg: dict[str, Any], *, direction: str) -> None:
        method = msg.get("method")
        msg_id = msg.get("id")
        evt_type = "mcp_request" if method and direction == "c2s" else (
            "mcp_notification" if method else "mcp_response"
        )
        await self._writer.write(Event(
            session_id=self._session_id,
            source="protocol",
            type=evt_type,
            direction=direction,
            data={"method": method, "id": msg_id, "message": msg},
        ))
