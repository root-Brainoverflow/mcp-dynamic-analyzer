"""Lightweight MCP test client built on top of the StdioInterceptor.

Implements the MCP handshake (``initialize`` → ``initialized``) and the
core methods needed for dynamic analysis: ``tools/list``, ``tools/call``,
``resources/list``, ``prompts/list``.
"""

from __future__ import annotations

from typing import Any

import structlog

from mcp_dynamic_analyzer.models import ToolInfo

log = structlog.get_logger()

MCP_PROTOCOL_VERSION = "2024-11-05"


class McpClient:
    """Thin async client that speaks the MCP JSON-RPC protocol.

    All methods raise ``McpError`` on JSON-RPC error responses.
    """

    def __init__(self, interceptor: Any) -> None:
        self._icp = interceptor
        self._server_info: dict[str, Any] = {}

    @property
    def server_info(self) -> dict[str, Any]:
        """Capabilities returned by the server during ``initialize``."""
        return self._server_info

    # -- handshake -----------------------------------------------------------

    async def initialize(self) -> dict[str, Any]:
        """Perform the MCP initialize handshake.

        Returns:
            The ``result`` payload from the server's initialize response.
        """
        resp = await self._icp.send_request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-dynamic-analyzer",
                    "version": "0.1.0",
                },
            },
        )
        result = _unwrap(resp)
        self._server_info = result
        log.info("mcp.initialized", server=result.get("serverInfo"))

        await self._icp.send_notification("notifications/initialized")
        return result

    # -- tool operations -----------------------------------------------------

    async def list_tools(self) -> list[ToolInfo]:
        """Call ``tools/list`` and return parsed ``ToolInfo`` objects."""
        resp = await self._icp.send_request("tools/list")
        result = _unwrap(resp)
        tools_raw: list[dict[str, Any]] = result.get("tools", [])
        return [
            ToolInfo(
                name=t["name"],
                description=t.get("description"),
                input_schema=t.get("inputSchema"),
                annotations=t.get("annotations"),
            )
            for t in tools_raw
        ]

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Call ``tools/call`` and return the result payload.

        Raises:
            McpError: on a JSON-RPC error response.  The ``context`` attribute
                contains the tool name and arguments for easier debugging.
        """
        params: dict[str, Any] = {"name": name}
        if arguments is not None:
            params["arguments"] = arguments
        log.debug("mcp.call_tool", tool=name, arguments=arguments)
        try:
            resp = await self._icp.send_request("tools/call", params)
            result = _unwrap(resp)
            log.debug("mcp.call_tool.ok", tool=name)
            return result
        except McpError as exc:
            log.warning(
                "mcp.call_tool.error",
                tool=name,
                code=exc.code,
                message=exc.message,
                hint=(
                    "If this is a backend-dependent tool (e.g. requires Ghidra/DB), "
                    "ensure the backend service is running and reachable."
                    if exc.code in (-32603, -32000)  # Internal error / server error
                    else None
                ),
            )
            raise
        except ConnectionError as exc:
            log.error(
                "mcp.call_tool.connection_lost",
                tool=name,
                error=str(exc),
                hint="Server stdout closed — the process may have crashed.",
            )
            raise

    # -- resource / prompt enumeration ---------------------------------------

    async def list_resources(self) -> list[dict[str, Any]]:
        resp = await self._icp.send_request("resources/list")
        return _unwrap(resp).get("resources", [])

    async def list_prompts(self) -> list[dict[str, Any]]:
        resp = await self._icp.send_request("prompts/list")
        return _unwrap(resp).get("prompts", [])

    # -- raw access ----------------------------------------------------------

    async def send_raw(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send an arbitrary JSON-RPC request and return the full response."""
        return await self._icp.send_request(method, params)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class McpError(Exception):
    """Raised when the server returns a JSON-RPC error response."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"MCP error {code}: {message}")


def _unwrap(resp: dict[str, Any]) -> dict[str, Any]:
    """Extract ``result`` from a JSON-RPC response or raise ``McpError``."""
    if "error" in resp:
        err = resp["error"]
        raise McpError(err.get("code", -1), err.get("message", "unknown"), err.get("data"))
    return resp.get("result", {})
