"""Network traffic monitoring for sandbox containers.

Periodically polls the container's network connections (via ``ss`` or
``/proc/net/tcp``) and records outbound connections as events.
Connections to addresses not in the allowlist generate
``blocked_connection`` events; allowed ones generate
``outbound_connection`` events.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import structlog

from mcp_dynamic_analyzer.correlation.event_store import EventWriter
from mcp_dynamic_analyzer.models import Event

log = structlog.get_logger()

_INTERNAL_PREFIXES = (
    "169.254.", "10.", "127.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "0.0.0.0",
)

# Parse lines from ``ss -tnp`` output.
_SS_RE = re.compile(
    r"(?:ESTAB|SYN-SENT|SYN-RECV)\s+\d+\s+\d+\s+"
    r"[\d.:]+\s+"               # local address
    r"(?P<remote>[\d.:]+)",     # remote address:port
)


class NetworkMonitor:
    """Background poller that records outbound network connections.

    In allowlist mode, connections outside the allowlist are flagged.
    When ``block_internal`` is True, any connection to RFC-1918 / link-local
    addresses generates a ``blocked_connection`` event.
    """

    def __init__(
        self,
        writer: EventWriter,
        session_id: str,
        *,
        allowlist: list[str] | None = None,
        block_internal: bool = True,
        docker_container: str | None = None,
    ) -> None:
        self._writer = writer
        self._session_id = session_id
        self._allowlist = set(allowlist or [])
        self._block_internal = block_internal
        self._container = docker_container
        self._seen: set[str] = set()
        self._task: asyncio.Task[None] | None = None
        self._stop = False

    async def start(self) -> None:
        self._stop = False
        self._task = asyncio.create_task(self._poll_loop(), name="netmon")

    async def stop(self) -> None:
        self._stop = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _poll_loop(self) -> None:
        try:
            while not self._stop:
                await self._check_connections()
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass

    async def _check_connections(self) -> None:
        """Run ``ss -tnp`` and record new outbound connections."""
        cmd = self._build_cmd()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        except (asyncio.TimeoutError, OSError):
            return

        for line in stdout.decode(errors="replace").splitlines():
            m = _SS_RE.search(line)
            if not m:
                continue
            remote = m.group("remote")
            if remote in self._seen:
                continue
            self._seen.add(remote)

            addr = remote.rsplit(":", 1)[0] if ":" in remote else remote

            if self._block_internal and _is_internal(addr):
                await self._emit("blocked_connection", remote, reason="internal_blocked")
            elif self._allowlist and not self._in_allowlist(remote):
                await self._emit("blocked_connection", remote, reason="not_in_allowlist")
            else:
                await self._emit("outbound_connection", remote)

    def _in_allowlist(self, remote: str) -> bool:
        return any(remote.startswith(a.split(":")[0]) for a in self._allowlist)

    def _build_cmd(self) -> list[str]:
        ss_cmd = ["ss", "-tnp"]
        if self._container:
            return ["docker", "exec", self._container] + ss_cmd
        return ss_cmd

    async def _emit(self, type_: str, destination: str, **extra: Any) -> None:
        await self._writer.write(Event(
            session_id=self._session_id,
            source="network",
            type=type_,
            data={"destination": destination, **extra},
        ))


def _is_internal(addr: str) -> bool:
    return any(addr.startswith(p) for p in _INTERNAL_PREFIXES)
