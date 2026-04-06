"""Cross-platform system monitor for MCP server process observation.

Backend selection (automatic):
  Linux   → strace  (event-driven syscall tracing, comprehensive)
  macOS   → psutil  (periodic snapshot diff, no root/SIP required)
  Windows → psutil  (periodic snapshot diff)

Both backends emit the same Event types into EventWriter so the rest of
the pipeline is platform-agnostic.

strace event types : file_open, file_read, file_write, process_exec, network_connect
psutil event types : file_open, network_connect, process_exec
  (file_read/write not available via psutil — requires syscall-level tracing)
"""

from __future__ import annotations

import asyncio
import platform
import re
import shutil
import sys
from typing import Any

import structlog

from mcp_dynamic_analyzer.correlation.event_store import EventWriter
from mcp_dynamic_analyzer.models import Event

log = structlog.get_logger()


class SysmonUnavailableError(Exception):
    """Raised when no suitable syscall/process monitor is available."""


# ---------------------------------------------------------------------------
# Public facade
# ---------------------------------------------------------------------------

class SystemMonitor:
    """Platform-aware process monitor.

    Automatically selects the best available backend:
    - Linux  + strace installed → StraceBackend
    - otherwise                 → PsutilBackend

    Usage::

        mon = SystemMonitor(pid, writer, session_id)
        await mon.start()
        ...
        await mon.stop()
    """

    def __init__(
        self,
        target_pid: int,
        writer: EventWriter,
        session_id: str,
        *,
        docker_container: str | None = None,
        poll_interval: float = 0.5,
    ) -> None:
        self._pid = target_pid
        self._writer = writer
        self._session_id = session_id
        self._container = docker_container
        self._poll_interval = poll_interval
        self._backend: _MonitorBackend | None = None

    async def start(self) -> None:
        backend = _select_backend(
            pid=self._pid,
            writer=self._writer,
            session_id=self._session_id,
            docker_container=self._container,
            poll_interval=self._poll_interval,
        )
        await backend.start()
        self._backend = backend
        log.info(
            "sysmon.start",
            backend=type(backend).__name__,
            pid=self._pid,
            platform=platform.system(),
        )

    async def stop(self) -> None:
        if self._backend is not None:
            await self._backend.stop()
            log.info("sysmon.stop", backend=type(self._backend).__name__)


# ---------------------------------------------------------------------------
# Backend interface
# ---------------------------------------------------------------------------

class _MonitorBackend:
    async def start(self) -> None: ...
    async def stop(self) -> None: ...


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

def _select_backend(
    *,
    pid: int,
    writer: EventWriter,
    session_id: str,
    docker_container: str | None,
    poll_interval: float,
) -> _MonitorBackend:
    """Pick the best available backend for this platform.

    Priority:
      1. Linux + strace    → StraceBackend  (event-driven, full syscall coverage)
      2. macOS + lsof      → LsofBackend    (polling, 100 ms, covers transient opens)
      3. any + psutil      → PsutilBackend  (polling, fallback, misses fast-close files)
      4. nothing available → SysmonUnavailableError
    """
    os_name = platform.system()  # "Linux", "Darwin", "Windows"

    # ── 1. Docker mode: strace runs INSIDE the container via docker exec ──────
    # The host OS doesn't need strace; the container image must have it.
    # Works on macOS / Windows / Linux equally because the container is Linux.
    if docker_container is not None:
        log.info(
            "sysmon.backend_selected",
            backend="strace",
            mode="docker-exec",
            container=docker_container,
        )
        return StraceBackend(
            pid=pid,
            writer=writer,
            session_id=session_id,
            docker_container=docker_container,
        )

    # ── 2. Local Linux + strace installed ────────────────────────────────────
    if os_name == "Linux" and shutil.which("strace"):
        log.info("sysmon.backend_selected", backend="strace", mode="local")
        return StraceBackend(
            pid=pid,
            writer=writer,
            session_id=session_id,
            docker_container=None,
        )

    if os_name == "Linux":
        log.warning(
            "sysmon.strace_not_found",
            hint="strace not installed — falling back to lsof/psutil (reduced coverage). "
                 "Install with: apt-get install strace",
        )

    # ── 2. macOS / Linux-without-strace: lsof ────────────────────────────────
    if shutil.which("lsof"):
        log.info(
            "sysmon.backend_selected",
            backend="lsof",
            os=os_name,
            hint="Using lsof polling (100 ms) for file-open tracking.",
        )
        return LsofBackend(
            pid=pid,
            writer=writer,
            session_id=session_id,
            poll_interval=min(poll_interval, 0.1),  # cap at 100 ms for lsof
        )

    # ── 3. Windows / no lsof: psutil ─────────────────────────────────────────
    try:
        import psutil  # noqa: F401
    except ImportError as exc:
        raise SysmonUnavailableError(
            f"No suitable syscall monitor available on {os_name}. "
            "strace not found (Linux only), lsof not found, and psutil is not installed. "
            "Install psutil: uv pip install psutil"
        ) from exc

    log.info(
        "sysmon.backend_selected",
        backend="psutil",
        os=os_name,
        hint="Using psutil polling. Fast-close file accesses may be missed.",
    )
    return PsutilBackend(
        pid=pid,
        writer=writer,
        session_id=session_id,
        poll_interval=poll_interval,
    )


# ---------------------------------------------------------------------------
# Backend 1: strace  (Linux only, event-driven)
# ---------------------------------------------------------------------------

_TRACE_SET = "open,openat,read,write,pread64,pwrite64,execve,connect"

_TYPE_MAP: dict[str, str] = {
    "open": "file_open",
    "openat": "file_open",
    "read": "file_read",
    "pread64": "file_read",
    "write": "file_write",
    "pwrite64": "file_write",
    "execve": "process_exec",
    "connect": "network_connect",
}

_LINE_RE = re.compile(
    r"^(?P<ts>[\d.]+)\s+"
    r"(?P<syscall>\w+)\("
    r"(?P<args>.*?)\)"
    r"\s*=\s*(?P<ret>-?\d+|0x[0-9a-f]+|\?)",
)
_QUOTED_RE = re.compile(r'"([^"]*)"')


class StraceBackend(_MonitorBackend):
    """Attach strace to the server PID and stream parsed syscall events."""

    def __init__(
        self,
        pid: int,
        writer: EventWriter,
        session_id: str,
        *,
        docker_container: str | None = None,
    ) -> None:
        self._pid = pid
        self._writer = writer
        self._session_id = session_id
        self._container = docker_container
        self._proc: asyncio.subprocess.Process | None = None
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        cmd = self._build_cmd()
        log.info("sysmon.strace.start", cmd=" ".join(cmd))
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise SysmonUnavailableError(
                "strace not found. Install via: apt-get install strace"
            ) from exc
        self._task = asyncio.create_task(self._read_loop(), name="sysmon-strace")

    async def stop(self) -> None:
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._proc.kill()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def _build_cmd(self) -> list[str]:
        if self._container:
            # Inside the container the MCP server is always PID 1 (the root
            # process launched by docker run).  We attach strace from the host
            # via ``docker exec`` so the host OS doesn't need strace installed —
            # only the container image does.  ``--cap-add SYS_PTRACE`` must be
            # set on the container (done in Sandbox._build_docker_cmd).
            return [
                "docker", "exec", self._container,
                "strace", "-f", "-t", "-T",
                "-e", f"trace={_TRACE_SET}",
                "-e", "signal=none",
                "-p", "1",  # server is always PID 1 inside the container
            ]
        # Local mode: attach to the host PID directly.
        return [
            "strace", "-f", "-t", "-T",
            "-e", f"trace={_TRACE_SET}",
            "-e", "signal=none",
            "-p", str(self._pid),
        ]

    async def _read_loop(self) -> None:
        assert self._proc and self._proc.stderr
        try:
            async for raw_line in self._proc.stderr:
                line = raw_line.decode(errors="replace").strip()
                evt = _parse_strace_line(line, self._session_id)
                if evt:
                    await self._writer.write(evt)
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("sysmon.strace.read_error")


def _parse_strace_line(line: str, session_id: str) -> Event | None:
    m = _LINE_RE.search(line)
    if not m:
        return None
    syscall = m.group("syscall")
    evt_type = _TYPE_MAP.get(syscall)
    if not evt_type:
        return None

    args_str = m.group("args")
    ret = m.group("ret")
    data: dict[str, Any] = {"syscall": syscall, "return": ret, "raw": line[:500]}

    quoted = _QUOTED_RE.findall(args_str)
    if quoted:
        data["path"] = quoted[0]
    if syscall == "execve" and quoted:
        data["executable"] = quoted[0]
        data["argv"] = quoted[1:] if len(quoted) > 1 else []
    if syscall == "connect":
        data["address"] = args_str[:200]

    return Event(session_id=session_id, source="syscall", type=evt_type, data=data)


# ---------------------------------------------------------------------------
# Backend 2: lsof  (macOS / Linux-fallback, polling via lsof -F n -p <pid>)
# ---------------------------------------------------------------------------

_LSOF_PATH_RE = re.compile(r"^n(.+)$")  # lsof -F output: 'n' prefix = name


class LsofBackend(_MonitorBackend):
    """Poll ``lsof -F n -p <pid>`` at a short interval to detect file opens.

    lsof snapshots all open file descriptors including those opened and
    closed between polls, as long as the file is still open at poll time.
    At 100 ms intervals it catches most short-lived file accesses.

    Also uses psutil for network connections and child process detection
    since lsof network parsing is more complex.

    Coverage:
    ✅ file_open      — lsof snapshot diff
    ✅ network_connect — psutil net_connections diff
    ✅ process_exec   — psutil children diff
    ❌ file_read / file_write — requires syscall-level tracing
    """

    def __init__(
        self,
        pid: int,
        writer: EventWriter,
        session_id: str,
        *,
        poll_interval: float = 0.1,
    ) -> None:
        self._pid = pid
        self._writer = writer
        self._session_id = session_id
        self._poll_interval = poll_interval
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._poll_loop(), name="sysmon-lsof")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _poll_loop(self) -> None:
        import psutil

        try:
            proc = psutil.Process(self._pid)
        except psutil.NoSuchProcess:
            log.warning("sysmon.lsof.no_process", pid=self._pid)
            return

        prev_files: set[str] = set()
        prev_conns: set[tuple[Any, ...]] = set()
        prev_children: set[int] = set()

        log.debug("sysmon.lsof.polling_start", pid=self._pid, interval=self._poll_interval)

        try:
            while True:
                await asyncio.sleep(self._poll_interval)

                try:
                    if not proc.is_running():
                        break
                except psutil.NoSuchProcess:
                    break

                # --- file opens via lsof ---
                try:
                    current_files = await self._lsof_files()
                    new_files = current_files - prev_files
                    for path in new_files:
                        await self._writer.write(Event(
                            session_id=self._session_id,
                            source="syscall",
                            type="file_open",
                            data={"path": path, "backend": "lsof"},
                        ))
                    prev_files = current_files
                except Exception:
                    pass

                # --- network connections via psutil ---
                try:
                    current_conns = _conn_keys(proc)
                    new_conns = current_conns - prev_conns
                    for key in new_conns:
                        laddr, raddr, status, kind = key
                        if raddr:
                            await self._writer.write(Event(
                                session_id=self._session_id,
                                source="syscall",
                                type="network_connect",
                                data={
                                    "address": f"{raddr[0]}:{raddr[1]}" if raddr else "",
                                    "local": f"{laddr[0]}:{laddr[1]}" if laddr else "",
                                    "status": status,
                                    "kind": kind,
                                    "backend": "lsof",
                                },
                            ))
                    prev_conns = current_conns
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # --- child processes via psutil ---
                try:
                    current_children = {c.pid for c in proc.children(recursive=True)}
                    new_children = current_children - prev_children
                    for child_pid in new_children:
                        try:
                            child = psutil.Process(child_pid)
                            cmdline = child.cmdline()
                            exe = child.exe() if cmdline else ""
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            cmdline, exe = [], ""
                        await self._writer.write(Event(
                            session_id=self._session_id,
                            source="syscall",
                            type="process_exec",
                            data={
                                "executable": exe or (cmdline[0] if cmdline else ""),
                                "argv": cmdline[1:] if len(cmdline) > 1 else [],
                                "child_pid": child_pid,
                                "backend": "lsof",
                            },
                        ))
                    prev_children = current_children
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("sysmon.lsof.poll_error")

    async def _lsof_files(self) -> set[str]:
        """Run ``lsof -F n -p <pid>`` and return the set of open file paths."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "lsof", "-F", "n", "-p", str(self._pid),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=2.0)
        except (FileNotFoundError, asyncio.TimeoutError):
            return set()

        paths: set[str] = set()
        for line in stdout.decode(errors="replace").splitlines():
            m = _LSOF_PATH_RE.match(line)
            if m:
                path = m.group(1)
                # Skip pipes, sockets, and pseudo-files
                if path.startswith("/") and not path.startswith("/proc/"):
                    paths.add(path)
        return paths


# ---------------------------------------------------------------------------
# Backend 3: psutil  (macOS / Windows / Linux fallback, polling-based)
# ---------------------------------------------------------------------------

class PsutilBackend(_MonitorBackend):
    """Periodic snapshot diff using psutil.

    Polls the target process (and its children) every *poll_interval* seconds.
    Detects new open files, new network connections, and new child processes by
    comparing consecutive snapshots.

    Coverage vs strace:
    ✅  file_open      — new entries in proc.open_files()
    ✅  network_connect — new entries in proc.net_connections() / proc.connections()
    ✅  process_exec   — new child processes via proc.children(recursive=True)
    ❌  file_read / file_write — requires syscall-level tracing
    """

    def __init__(
        self,
        pid: int,
        writer: EventWriter,
        session_id: str,
        *,
        poll_interval: float = 0.5,
    ) -> None:
        self._pid = pid
        self._writer = writer
        self._session_id = session_id
        self._poll_interval = poll_interval
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._poll_loop(), name="sysmon-psutil")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _poll_loop(self) -> None:
        import psutil

        try:
            proc = psutil.Process(self._pid)
        except psutil.NoSuchProcess:
            log.warning("sysmon.psutil.no_process", pid=self._pid)
            return

        prev_files: set[str] = set()
        prev_conns: set[tuple[Any, ...]] = set()
        prev_children: set[int] = set()

        log.debug("sysmon.psutil.polling_start", pid=self._pid, interval=self._poll_interval)

        try:
            while True:
                await asyncio.sleep(self._poll_interval)

                if not proc.is_running():
                    log.debug("sysmon.psutil.process_gone", pid=self._pid)
                    break

                # --- open files ---
                try:
                    current_files = {f.path for f in proc.open_files()}
                    new_files = current_files - prev_files
                    for path in new_files:
                        await self._writer.write(Event(
                            session_id=self._session_id,
                            source="syscall",
                            type="file_open",
                            data={"path": path, "backend": "psutil"},
                        ))
                    prev_files = current_files
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # --- network connections ---
                try:
                    current_conns = _conn_keys(proc)
                    new_conns = current_conns - prev_conns
                    for key in new_conns:
                        laddr, raddr, status, kind = key
                        if raddr:
                            await self._writer.write(Event(
                                session_id=self._session_id,
                                source="syscall",
                                type="network_connect",
                                data={
                                    "address": f"{raddr[0]}:{raddr[1]}" if raddr else "",
                                    "local": f"{laddr[0]}:{laddr[1]}" if laddr else "",
                                    "status": status,
                                    "kind": kind,
                                    "backend": "psutil",
                                },
                            ))
                    prev_conns = current_conns
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

                # --- child processes (process_exec approximation) ---
                try:
                    current_children = {c.pid for c in proc.children(recursive=True)}
                    new_children = current_children - prev_children
                    for child_pid in new_children:
                        try:
                            child = psutil.Process(child_pid)
                            cmdline = child.cmdline()
                            exe = child.exe() if cmdline else ""
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            cmdline, exe = [], ""
                        await self._writer.write(Event(
                            session_id=self._session_id,
                            source="syscall",
                            type="process_exec",
                            data={
                                "executable": exe or (cmdline[0] if cmdline else ""),
                                "argv": cmdline[1:] if len(cmdline) > 1 else [],
                                "child_pid": child_pid,
                                "backend": "psutil",
                            },
                        ))
                    prev_children = current_children
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass

        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("sysmon.psutil.poll_error")


def _conn_keys(proc: Any) -> set[tuple[Any, ...]]:
    """Return a hashable set of connection tuples for diffing."""
    import psutil

    try:
        # psutil >= 6.0 uses net_connections(); < 6.0 uses connections()
        if hasattr(proc, "net_connections"):
            conns = proc.net_connections()
        else:
            conns = proc.connections()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return set()

    result = set()
    for c in conns:
        laddr = tuple(c.laddr) if c.laddr else None
        raddr = tuple(c.raddr) if c.raddr else None
        result.add((laddr, raddr, c.status, c.type))
    return result
