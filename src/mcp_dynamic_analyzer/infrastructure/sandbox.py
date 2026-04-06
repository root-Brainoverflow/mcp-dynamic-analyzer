"""Docker-based sandbox for running MCP servers in isolation.

Uses ``docker run -i`` via asyncio subprocess so that the container's
stdin/stdout map directly to asyncio StreamWriter/StreamReader.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

import structlog

from mcp_dynamic_analyzer.config import SandboxConfig, ServerConfig

log = structlog.get_logger()

# Env-variation presets used for R4 behavioral-drift detection.
_ENV_VARIATIONS: list[dict[str, str]] = [
    {"USER": "admin", "TZ": "Asia/Tokyo", "LANG": "ja_JP.UTF-8"},
    {"USER": "ci-bot", "TZ": "US/Pacific", "LANG": "en_US.UTF-8"},
    {"USER": "root", "TZ": "UTC", "LANG": "C"},
]


def generate_env_variation(
    base_env: dict[str, str],
    variation_index: int,
) -> dict[str, str]:
    """Merge *base_env* with a preset variation for R4 env-diff analysis."""
    preset = _ENV_VARIATIONS[variation_index % len(_ENV_VARIATIONS)]
    return {**base_env, **preset}


class Sandbox:
    """Manages a single sandboxed MCP server process.

    When used as an async context-manager the server is started on entry and
    killed + cleaned-up on exit.

    The sandbox operates in two modes depending on ``use_docker``:

    * **docker** (default): runs the server inside a Docker container via
      ``docker run -i``.  Requires Docker to be installed.
    * **local**: runs the server as a bare subprocess — useful for unit tests
      or development when Docker is not available.
    """

    def __init__(
        self,
        server_config: ServerConfig,
        sandbox_config: SandboxConfig,
        *,
        env_override: dict[str, str] | None = None,
        honeypot_dir: str | None = None,
        use_docker: bool = True,
    ) -> None:
        self._server = server_config
        self._sandbox = sandbox_config
        self._env_override = env_override
        self._honeypot_dir = honeypot_dir
        self._use_docker = use_docker
        self._proc: asyncio.subprocess.Process | None = None
        # Unique container name assigned before docker run so SystemMonitor
        # can attach strace via ``docker exec <name> strace -p 1``.
        self._container_name: str = f"mcp-analyzer-{uuid.uuid4().hex[:12]}"
        # Host directory mounted as /workspace inside the container.
        # Defaults to CWD so that relative server script paths resolve correctly.
        self._workspace_dir: str = str(Path.cwd())

    # -- public properties ---------------------------------------------------

    @property
    def stdin(self) -> asyncio.StreamWriter:
        assert self._proc is not None and self._proc.stdin is not None
        return self._proc.stdin

    @property
    def stdout(self) -> asyncio.StreamReader:
        assert self._proc is not None and self._proc.stdout is not None
        return self._proc.stdout

    @property
    def stderr(self) -> asyncio.StreamReader:
        assert self._proc is not None and self._proc.stderr is not None
        return self._proc.stderr

    @property
    def pid(self) -> int:
        """Host PID of the subprocess (docker process or direct server)."""
        assert self._proc is not None
        return self._proc.pid

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    @property
    def container_name(self) -> str | None:
        """Docker container name, or None in local mode."""
        return self._container_name if self._use_docker else None

    @property
    def http_base_url(self) -> str | None:
        """Local base URL to reach the target HTTP transport server."""
        if self._server.transport != "http" or not self._server.http_port:
            return None
        return f"http://127.0.0.1:{self._server.http_port}"

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        if self._use_docker:
            cmd = self._build_docker_cmd()
        else:
            cmd = self._build_local_cmd()

        log.info("sandbox.start", cmd=" ".join(cmd))
        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # Default asyncio StreamReader limit is 64 KB. MCP servers with
            # many tools (e.g. ghidra-mcp: 163 tools) return tools/list
            # responses that can exceed 90 KB in a single line. Raise to 8 MB.
            limit=2 ** 23,
        )
        log.info("sandbox.spawned", pid=self._proc.pid, use_docker=self._use_docker)
        # Drain stderr in the background so the pipe buffer never fills and
        # so that backend startup errors (e.g. "Cannot connect to Ghidra") are
        # visible in structured logs rather than silently discarded.
        self._stderr_task: asyncio.Task[None] = asyncio.create_task(
            self._drain_stderr(), name="sandbox-stderr"
        )
        # Give the server a moment to start up; if it exits immediately that's
        # a hard failure we can detect early.
        await asyncio.sleep(0.3)
        if self._proc.returncode is not None:
            # Collect whatever stderr we already have before raising.
            stderr_snippet = await self._read_stderr_snippet()
            raise RuntimeError(
                f"Server process exited immediately (rc={self._proc.returncode}). "
                f"stderr: {stderr_snippet or '(empty)'}"
            )

    async def _drain_stderr(self) -> None:
        """Read stderr line-by-line and forward to structlog."""
        assert self._proc is not None and self._proc.stderr is not None
        try:
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    break
                text = line.decode(errors="replace").rstrip()
                if text:
                    # Surface at WARNING level so backend errors are visible
                    # without being as noisy as DEBUG.
                    log.warning("sandbox.server_stderr", msg=text)
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("sandbox.stderr_drain_error")

    async def _read_stderr_snippet(self, max_bytes: int = 2048) -> str:
        """Read up to *max_bytes* from stderr without blocking long."""
        assert self._proc is not None and self._proc.stderr is not None
        try:
            data = await asyncio.wait_for(
                self._proc.stderr.read(max_bytes), timeout=1.0
            )
            return data.decode(errors="replace").strip()
        except (asyncio.TimeoutError, Exception):
            return ""

    async def stop(self) -> None:
        if self._proc is None:
            return
        # Cancel the stderr drain task first.
        task: asyncio.Task[None] | None = getattr(self, "_stderr_task", None)
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        if self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                log.warning("sandbox.kill_fallback", pid=self._proc.pid)
                self._proc.kill()
                await self._proc.wait()

        rc = self._proc.returncode
        if rc not in (0, -15, -9, None):  # -15=SIGTERM, -9=SIGKILL (normal shutdown)
            log.warning(
                "sandbox.abnormal_exit",
                pid=self._proc.pid,
                rc=rc,
                hint="Non-zero exit may indicate a startup failure or crash.",
            )
        else:
            log.info("sandbox.stop", pid=self._proc.pid, rc=rc)

    # -- context manager -----------------------------------------------------

    async def __aenter__(self) -> Sandbox:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    # -- command builders ----------------------------------------------------

    def _merged_env(self) -> dict[str, str]:
        env = dict(self._server.env)
        if self._env_override:
            env.update(self._env_override)
        return env

    def _docker_remap_cmd(self, cmd: str) -> str:
        """Normalise a server command for use inside the mcp-sandbox container.

        Handles three cases:
        1. Bare name alias  : "python"  → "python3"
        2. Host interpreter : "/Users/.../venv/bin/python3" → "python3"
           (absolute path to a Python/Node binary that won't exist in the image)
        3. Everything else  : returned unchanged
        """
        basename = Path(cmd).name  # works for both bare names and absolute paths
        _aliases: dict[str, str] = {
            "python": "python3",
            "python3.10": "python3",
            "python3.11": "python3",
            "python3.12": "python3",
            "python3.13": "python3",
            "node": "node",
            "nodejs": "node",
        }
        remapped = _aliases.get(basename, cmd if not Path(cmd).is_absolute() else basename)
        if remapped != cmd:
            log.info(
                "sandbox.cmd_remapped",
                original=cmd,
                remapped=remapped,
                reason="Host path or alias not available in mcp-sandbox image.",
            )
        return remapped

    def _build_docker_cmd(self) -> list[str]:
        sb = self._sandbox
        net = sb.network

        server_cmd = self._docker_remap_cmd(self._server.command)

        # Remap absolute-path args to container-internal paths and collect
        # extra volume mounts.  This handles --server-path /abs/path/server.py
        # where the server lives outside the CWD workspace.
        extra_mounts: dict[str, str] = {}   # host_dir → container_dir
        remapped_args: list[str] = []
        for arg in self._server.args:
            p = Path(arg)
            if p.is_absolute() and p.exists():
                host_dir = str(p.parent)
                # Reuse the same container dir if already mounted.
                if host_dir not in extra_mounts:
                    extra_mounts[host_dir] = f"/mcp-server-{len(extra_mounts)}"
                container_path = f"{extra_mounts[host_dir]}/{p.name}"
                log.info(
                    "sandbox.arg_remapped",
                    original=arg,
                    container=container_path,
                    reason="Absolute host path remapped to container mount point.",
                )
                remapped_args.append(container_path)
            else:
                remapped_args.append(arg)

        cmd: list[str] = [
            "docker", "run",
            "-i", "--rm",
            "--name", self._container_name,
            "--memory", sb.memory_limit,
            "--cpus", str(sb.cpu_limit),
            "--read-only",
            "--tmpfs", "/tmp:size=100m",
            "--security-opt", "no-new-privileges",
            "--cap-add", "SYS_PTRACE",
        ]

        if net.mode == "none":
            cmd += ["--network", "none"]
        elif net.mode == "allowlist":
            # Default Docker bridge: outbound internet for npx/npm, while avoiding
            # --network host (which would expose the host LAN).  True egress
            # filtering requires external firewall/proxy; netmon allowlist only
            # classifies observed connections in events.
            cmd += ["--network", "bridge"]

        for key, val in self._merged_env().items():
            cmd += ["-e", f"{key}={val}"]

        if self._honeypot_dir:
            # rw: npx/npm need to create ~/.npm under $HOME; many images use
            # /home/user as HOME.  RO caused ENOENT mkdir '/home/user/.npm'.
            # The host path is a per-session temp dir — still isolated from prod.
            cmd += ["-v", f"{self._honeypot_dir}:/home/user:rw"]

        # CWD workspace: for relative paths like "python tests/fixtures/server.py"
        cmd += ["-v", f"{self._workspace_dir}:/workspace:ro"]
        cmd += ["-w", "/workspace"]

        # Extra mounts for absolute server paths outside the workspace
        for host_dir, container_dir in extra_mounts.items():
            cmd += ["-v", f"{host_dir}:{container_dir}:ro"]

        if self._server.transport == "http" and self._server.http_port:
            cmd += ["-p", f"127.0.0.1:{self._server.http_port}:{self._server.http_port}/tcp"]

        cmd.append("mcp-sandbox")
        cmd.append(server_cmd)
        cmd += remapped_args

        return cmd

    def _build_local_cmd(self) -> list[str]:
        """Direct subprocess — no Docker isolation."""
        # Do NOT split command by whitespace here.
        # ``server.command`` may be an absolute executable path containing spaces
        # (e.g. "/Users/.../Integrated Project/.../.venv/bin/python3").
        return [self._server.command, *self._server.args]
