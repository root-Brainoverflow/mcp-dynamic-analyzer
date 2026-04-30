"""Docker-based sandbox for running MCP servers in isolation.

Uses ``docker run -i`` via asyncio subprocess so that the container's
stdin/stdout map directly to asyncio StreamWriter/StreamReader.

Bootstrap retry
───────────────
When a server process exits immediately (within 0.3 s of spawn), the sandbox
captures the accumulated stderr, analyses it for missing-dependency signals,
builds a patched bootstrap image, and retries once.  Two layers of detection:

1. Recipe-based (``plan_bootstrap(stderr_snippet=...)``) — matches the
   ``stderr_tokens_any`` rules already defined in ``builtin.yaml``.
2. Dynamic heuristics (``_apt_packages_from_stderr``) — parses
   "X: command not found" and "cannot open shared object file: libY.so.N"
   patterns and maps them to known apt packages.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

import structlog

from mcp_dynamic_analyzer.config import SandboxConfig, ServerConfig
from mcp_dynamic_analyzer.infrastructure.bootstrap import (
    BootstrapPlan,
    PreflightEvidence,
    SourcePreflightInspector,
    merged_bootstrap_env,
    plan_bootstrap,
    render_bootstrap_dockerfile,
)
from mcp_dynamic_analyzer.infrastructure.runtime_resolver import (
    ResolvedRuntime,
    RuntimeResolver,
)

log = structlog.get_logger()

# Env-variation presets used for R4 behavioral-drift detection.
_ENV_VARIATIONS: list[dict[str, str]] = [
    {"USER": "admin", "TZ": "Asia/Tokyo", "LANG": "ja_JP.UTF-8"},
    {"USER": "ci-bot", "TZ": "US/Pacific", "LANG": "en_US.UTF-8"},
    {"USER": "root", "TZ": "UTC", "LANG": "C"},
]

# Project markers used to widen absolute-path mounts beyond a single file's
# parent directory. This preserves sibling assets such as ``bin/../scripts``.
_PROJECT_ROOT_MARKERS = (
    "package.json",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Cargo.toml",
    "go.mod",
    ".git",
)
_MAX_PROJECT_ROOT_ASCENT = 5

# Commands that fetch and run a package on demand. They never need the host
# CWD as their working directory — mounting it (and especially mounting the
# analyzer's own repo) leaks artifacts like ``.venv/`` from the host into the
# sandbox. ``uv`` then tries to mutate that .venv and crashes with
# "Read-only file system" on the workspace mount. For these commands we use
# a fresh tmpfs cwd instead.
_PACKAGE_RUNNERS = frozenset({
    "uv", "uvx", "npx", "pnpx", "bunx", "pipx",
})

_SECRET_KEY_RE = re.compile(
    r"(?i)(secret|token|api[_\-]?key|password|passwd|credential)",
)

# ─────────────────────────────────────────────────────────────────────────────
# Dynamic stderr → apt package heuristics
# ─────────────────────────────────────────────────────────────────────────────

_RE_CMD_NOT_FOUND = re.compile(
    r"(?:bash: |/bin/sh: )?'?(\S+?)'?:"
    r" (?:command not found|not found|No such file or directory)",
    re.IGNORECASE,
)
_RE_LIB_NOT_FOUND = re.compile(
    r"(?:error while loading shared libraries|cannot open shared object file):"
    r"\s*(lib[^\s:,]+)",
    re.IGNORECASE,
)

_COMMAND_TO_APT: dict[str, str] = {
    "curl":             "curl",
    "wget":             "wget",
    "zip":              "zip",
    "unzip":            "unzip",
    "jq":               "jq",
    "make":             "build-essential",
    "gcc":              "gcc",
    "g++":              "g++",
    "ffmpeg":           "ffmpeg",
    "git":              "git",
    "convert":          "imagemagick",
    "identify":         "imagemagick",
    "tesseract":        "tesseract-ocr",
    "pdftotext":        "poppler-utils",
    "pdftoppm":         "poppler-utils",
    "pdfinfo":          "poppler-utils",
    "xvfb-run":         "xvfb",
    "Xvfb":             "xvfb",
    "dot":              "graphviz",
    "graphviz":         "graphviz",
    "gs":               "ghostscript",
    "ghostscript":      "ghostscript",
    "inkscape":         "inkscape",
    "soffice":          "libreoffice-core",
    "libreoffice":      "libreoffice-core",
    "pandoc":           "pandoc",
    "sqlite3":          "sqlite3",
    "psql":             "postgresql-client",
    "mysql":            "default-mysql-client",
    "redis-cli":        "redis-tools",
    "chromium":         "chromium-browser",
    "chromium-browser": "chromium-browser",
    "wkhtmltopdf":      "wkhtmltopdf",
    "xdg-open":         "xdg-utils",
    "dbus-launch":      "dbus",
}

_LIB_TO_APT: dict[str, str] = {
    "libGL":           "libgl1",
    "libGLU":          "libglu1-mesa",
    "libEGL":          "libegl1",
    "libpq":           "libpq5",
    "libsqlite3":      "libsqlite3-0",
    "libssl":          "libssl3",
    "libcrypto":       "libssl3",
    "libcairo":        "libcairo2",
    "libpangocairo":   "libpango-1.0-0",
    "libpango":        "libpango-1.0-0",
    "libgdk_pixbuf":   "libgdk-pixbuf-2.0-0",
    "libglib":         "libglib2.0-0",
    "libatk":          "libatk1.0-0",
    "libstdc++":       "libstdc++6",
    "libgcc_s":        "libgcc-s1",
    "libX11":          "libx11-6",
    "libXcomposite":   "libxcomposite1",
    "libXcursor":      "libxcursor1",
    "libXdamage":      "libxdamage1",
    "libXext":         "libxext6",
    "libXfixes":       "libxfixes3",
    "libXi":           "libxi6",
    "libXrandr":       "libxrandr2",
    "libXrender":      "libxrender1",
    "libXss":          "libxss1",
    "libXtst":         "libxtst6",
    "libgbm":          "libgbm1",
    "libnss3":         "libnss3",
    "libnspr4":        "libnspr4",
    "libasound":       "libasound2",
    "libdbus":         "libdbus-1-3",
    "libexpat":        "libexpat1",
    "libfontconfig":   "libfontconfig1",
    "libfreetype":     "libfreetype6",
    "libharfbuzz":     "libharfbuzz0b",
    "libicu":          "libicu72",
    "libjpeg":         "libjpeg62-turbo",
    "libpng":          "libpng16-16",
    "libz":            "zlib1g",
    "libzip":          "libzip4",
    "libzstd":         "libzstd1",
    "libcurl":         "libcurl4",
    "libmagic":        "libmagic1",
    "libmagickcore":   "libmagickcore-6.q16-6",
    "libmagickwand":   "libmagickwand-6.q16-6",
    "libtesseract":    "libtesseract5",
    "libpoppler":      "libpoppler126",
    "libavcodec":      "libavcodec60",
    "libavformat":     "libavformat60",
    "libswscale":      "libswscale7",
}


def _apt_packages_from_stderr(stderr: str) -> list[str]:
    """Heuristically map stderr failure patterns to apt package names."""
    seen: dict[str, None] = {}  # ordered set via dict

    for m in _RE_CMD_NOT_FOUND.finditer(stderr):
        cmd = m.group(1).strip("'\"")
        pkg = _COMMAND_TO_APT.get(cmd)
        if pkg:
            seen[pkg] = None

    for m in _RE_LIB_NOT_FOUND.finditer(stderr):
        lib = m.group(1)
        base_m = re.match(r"(lib[a-zA-Z0-9+_-]+)(?:\.so|\.so\.\d+)", lib)
        if base_m:
            pkg = _LIB_TO_APT.get(base_m.group(1))
            if pkg is None:
                # Fallback: libfoo.so.N → libfooN
                so_m = re.match(r"(lib[a-zA-Z0-9+_-]+)\.so\.(\d+)", lib)
                if so_m:
                    pkg = f"{so_m.group(1)}{so_m.group(2)}"
            if pkg:
                seen[pkg] = None

    return list(seen.keys())


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
        sysmon_enabled: bool = False,
        runtime_resolver: RuntimeResolver | None = None,
        preflight_inspector: SourcePreflightInspector | None = None,
    ) -> None:
        self._server = server_config
        self._sandbox = sandbox_config
        self._env_override = env_override
        self._honeypot_dir = honeypot_dir
        self._use_docker = use_docker
        self._sysmon_enabled = sysmon_enabled
        self._resolver = runtime_resolver or RuntimeResolver()
        self._preflight = (
            preflight_inspector or SourcePreflightInspector()
            if use_docker
            else None
        )
        self._resolved: ResolvedRuntime | None = None
        self._preflight_evidence: PreflightEvidence | None = None
        self._bootstrap_plan: BootstrapPlan | None = None
        self._bootstrap_image: str | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._stderr_lines: list[str] = []
        self._stderr_task: asyncio.Task[None] | None = None
        self._bootstrap_retry_done: bool = False
        self._container_name: str = f"mcp-analyzer-{uuid.uuid4().hex[:12]}"
        self._workspace_dir: str = str(Path.cwd().resolve())
        # Sidecar lifecycle state: backend services declared by recipes.
        # When non-empty the MCP server runs on a private docker network so
        # sidecars are reachable by their alias and the host is not.
        self._network_name: str | None = None
        self._sidecar_containers: list[str] = []
        # IPs of running sidecar containers, fetched after each one starts.
        # Used by analysis-phase scanners (R1) to recognise legitimate sidecar
        # traffic and skip the RFC1918-as-SSRF heuristic for these addresses.
        self._sidecar_ips: list[str] = []

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
    def sidecar_ips(self) -> tuple[str, ...]:
        """IPs of running sidecar containers on the private network.

        Populated as each sidecar starts in ``_start_sidecars``. Empty in
        non-sidecar mode. Analysis-phase code uses this to distinguish
        legitimate sidecar traffic from real SSRF attempts at RFC1918 IPs.
        """
        return tuple(self._sidecar_ips)

    @property
    def has_sidecars(self) -> bool:
        """True when the sandbox is attached to a private sidecar network.

        On a sidecar-mode (``--internal``) network, every connection observed
        by netmon is intra-network — host traffic and external traffic are
        blocked at the network layer and never appear. NetworkMonitor's
        RFC1918 'block_internal' heuristic should be disabled in this mode
        so legitimate sidecar traffic isn't misreported as SSRF.
        """
        return self._network_name is not None and bool(self._sidecar_containers)

    @property
    def http_base_url(self) -> str | None:
        """Local base URL to reach the target HTTP transport server."""
        if self._server.transport != "http" or not self._server.http_port:
            return None
        return f"http://127.0.0.1:{self._server.http_port}"

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        if self._use_docker:
            await self._prepare_bootstrap_image()
            await self._start_sidecars()
            cmd = self._build_docker_cmd()
        else:
            cmd = self._build_local_cmd()

        await self._spawn_process(cmd)

        # Give the server a moment to start; an immediate exit is a hard failure.
        await asyncio.sleep(0.3)
        if self._proc is not None and self._proc.returncode is not None:
            stderr = self._collected_stderr()
            if self._use_docker and not self._bootstrap_retry_done:
                self._bootstrap_retry_done = True
                if await self._retry_bootstrap_from_stderr(stderr):
                    return  # retry succeeded
            raise RuntimeError(
                f"Server process exited immediately (rc={self._proc.returncode}). "
                f"stderr: {stderr or '(empty)'}"
            )

    async def _spawn_process(self, cmd: list[str]) -> None:
        """Spawn a new subprocess and reset stderr collection buffer."""
        self._stderr_lines = []
        log.info("sandbox.start", cmd=" ".join(cmd))
        self._proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=2 ** 23,
        )
        log.info("sandbox.spawned", pid=self._proc.pid, use_docker=self._use_docker)
        self._stderr_task = asyncio.create_task(
            self._drain_stderr(), name="sandbox-stderr"
        )

    async def _drain_stderr(self) -> None:
        """Read stderr line-by-line: log it and collect into _stderr_lines."""
        assert self._proc is not None and self._proc.stderr is not None
        try:
            while True:
                line = await self._proc.stderr.readline()
                if not line:
                    break
                text = line.decode(errors="replace").rstrip()
                if text:
                    self._stderr_lines.append(text)
                    log.warning("sandbox.server_stderr", msg=text)
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("sandbox.stderr_drain_error")

    def _collected_stderr(self, max_lines: int = 100) -> str:
        """Return buffered stderr lines as a single string."""
        return "\n".join(self._stderr_lines[:max_lines])

    async def _read_stderr_snippet(self, max_bytes: int = 2048) -> str:
        """Compat shim — returns buffered stderr (does not read the pipe)."""
        return self._collected_stderr()

    async def _cancel_stderr_drain(self) -> None:
        task = self._stderr_task
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    # -- bootstrap retry -----------------------------------------------------

    async def _retry_bootstrap_from_stderr(self, stderr: str) -> bool:
        """Analyse stderr, build a patched image, and respawn once."""
        if not stderr:
            return False

        runtime = self._resolve_runtime()
        current_ids: set[str] = {
            a.action_id for a in (self._bootstrap_plan.actions if self._bootstrap_plan else [])
        }

        # Layer 1: recipe matching on stderr tokens
        new_plan = plan_bootstrap(
            self._server, runtime,
            evidence=self._preflight_evidence,
            stderr_snippet=stderr,
        )

        # Layer 2: dynamic heuristics
        dynamic_pkgs = _apt_packages_from_stderr(stderr)

        extra_lines: list[str] = []
        extra_env: dict[str, str] = {}
        new_ids: list[str] = []

        if new_plan:
            for action in new_plan.actions:
                if action.action_id not in current_ids:
                    extra_lines.extend(action.dockerfile_lines)
                    extra_env.update(dict(action.env))
                    new_ids.append(action.action_id)

        if dynamic_pkgs:
            pkgs_str = " ".join(dynamic_pkgs)
            extra_lines += [
                "USER root",
                (
                    f"RUN apt-get update && apt-get install -y --no-install-recommends"
                    f" {pkgs_str} && rm -rf /var/lib/apt/lists/*"
                ),
                "USER user",
            ]
            new_ids.append("dynamic:" + "+".join(dynamic_pkgs[:5]))

        if not extra_lines:
            log.debug(
                "sandbox.bootstrap.retry_skip",
                reason="stderr analysis produced no new installation steps",
                stderr_hint=stderr[:300],
            )
            return False

        base_image = self._bootstrap_image or runtime.image
        new_image = await self._build_dynamic_image(base_image, extra_lines, extra_env, new_ids)
        if new_image is None:
            return False

        self._bootstrap_image = new_image

        # Kill the failed process cleanly before respawning.
        await self._cancel_stderr_drain()
        if self._proc is not None and self._proc.returncode is None:
            self._proc.kill()
            await self._proc.wait()

        cmd = self._build_docker_cmd()
        log.info(
            "sandbox.bootstrap.retry",
            image=new_image,
            new_actions=new_ids,
            stderr_hint=stderr[:200],
        )
        await self._spawn_process(cmd)
        await asyncio.sleep(0.3)

        if self._proc is not None and self._proc.returncode is not None:
            raise RuntimeError(
                f"Server exited again after bootstrap retry (rc={self._proc.returncode}). "
                f"stderr: {self._collected_stderr()}"
            )

        return True

    async def _build_dynamic_image(
        self,
        base_image: str,
        dockerfile_lines: list[str],
        env: dict[str, str],
        action_ids: list[str],
    ) -> str | None:
        """Build a Dockerfile extending *base_image* and return the image tag."""
        content = base_image + "|" + "\n".join(dockerfile_lines)
        digest = hashlib.sha256(content.encode()).hexdigest()[:12]
        image_name = f"{base_image}-retry-{digest}"

        if await self._docker_image_exists(image_name):
            log.info("sandbox.bootstrap.retry_cached", image=image_name)
            return image_name

        lines = [f"FROM {base_image}", *dockerfile_lines]
        for k, v in env.items():
            lines.append(f"ENV {k}={v}")
        dockerfile = "\n".join(lines) + "\n"

        build_dir = Path(tempfile.mkdtemp(prefix="mcp-retry-"))
        (build_dir / "Dockerfile").write_text(dockerfile, encoding="utf-8")

        log.info(
            "sandbox.bootstrap.retry_build",
            image=image_name,
            base_image=base_image,
            actions=action_ids,
        )
        proc = await asyncio.create_subprocess_exec(
            "docker", "build", "-t", image_name, str(build_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, build_stderr = await proc.communicate()
        shutil.rmtree(build_dir, ignore_errors=True)

        if proc.returncode != 0:
            log.warning(
                "sandbox.bootstrap.retry_build_failed",
                image=image_name,
                rc=proc.returncode,
                stderr=build_stderr.decode(errors="replace")[-600:],
            )
            return None

        log.info("sandbox.bootstrap.retry_ready", image=image_name)
        return image_name

    # -- stop / context manager ----------------------------------------------

    async def stop(self) -> None:
        if self._proc is None:
            return
        await self._cancel_stderr_drain()

        if self._proc.returncode is None:
            self._proc.terminate()
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                log.warning("sandbox.kill_fallback", pid=self._proc.pid)
                self._proc.kill()
                await self._proc.wait()

        rc = self._proc.returncode
        if rc not in (0, -15, -9, None):
            log.warning(
                "sandbox.abnormal_exit",
                pid=self._proc.pid,
                rc=rc,
                hint="Non-zero exit may indicate a startup failure or crash.",
            )
        else:
            log.info("sandbox.stop", pid=self._proc.pid, rc=rc)

        await self._stop_sidecars()

    async def __aenter__(self) -> Sandbox:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()

    # -- command builders ----------------------------------------------------

    def _merged_env(self) -> dict[str, str]:
        env = merged_bootstrap_env(self._bootstrap_plan)
        env.update(self._server.env)
        if self._env_override:
            env.update(self._env_override)
        # Sidecar recipes own the connection endpoint — their env wins over
        # any user value to ensure the sandboxed server cannot retain a
        # production connection string discovered from the host config.
        if self._bootstrap_plan is not None:
            forced = self._bootstrap_plan.forced_runtime_env
            for key, value in forced.items():
                prior = env.get(key)
                if prior is not None and prior != value:
                    log.warning(
                        "sandbox.env_redirected_to_sidecar",
                        key=key,
                        original=_redact_secrets_in_uri(prior),
                        replacement=value,
                        reason="User env carried a connection string; redirected to ephemeral sidecar.",
                    )
                env[key] = value
        return env

    def _resolve_runtime(self) -> ResolvedRuntime:
        """Resolve and cache the runtime profile for this sandbox."""
        if self._resolved is None:
            self._resolved = self._resolver.resolve(self._server)
            log.info(
                "sandbox.runtime_resolved",
                selected=(
                    f"{self._server.command} -> {self._resolved.image} "
                    f"({self._resolved.reason})"
                ),
                image=self._resolved.image,
                command=self._resolved.command,
                reason=self._resolved.reason,
            )
        return self._resolved

    @staticmethod
    def _host_mount_source(path: str) -> str:
        p = Path(path).resolve()
        return str(p).replace("\\", "/")

    @classmethod
    def _guess_mount_root(cls, path: Path) -> Path:
        resolved = path.resolve()
        start = resolved if resolved.is_dir() else resolved.parent
        for candidate in [start, *list(start.parents)[:_MAX_PROJECT_ROOT_ASCENT]]:
            if any((candidate / marker).exists() for marker in _PROJECT_ROOT_MARKERS):
                return candidate
        return start

    def _build_docker_cmd(self) -> list[str]:
        sb = self._sandbox
        net = sb.network

        runtime = self._resolve_runtime()
        server_cmd = runtime.command
        image = self._bootstrap_image or runtime.image

        # Apply recipe-driven arg rewrites first so that subsequent path-mount
        # logic doesn't try to mount a freshly-redirected connection string.
        rewritten_args = self._apply_arg_rewrites(list(self._server.args))

        extra_mounts: dict[str, str] = {}
        remapped_args: list[str] = []
        for arg in rewritten_args:
            p = Path(arg)
            if p.is_absolute() and p.exists():
                resolved = p.resolve()
                mount_root = self._guess_mount_root(resolved)
                host_dir = self._host_mount_source(str(mount_root))
                if host_dir not in extra_mounts:
                    extra_mounts[host_dir] = f"/mcp-server-{len(extra_mounts)}"
                rel_path = resolved.relative_to(mount_root)
                container_path = str(
                    PurePosixPath(extra_mounts[host_dir], *rel_path.parts)
                )
                log.info(
                    "sandbox.arg_remapped",
                    original=arg,
                    container=container_path,
                    mount_root=str(mount_root),
                    reason="Absolute host path remapped to a project-root mount.",
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
            "--pids-limit", "512",
        ]

        cmd_basename = Path(self._server.command.replace("\\", "/")).name.lower()
        is_package_runner = cmd_basename in _PACKAGE_RUNNERS

        if sb.isolation == "strict":
            # Package runners install a venv + dep cache on first invocation;
            # 100 MB tmpfs is too tight for typical python servers (psycopg2,
            # mcp-sdk, etc.) and forces uv to fail with ENOSPC.
            tmpfs_size = "512m" if is_package_runner else "100m"
            cmd += [
                "--read-only",
                "--tmpfs", f"/tmp:size={tmpfs_size}",
                "--security-opt", "no-new-privileges",
                "--cap-drop", "ALL",
            ]
            if self._sysmon_enabled:
                cmd += ["--cap-add", "SYS_PTRACE"]
        else:
            cmd += [
                "--cap-add", "ALL",
                "--security-opt", "seccomp=unconfined",
                "--security-opt", "apparmor=unconfined",
            ]

        if self._network_name is not None:
            # Sidecars have already been launched on this private network;
            # joining it makes them reachable by alias and isolates the MCP
            # server from the host's bridge network entirely.
            cmd += ["--network", self._network_name]
        elif net.mode == "none":
            cmd += ["--network", "none"]
        elif net.mode == "allowlist":
            cmd += ["--network", "bridge"]

        merged_env = self._merged_env()
        for key in merged_env:
            if _SECRET_KEY_RE.search(key):
                log.warning(
                    "sandbox.env_secret_exposure",
                    key=key,
                    hint=(
                        "This env var may contain a secret and will be visible "
                        "to the container. Remove it from server.env if not required."
                    ),
                )
        for key, val in merged_env.items():
            cmd += ["-e", f"{key}={val}"]

        if self._honeypot_dir:
            honeypot_src = self._host_mount_source(self._honeypot_dir)
            cmd += ["-v", f"{honeypot_src}:/home/user:rw"]

        needs_host_workspace = bool(extra_mounts) or not is_package_runner
        if needs_host_workspace:
            ws_src = self._host_mount_source(self._workspace_dir)
            ws_mode = "rw" if sb.isolation == "permissive" else "ro"
            cmd += ["-v", f"{ws_src}:/workspace:{ws_mode}"]
            cmd += ["-w", "/workspace"]
        else:
            # Package runners (uv/uvx/npx/...) write a lockfile and possibly
            # a venv to cwd. /tmp is already a writable tmpfs in strict mode.
            cmd += ["-w", "/tmp"]
            # uv / pip read HOME for cache & config; pin them inside the
            # writable tmpfs so they don't blow up on /root being read-only.
            if "HOME" not in merged_env:
                cmd += ["-e", "HOME=/tmp"]
            if "XDG_CACHE_HOME" not in merged_env:
                cmd += ["-e", "XDG_CACHE_HOME=/tmp/.cache"]

        for host_dir, container_dir in extra_mounts.items():
            cmd += ["-v", f"{host_dir}:{container_dir}:ro"]

        if self._server.transport == "http" and self._server.http_port:
            cmd += ["-p", f"127.0.0.1:{self._server.http_port}:{self._server.http_port}/tcp"]

        cmd.append(image)
        cmd.append(server_cmd)
        cmd += remapped_args

        return cmd

    async def _prepare_bootstrap_image(self) -> None:
        """Build a prerequisite-augmented image when the server requires it."""
        if not self._use_docker:
            self._preflight_evidence = None
            self._bootstrap_plan = None
            self._bootstrap_image = None
            return

        runtime = self._resolve_runtime()
        assert self._preflight is not None
        evidence = await self._preflight.inspect(
            self._server,
            runtime,
            network_mode=self._sandbox.network.mode,
        )
        self._preflight_evidence = evidence
        if evidence is not None:
            log.info(
                "sandbox.preflight_resolved",
                source=evidence.source,
                manifest=evidence.manifest_path,
                package=evidence.package_name,
                version=evidence.package_version,
                node_dependencies=[name for name, _ in evidence.node_dependencies],
                python_dependencies=list(evidence.python_dependencies),
                source_signals=list(evidence.source_signals),
            )

        plan = plan_bootstrap(self._server, runtime, evidence=evidence)
        self._bootstrap_plan = plan
        if plan is None:
            return

        if not plan.has_image_changes:
            # Sidecar-only plan: no Dockerfile prerequisites to layer onto the
            # base image. Env vars from the recipe still flow through
            # ``merged_bootstrap_env`` at run-time via docker -e flags.
            self._bootstrap_image = None
            log.info(
                "sandbox.bootstrap.runtime_only",
                base_image=runtime.image,
                actions=[a.action_id for a in plan.actions],
                reason=plan.reason,
            )
            return

        target_image = plan.image_tag(runtime.image)
        self._bootstrap_image = target_image
        if await self._docker_image_exists(target_image):
            log.info(
                "sandbox.bootstrap.cached",
                image=target_image,
                base_image=runtime.image,
                actions=[a.action_id for a in plan.actions],
                reason=plan.reason,
            )
            return

        build_dir = Path(tempfile.mkdtemp(prefix="mcp-bootstrap-"))
        dockerfile_path = build_dir / "Dockerfile"
        dockerfile_path.write_text(
            render_bootstrap_dockerfile(runtime.image, plan),
            encoding="utf-8",
        )

        log.info(
            "sandbox.bootstrap.start",
            image=target_image,
            base_image=runtime.image,
            actions=[a.action_id for a in plan.actions],
            reason=plan.reason,
        )

        proc = await asyncio.create_subprocess_exec(
            "docker", "build", "-t", target_image, str(build_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        shutil.rmtree(build_dir, ignore_errors=True)

        if proc.returncode != 0:
            self._bootstrap_image = None
            log.warning(
                "sandbox.bootstrap.failed",
                image=target_image,
                base_image=runtime.image,
                rc=proc.returncode,
                stdout=stdout.decode(errors="replace")[-400:],
                stderr=stderr.decode(errors="replace")[-800:],
                hint="Continuing with the base sandbox image.",
            )
            return

        log.info(
            "sandbox.bootstrap.ready",
            image=target_image,
            base_image=runtime.image,
            actions=[a.action_id for a in plan.actions],
        )

    async def _docker_image_exists(self, image: str) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "docker", "image", "inspect", image,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        rc = await proc.wait()
        return rc == 0

    def _build_local_cmd(self) -> list[str]:
        """Direct subprocess — no Docker isolation."""
        return [self._server.command, *self._server.args]

    # -- sidecar lifecycle ---------------------------------------------------

    def _apply_arg_rewrites(self, args: list[str]) -> list[str]:
        """Replace user-provided connection strings with sidecar-local URIs.

        Recipe-defined regex/replacement pairs run before path-based mount
        remapping so the MCP server cannot retain a reference to host
        databases or services even when the user's discovered config carries
        real credentials.
        """
        if self._bootstrap_plan is None:
            return args
        rewrites = self._bootstrap_plan.arg_rewrites
        if not rewrites:
            return args
        out: list[str] = []
        for arg in args:
            new_arg = arg
            for rule in rewrites:
                try:
                    rewritten = re.sub(rule.pattern, rule.replacement, new_arg)
                except re.error as exc:
                    log.warning(
                        "sandbox.arg_rewrite_invalid",
                        pattern=rule.pattern,
                        error=str(exc),
                    )
                    continue
                if rewritten != new_arg:
                    log.warning(
                        "sandbox.arg_rewritten",
                        original=_redact_secrets_in_uri(arg),
                        rewritten=rewritten,
                        reason="Recipe redirected arg to ephemeral sidecar.",
                    )
                    new_arg = rewritten
            out.append(new_arg)
        return out

    async def _start_sidecars(self) -> None:
        """Boot any sidecar services declared by matched recipes.

        Creates a private docker network so MCP server ↔ sidecar traffic stays
        within the sandbox and the host bridge isn't reachable from the MCP
        server. Each sidecar joins the network with ``--network-alias`` set to
        the recipe's alias so the MCP server can dial it as ``alias:port``.
        """
        if self._bootstrap_plan is None:
            return
        services = self._bootstrap_plan.services
        if not services:
            return

        network_name = f"mcp-net-{uuid.uuid4().hex[:12]}"
        # ``--internal`` blocks routing between this network and the host /
        # outside world: only containers attached to the network can talk to
        # each other. Without this, Docker's default bridge driver lets the
        # MCP server reach ``host.docker.internal`` and the host's actual
        # database — defeating the entire point of the sidecar redirect.
        rc = await self._run_docker(["network", "create", "--internal", network_name])
        if rc != 0:
            log.error(
                "sandbox.sidecar.network_create_failed",
                network=network_name,
                hint="Sidecar services unavailable; MCP server may fail to connect.",
            )
            return
        self._network_name = network_name
        log.info(
            "sandbox.sidecar.network_created",
            network=network_name,
            isolation="internal (host unreachable)",
        )

        for svc in services:
            container = f"mcp-svc-{svc.alias}-{uuid.uuid4().hex[:8]}"
            cmd = [
                "docker", "run", "-d", "--rm",
                "--name", container,
                "--network", network_name,
                "--network-alias", svc.alias,
            ]
            for k, v in svc.env:
                cmd += ["-e", f"{k}={v}"]
            cmd.append(svc.image)

            log.info(
                "sandbox.sidecar.start",
                alias=svc.alias,
                image=svc.image,
                container=container,
            )
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                log.error(
                    "sandbox.sidecar.start_failed",
                    alias=svc.alias,
                    image=svc.image,
                    stderr=stderr.decode(errors="replace")[-400:],
                )
                continue
            self._sidecar_containers.append(container)

            if svc.health_cmd:
                ok = await self._wait_for_sidecar_health(
                    container, svc.health_cmd, svc.startup_timeout_sec,
                )
                if not ok:
                    log.warning(
                        "sandbox.sidecar.unhealthy",
                        alias=svc.alias,
                        container=container,
                        timeout=svc.startup_timeout_sec,
                        hint="MCP server may receive connection errors from this sidecar.",
                    )

            ip = await self._inspect_sidecar_ip(container, network_name)
            if ip:
                self._sidecar_ips.append(ip)
                log.info(
                    "sandbox.sidecar.ip_resolved",
                    alias=svc.alias,
                    container=container,
                    ip=ip,
                )

    async def _inspect_sidecar_ip(self, container: str, network: str) -> str | None:
        """Return the sidecar container's IP on *network*, or None on failure.

        The network name contains dashes, which Go templates can't handle as
        map field accessors (``.Foo.bar-baz`` is parsed as ``.Foo.bar`` minus
        ``baz``). Use ``index`` with the quoted key instead.
        """
        fmt = (
            '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
        )
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", "--format", fmt, container,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        except asyncio.TimeoutError:
            return None
        if proc.returncode != 0:
            return None
        ip = stdout.decode(errors="replace").strip()
        return ip or None

    async def _wait_for_sidecar_health(
        self, container: str, health_cmd: tuple[str, ...], timeout_sec: float,
    ) -> bool:
        """Poll ``docker exec <container> <health_cmd>`` until it succeeds."""
        deadline = asyncio.get_event_loop().time() + timeout_sec
        attempt = 0
        while asyncio.get_event_loop().time() < deadline:
            attempt += 1
            rc = await self._run_docker(
                ["exec", container, *health_cmd],
                quiet=True,
            )
            if rc == 0:
                log.info(
                    "sandbox.sidecar.healthy",
                    container=container,
                    attempt=attempt,
                )
                return True
            await asyncio.sleep(1.0)
        return False

    async def _stop_sidecars(self) -> None:
        """Kill sidecar containers and remove the private network."""
        for container in self._sidecar_containers:
            await self._run_docker(["kill", container], quiet=True)
        self._sidecar_containers.clear()
        self._sidecar_ips.clear()
        if self._network_name is not None:
            # Containers were started with --rm so the network is empty after
            # the kills land. A short delay avoids "network has active endpoints".
            await asyncio.sleep(0.3)
            rc = await self._run_docker(
                ["network", "rm", self._network_name],
                quiet=True,
            )
            if rc != 0:
                log.warning(
                    "sandbox.sidecar.network_rm_failed",
                    network=self._network_name,
                )
            self._network_name = None

    async def _run_docker(self, args: list[str], *, quiet: bool = False) -> int:
        proc = await asyncio.create_subprocess_exec(
            "docker", *args,
            stdout=asyncio.subprocess.DEVNULL if quiet else asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL if quiet else asyncio.subprocess.PIPE,
        )
        return await proc.wait()


def _redact_secrets_in_uri(arg: str) -> str:
    """Mask user:pass in URIs before logging the original arg value.

    Handles ``scheme://user:pass@host`` and Redis-style ``scheme://:pass@host``
    (empty username) so the password never reaches the log line.
    """
    return re.sub(
        r"(\w+://)[^@/\s]*:[^@/\s]+@",
        r"\1***:***@",
        arg,
    )
