"""Pick the right sandbox runtime profile for a given MCP server.

Given a :class:`ServerConfig` (the ``command``/``args`` the user wants to run),
:class:`RuntimeResolver` decides which pre-built Docker image from
``docker/profiles/`` to use and normalises the command so it resolves inside
that image. This replaces the old "one fat image + best-effort command remap"
approach in :mod:`mcp_dynamic_analyzer.infrastructure.sandbox`.

Resolution order:

1. **Explicit override** — ``ServerConfig.env["MCP_SANDBOX_PROFILE"]`` wins.
2. **Command shape** — ``npx``/``node`` → node profile; ``uv``/``uvx``/
   ``python*`` → python profile.
3. **Manifest sniffing** — if an absolute path in ``args`` points into a repo
   containing ``package.json`` with ``engines.node`` or ``pyproject.toml`` with
   ``requires-python``, use the declared version.
4. **Fallback** — ``polyglot``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import structlog

from mcp_dynamic_analyzer.config import ServerConfig

log = structlog.get_logger()


# Supported profile tags. The name is both the docker image suffix
# (``mcp-sandbox-<name>``) and the directory under ``docker/profiles/``.
NODE_PROFILES = ("node20", "node22")
PYTHON_PROFILES = ("python311", "python312")
POLYGLOT = "polyglot"
DEFAULT_NODE = "node22"
DEFAULT_PYTHON = "python312"


@dataclass(frozen=True)
class ResolvedRuntime:
    """Outcome of :meth:`RuntimeResolver.resolve`.

    Attributes:
        image: Docker image tag to run (e.g. ``mcp-sandbox-node22``).
        command: The binary to exec inside the container. Already normalised
            away from host-absolute paths (``/Users/.../python3`` → ``python3``).
        reason: Short human-readable explanation of why this profile was chosen.
            Surfaced in structured logs so operators can audit resolver decisions.
    """

    image: str
    command: str
    reason: str


# ---------------------------------------------------------------------------
# Command classification
# ---------------------------------------------------------------------------

_NODE_COMMANDS = {"node", "nodejs", "npx", "npm", "pnpm", "pnpx", "yarn", "bunx", "bun"}
_PY_COMMANDS = {
    "python", "python3",
    "python3.10", "python3.11", "python3.12", "python3.13",
    "uv", "uvx", "pipx", "poetry",
}

# e.g. "python3.11" -> "311"
_PY_VERSION_RE = re.compile(r"^python3\.(\d+)$")


def _basename(cmd: str) -> str:
    """Return the final path component. Handles both POSIX and Windows paths."""
    # Path(...).name on POSIX doesn't split on ``\``, so normalise first.
    return Path(cmd.replace("\\", "/")).name


def _classify_command(cmd: str) -> str | None:
    """Return ``"node"``, ``"python"``, or ``None`` based on a raw command string."""
    base = _basename(cmd).lower()
    if base in _NODE_COMMANDS:
        return "node"
    if base in _PY_COMMANDS or _PY_VERSION_RE.match(base):
        return "python"
    return None


def _python_version_from_command(cmd: str) -> str | None:
    """Map ``python3.11`` → ``python311``. Returns None for generic ``python3``."""
    m = _PY_VERSION_RE.match(_basename(cmd).lower())
    if not m:
        return None
    minor = m.group(1)
    candidate = f"python3{minor}"
    return candidate if candidate in PYTHON_PROFILES else None


# ---------------------------------------------------------------------------
# Manifest sniffing
# ---------------------------------------------------------------------------

def _find_manifest_dir(args: list[str]) -> Path | None:
    """Walk upward from any absolute path in *args* looking for a project root.

    We try each absolute path in ``args`` in turn so that the resolver works
    both for ``python /abs/path/server.py`` and for ``--server-path /abs/...``
    style invocations. Bounded upward walk (5 levels) to avoid scanning
    the whole filesystem when args point deep into site-packages.
    """
    for raw in args:
        p = Path(raw)
        if not p.is_absolute() or not p.exists():
            continue
        start = p if p.is_dir() else p.parent
        for candidate in [start, *list(start.parents)[:5]]:
            if (candidate / "package.json").exists() or (candidate / "pyproject.toml").exists():
                return candidate
    return None


def _node_profile_from_manifest(manifest_dir: Path) -> str | None:
    """Parse ``engines.node`` from ``package.json`` and pick a profile."""
    pkg = manifest_dir / "package.json"
    if not pkg.exists():
        return None
    try:
        import json
        data = json.loads(pkg.read_text())
    except (OSError, ValueError):
        return None
    engines = (data.get("engines") or {}).get("node", "")
    # engines.node is a semver range; we only care about the major floor.
    m = re.search(r"(\d+)", engines)
    if not m:
        return None
    major = int(m.group(1))
    if major <= 20:
        return "node20"
    return "node22"


def _python_profile_from_manifest(manifest_dir: Path) -> str | None:
    """Parse ``requires-python`` from ``pyproject.toml``."""
    py = manifest_dir / "pyproject.toml"
    if not py.exists():
        return None
    try:
        # tomllib is stdlib on 3.11+; this package already targets 3.12.
        import tomllib
        data = tomllib.loads(py.read_text())
    except (OSError, ValueError, ImportError):
        return None
    req = (data.get("project") or {}).get("requires-python", "")
    m = re.search(r"3\.(\d+)", req)
    if not m:
        return None
    minor = int(m.group(1))
    if minor <= 11:
        return "python311"
    return "python312"


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

class RuntimeResolver:
    """Resolve ``ServerConfig`` → ``ResolvedRuntime``.

    Pure function wrapped in a class so callers can inject a custom resolver
    in tests.
    """

    _OVERRIDE_ENV = "MCP_SANDBOX_PROFILE"

    def resolve(self, server: ServerConfig) -> ResolvedRuntime:
        # 1. Explicit override via env var — escape hatch for users who know
        #    their server needs a specific profile we can't auto-detect.
        override = server.env.get(self._OVERRIDE_ENV)
        if override:
            image = f"mcp-sandbox-{override}"
            cmd = self._normalise_command(server.command, override)
            return ResolvedRuntime(
                image=image,
                command=cmd,
                reason=f"explicit override via {self._OVERRIDE_ENV}={override}",
            )

        kind = _classify_command(server.command)
        manifest_dir = _find_manifest_dir(server.args)

        # 2a. Node family.
        if kind == "node":
            profile = (
                _node_profile_from_manifest(manifest_dir) if manifest_dir else None
            ) or DEFAULT_NODE
            return ResolvedRuntime(
                image=f"mcp-sandbox-{profile}",
                command=self._normalise_command(server.command, profile),
                reason=f"node command '{_basename(server.command)}' → {profile}",
            )

        # 2b. Python family: prefer explicit python3.X in command, then manifest.
        if kind == "python":
            profile = (
                _python_version_from_command(server.command)
                or (_python_profile_from_manifest(manifest_dir) if manifest_dir else None)
                or DEFAULT_PYTHON
            )
            return ResolvedRuntime(
                image=f"mcp-sandbox-{profile}",
                command=self._normalise_command(server.command, profile),
                reason=f"python command '{_basename(server.command)}' → {profile}",
            )

        # 3. Manifest sniffing even when the command itself is ambiguous
        #    (e.g. a shell wrapper). Python manifest wins if both exist because
        #    python MCP servers more often ship with a wrapper script.
        if manifest_dir is not None:
            py_profile = _python_profile_from_manifest(manifest_dir)
            if py_profile:
                return ResolvedRuntime(
                    image=f"mcp-sandbox-{py_profile}",
                    command=server.command,
                    reason=f"pyproject.toml at {manifest_dir} → {py_profile}",
                )
            node_profile = _node_profile_from_manifest(manifest_dir)
            if node_profile:
                return ResolvedRuntime(
                    image=f"mcp-sandbox-{node_profile}",
                    command=server.command,
                    reason=f"package.json at {manifest_dir} → {node_profile}",
                )

        # 4. Fallback.
        log.warning(
            "runtime_resolver.fallback",
            command=server.command,
            hint="Could not infer runtime; using polyglot image.",
        )
        return ResolvedRuntime(
            image=f"mcp-sandbox-{POLYGLOT}",
            command=server.command,
            reason="no runtime signal from command or manifests",
        )

    # -- command normalisation ----------------------------------------------

    def _normalise_command(self, cmd: str, profile: str) -> str:
        """Rewrite a host command so it resolves inside *profile*'s image.

        Absolute host paths (``/Users/woojin/.venv/bin/python3``) can't exist
        inside the container, so we strip them to a basename the image's
        ``$PATH`` provides. Version-specific aliases collapse to the image's
        canonical binary name.
        """
        base = _basename(cmd)
        # Absolute host path: replace with basename, which must exist in the
        # target image's PATH. We accept a small risk here that the basename
        # doesn't match (e.g. obscure launcher scripts) — the caller will see
        # a clear "command not found" in sandbox stderr.
        if Path(cmd).is_absolute() or "\\" in cmd:
            cmd = base

        if profile.startswith("node"):
            if base in {"nodejs"}:
                return "node"
            return cmd

        if profile.startswith("python"):
            # All python aliases collapse to the image's default `python3`.
            if base == "python" or _PY_VERSION_RE.match(base.lower()):
                return "python3"
            return cmd

        return cmd
