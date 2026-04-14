"""Discover MCP servers already configured on the local machine.

Instead of asking the user to type raw ``npx ...`` commands, we scan the
well-known configuration files used by MCP clients (Claude Desktop, Claude
Code, Cursor, VSCode) and surface every declared server as a
:class:`DiscoveredServer`. The CLI then lets the user pick one by name.

All parsers are best-effort: a missing or malformed file is silently skipped
rather than raising, because most users only have one or two clients
installed.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import structlog

from mcp_dynamic_analyzer.config import ServerConfig

log = structlog.get_logger()


@dataclass(frozen=True)
class DiscoveredServer:
    """One MCP server definition found in a local config file.

    Attributes:
        name: Logical name as declared in the source config (the key under
            ``mcpServers``). Not guaranteed unique across sources.
        source: Human-readable origin tag, e.g. ``claude-desktop`` or
            ``cursor``.
        source_path: Absolute path to the config file we parsed.
        server: ``ServerConfig`` ready to hand to ``run_analysis``.
    """

    name: str
    source: str
    source_path: Path
    server: ServerConfig


# ---------------------------------------------------------------------------
# Per-source config paths
# ---------------------------------------------------------------------------

def _claude_desktop_paths() -> list[Path]:
    """Cross-platform Claude Desktop config locations."""
    home = Path.home()
    if sys.platform == "darwin":
        return [home / "Library/Application Support/Claude/claude_desktop_config.json"]
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            return [Path(appdata) / "Claude" / "claude_desktop_config.json"]
        return []
    # Linux / other POSIX: respect XDG_CONFIG_HOME if set.
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else home / ".config"
    return [base / "Claude" / "claude_desktop_config.json"]


def _claude_code_paths() -> list[Path]:
    home = Path.home()
    candidates = [
        home / ".claude.json",
        home / ".claude" / "settings.json",
        Path.cwd() / ".claude" / "settings.json",
    ]
    return candidates


def _cursor_paths() -> list[Path]:
    return [Path.home() / ".cursor" / "mcp.json"]


def _vscode_paths() -> list[Path]:
    return [
        Path.home() / ".vscode" / "mcp.json",
        Path.cwd() / ".vscode" / "mcp.json",
    ]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> dict | None:
    """Read *path* as JSON. Returns None on any failure."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        log.warning("discovery.parse_failed", path=str(path), error=str(exc))
        return None


def _extract_mcp_servers(data: dict) -> dict:
    """Return the ``mcpServers`` mapping from *data*, searching common keys.

    The canonical key is ``mcpServers`` but some VSCode variants nest it under
    ``mcp.servers``. We check both so the caller gets a uniform shape.
    """
    if "mcpServers" in data and isinstance(data["mcpServers"], dict):
        return data["mcpServers"]
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return mcp["servers"]
    return {}


def _to_server_config(entry: dict) -> ServerConfig | None:
    """Convert one raw ``mcpServers`` entry to our ``ServerConfig``.

    Returns None for entries that lack an executable command (e.g. pure
    transport-url entries we can't launch ourselves). Those are legitimate in
    remote-SSE setups but not useful for dynamic analysis, which needs to
    spawn the server locally.
    """
    command = entry.get("command")
    if not command or not isinstance(command, str):
        return None
    args = entry.get("args") or []
    env = entry.get("env") or {}
    if not isinstance(args, list) or not isinstance(env, dict):
        return None
    # Coerce env values to strings — some configs store ints/bools.
    env_str = {str(k): str(v) for k, v in env.items()}
    return ServerConfig(
        command=command,
        args=[str(a) for a in args],
        env=env_str,
        transport="stdio",
    )


def _parse_source(source: str, paths: list[Path]) -> list[DiscoveredServer]:
    """Run ``_load_json`` + ``_extract_mcp_servers`` for one source."""
    found: list[DiscoveredServer] = []
    for path in paths:
        data = _load_json(path)
        if not data:
            continue
        servers = _extract_mcp_servers(data)
        for name, entry in servers.items():
            if not isinstance(entry, dict):
                continue
            cfg = _to_server_config(entry)
            if cfg is None:
                log.debug(
                    "discovery.skipped_entry",
                    source=source,
                    path=str(path),
                    name=name,
                    reason="missing command or invalid shape (likely remote-only server)",
                )
                continue
            found.append(
                DiscoveredServer(
                    name=name,
                    source=source,
                    source_path=path,
                    server=cfg,
                )
            )
    return found


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def discover_servers() -> list[DiscoveredServer]:
    """Scan all known config locations and return every server we find.

    Ordering is stable (source priority, then config file order) so that
    ``--target <name>`` resolves deterministically when multiple clients
    declare the same logical server. Duplicates across sources are preserved;
    selection logic in the CLI handles disambiguation.
    """
    results: list[DiscoveredServer] = []
    results += _parse_source("claude-desktop", _claude_desktop_paths())
    results += _parse_source("claude-code", _claude_code_paths())
    results += _parse_source("cursor", _cursor_paths())
    results += _parse_source("vscode", _vscode_paths())
    return results


def select_server(
    servers: list[DiscoveredServer],
    target: str,
    source: str | None = None,
) -> DiscoveredServer:
    """Resolve a user-provided target string to one discovered server.

    Matching rules:

    * If *source* is given, restrict candidates to that source first.
    * Exact name match wins.
    * If multiple candidates share the name, raise ``ValueError`` listing
      them so the caller can prompt the user to add ``--source``.
    * If nothing matches, raise ``ValueError`` with a list of valid names.
    """
    pool = [s for s in servers if source is None or s.source == source]
    matches = [s for s in pool if s.name == target]
    if not matches:
        available = ", ".join(sorted({s.name for s in pool})) or "(none)"
        raise ValueError(
            f"No MCP server named '{target}' found"
            f"{' in source ' + source if source else ''}. "
            f"Available: {available}"
        )
    if len(matches) > 1:
        srcs = ", ".join(f"{m.source}" for m in matches)
        raise ValueError(
            f"Multiple servers named '{target}' across sources [{srcs}]. "
            f"Disambiguate with --source <name>."
        )
    return matches[0]
