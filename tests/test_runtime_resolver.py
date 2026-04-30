"""Tests for runtime profile selection."""

from __future__ import annotations

from pathlib import Path

from mcp_dynamic_analyzer.config import ServerConfig
from mcp_dynamic_analyzer.infrastructure.runtime_resolver import RuntimeResolver


def test_resolve_default_node_profile_for_npx_package() -> None:
    resolver = RuntimeResolver()
    resolved = resolver.resolve(
        ServerConfig(command="npx", args=["chrome-devtools-mcp@latest"]),
    )

    assert resolved.image == "mcp-sandbox-node22"
    assert resolved.command == "npx"
    assert "node command" in resolved.reason.lower()


def test_resolve_python_profile_from_manifest(tmp_path: Path) -> None:
    project = tmp_path / "server"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        "[project]\nrequires-python = \">=3.11,<3.12\"\n",
        encoding="utf-8",
    )
    script = project / "server.py"
    script.write_text("print('ok')\n", encoding="utf-8")

    resolver = RuntimeResolver()
    resolved = resolver.resolve(
        ServerConfig(command="python", args=[str(script)]),
    )

    assert resolved.image == "mcp-sandbox-python311"
