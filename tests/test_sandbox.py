"""Tests for sandbox command construction."""

from pathlib import Path

from mcp_dynamic_analyzer.config import NetworkConfig, SandboxConfig, ServerConfig
from mcp_dynamic_analyzer.infrastructure.sandbox import Sandbox


def test_build_docker_cmd_network_none_vs_allowlist() -> None:
    server = ServerConfig(command="npx", args=["pkg@latest"])
    none_net = SandboxConfig(network=NetworkConfig(mode="none"))
    allow_net = SandboxConfig(network=NetworkConfig(mode="allowlist"))
    sb_none = Sandbox(server, none_net, honeypot_dir="/tmp/hp")
    sb_allow = Sandbox(server, allow_net, honeypot_dir="/tmp/hp")
    cmd_none = sb_none._build_docker_cmd()
    cmd_allow = sb_allow._build_docker_cmd()
    assert "--network" in cmd_none
    assert cmd_none[cmd_none.index("--network") + 1] == "none"
    assert "--network" in cmd_allow
    assert cmd_allow[cmd_allow.index("--network") + 1] == "bridge"


def test_build_local_cmd_preserves_executable_path_with_spaces() -> None:
    server = ServerConfig(
        command="/Users/test/Integrated Project/.venv/bin/python3",
        args=["/Users/test/my-mcp-server/server.py"],
    )
    sandbox = Sandbox(server, SandboxConfig(), use_docker=False)
    cmd = sandbox._build_local_cmd()
    assert cmd == [
        "/Users/test/Integrated Project/.venv/bin/python3",
        "/Users/test/my-mcp-server/server.py",
    ]


def test_build_docker_cmd_mounts_project_root_for_absolute_server_args(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "notion-mcp-server"
    bin_dir = project_root / "bin"
    scripts_dir = project_root / "scripts"
    bin_dir.mkdir(parents=True)
    scripts_dir.mkdir()
    (project_root / "package.json").write_text("{}")
    cli_path = bin_dir / "cli.mjs"
    cli_path.write_text("console.log('ok')\n")
    (scripts_dir / "notion-openapi.json").write_text("{}\n")

    server = ServerConfig(command="node", args=[str(cli_path)])
    sandbox = Sandbox(server, SandboxConfig())

    cmd = sandbox._build_docker_cmd()

    assert f"{project_root.resolve().as_posix()}:/mcp-server-0:ro" in cmd
    assert "/mcp-server-0/bin/cli.mjs" in cmd
