"""Tests for sandbox command construction."""

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

