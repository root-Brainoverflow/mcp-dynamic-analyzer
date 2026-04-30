"""Tests for prerequisite bootstrap planning."""

from __future__ import annotations

import asyncio

from mcp_dynamic_analyzer.config import SandboxConfig, ServerConfig
from mcp_dynamic_analyzer.infrastructure.bootstrap import (
    PreflightEvidence,
    SourcePreflightInspector,
    merged_bootstrap_env,
    plan_bootstrap,
    render_bootstrap_dockerfile,
)
from mcp_dynamic_analyzer.infrastructure.runtime_resolver import ResolvedRuntime
from mcp_dynamic_analyzer.infrastructure.sandbox import Sandbox


class StubRemoteNodeInspector(SourcePreflightInspector):
    async def _inspect_remote_node(
        self,
        package_spec: str,
    ) -> PreflightEvidence | None:
        assert package_spec == "remote-mcp@latest"
        return PreflightEvidence(
            source="npm-pack:remote-mcp@latest",
            manifest_path="package.json + source archive",
            package_name="remote-mcp",
            package_version="1.4.0",
            node_dependencies=(("playwright", "^1.49.0"),),
        )


def test_local_manifest_inspection_drives_node_playwright_bootstrap(tmp_path) -> None:
    project = tmp_path / "server"
    project.mkdir()
    (project / "package.json").write_text(
        """
        {
          "name": "browser-mcp",
          "version": "0.1.0",
          "dependencies": {
            "playwright": "^1.49.0"
          }
        }
        """,
        encoding="utf-8",
    )
    script = project / "server.js"
    script.write_text("console.log('ok')\n", encoding="utf-8")

    server = ServerConfig(command="node", args=[str(script)])
    runtime = ResolvedRuntime(
        image="mcp-sandbox-node22",
        command="node",
        reason="node command 'node' -> node22",
    )

    evidence = asyncio.run(
        SourcePreflightInspector().inspect(server, runtime, network_mode="none"),
    )
    assert evidence is not None
    assert evidence.source == "local-manifest"
    assert dict(evidence.node_dependencies)["playwright"] == "^1.49.0"

    plan = plan_bootstrap(server, runtime, evidence=evidence)
    assert plan is not None

    dockerfile = render_bootstrap_dockerfile(runtime.image, plan)
    assert "npx -y playwright@1.49.0 install --with-deps chromium" in dockerfile
    assert "ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in dockerfile


def test_remote_npx_package_manifest_can_drive_bootstrap() -> None:
    server = ServerConfig(command="npx", args=["-y", "remote-mcp@latest"])
    runtime = ResolvedRuntime(
        image="mcp-sandbox-node22",
        command="npx",
        reason="node command 'npx' -> node22",
    )

    evidence = asyncio.run(StubRemoteNodeInspector().inspect(server, runtime))
    assert evidence is not None
    assert evidence.source == "npm-pack:remote-mcp@latest"

    plan = plan_bootstrap(server, runtime, evidence=evidence)
    assert plan is not None
    assert "Playwright" in plan.reason


def test_prerelease_playwright_dependency_preserves_full_version() -> None:
    server = ServerConfig(command="npx", args=["@playwright/mcp@latest"])
    runtime = ResolvedRuntime(
        image="mcp-sandbox-node22",
        command="npx",
        reason="node command 'npx' -> node22",
    )
    evidence = PreflightEvidence(
        source="npm-view:@playwright/mcp@latest",
        manifest_path="package.json (registry metadata)",
        package_name="@playwright/mcp",
        package_version="0.0.70",
        node_dependencies=(("playwright", "1.60.0-alpha-1774999321000"),),
    )

    plan = plan_bootstrap(server, runtime, evidence=evidence)
    assert plan is not None

    dockerfile = render_bootstrap_dockerfile(runtime.image, plan)
    assert "npx -y playwright@1.60.0-alpha-1774999321000 install --with-deps chromium" in dockerfile


def test_source_signal_promotes_playwright_to_google_chrome(tmp_path) -> None:
    project = tmp_path / "server"
    project.mkdir()
    (project / "package.json").write_text(
        """
        {
          "name": "browser-mcp",
          "version": "0.1.0",
          "dependencies": {
            "playwright": "^1.49.0"
          }
        }
        """,
        encoding="utf-8",
    )
    script = project / "server.js"
    script.write_text(
        """
        import { chromium } from "playwright";
        await chromium.launch({ channel: "chrome" });
        """,
        encoding="utf-8",
    )

    server = ServerConfig(command="node", args=[str(script)])
    runtime = ResolvedRuntime(
        image="mcp-sandbox-node22",
        command="node",
        reason="node command 'node' -> node22",
    )

    evidence = asyncio.run(
        SourcePreflightInspector().inspect(server, runtime, network_mode="none"),
    )

    assert evidence is not None
    assert "playwright.channel.chrome" in evidence.source_signals

    plan = plan_bootstrap(server, runtime, evidence=evidence)
    assert plan is not None

    dockerfile = render_bootstrap_dockerfile(runtime.image, plan)
    assert "npx -y playwright@1.49.0 install --with-deps chrome" in dockerfile


def test_fallback_playwright_detection_still_works_without_manifest() -> None:
    server = ServerConfig(command="npx", args=["@playwright/mcp@latest"])
    runtime = ResolvedRuntime(
        image="mcp-sandbox-node22",
        command="npx",
        reason="node command 'npx' -> node22",
    )

    plan = plan_bootstrap(server, runtime)

    assert plan is not None
    assert plan.actions[0].action_id.startswith("playwright-node")


def test_python_playwright_dependency_emits_python_hook() -> None:
    server = ServerConfig(command="uvx", args=["some-python-mcp"])
    runtime = ResolvedRuntime(
        image="mcp-sandbox-python312",
        command="uvx",
        reason="python command 'uvx' -> python312",
    )
    evidence = PreflightEvidence(
        source="local-manifest",
        manifest_path="/tmp/pyproject.toml",
        package_name="python-mcp",
        package_version="1.44.1",
        python_dependencies=("playwright",),
    )

    plan = plan_bootstrap(server, runtime, evidence=evidence)
    assert plan is not None

    dockerfile = render_bootstrap_dockerfile(runtime.image, plan)
    assert "python3 -m pip install --no-cache-dir playwright==1.44.1" in dockerfile
    assert "python3 -m playwright install --with-deps chromium" in dockerfile


def test_sandbox_uses_bootstrap_image_and_env() -> None:
    server = ServerConfig(command="npx", args=["@playwright/mcp@latest"])
    sandbox = Sandbox(server, SandboxConfig(), honeypot_dir="/tmp/hp")
    runtime = sandbox._resolve_runtime()
    plan = plan_bootstrap(
        server,
        runtime,
        evidence=PreflightEvidence(
            source="local-manifest",
            manifest_path="/tmp/package.json",
            package_name="browser-mcp",
            package_version="1.49.0",
            node_dependencies=(("playwright", "^1.49.0"),),
        ),
    )
    assert plan is not None

    sandbox._bootstrap_plan = plan
    sandbox._bootstrap_image = plan.image_tag(runtime.image)

    cmd = sandbox._build_docker_cmd()

    assert sandbox._bootstrap_image in cmd
    assert "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright" in cmd
    assert merged_bootstrap_env(plan)["PLAYWRIGHT_BROWSERS_PATH"] == "/ms-playwright"


def test_user_env_overrides_bootstrap_defaults() -> None:
    server = ServerConfig(
        command="npx",
        args=["@playwright/mcp@latest"],
        env={"PLAYWRIGHT_BROWSERS_PATH": "/custom/browsers"},
    )
    sandbox = Sandbox(server, SandboxConfig())
    runtime = sandbox._resolve_runtime()
    plan = plan_bootstrap(
        server,
        runtime,
        evidence=PreflightEvidence(
            source="local-manifest",
            manifest_path="/tmp/package.json",
            package_name="browser-mcp",
            package_version="1.49.0",
            node_dependencies=(("playwright", "^1.49.0"),),
        ),
    )
    assert plan is not None

    sandbox._bootstrap_plan = plan

    assert sandbox._merged_env()["PLAYWRIGHT_BROWSERS_PATH"] == "/custom/browsers"


# ─────────────────────────────────────────────────────────────────────────────
# Sidecar backend services (postgres, mysql, redis, mongodb)
# ─────────────────────────────────────────────────────────────────────────────


def test_postgres_mcp_recipe_stacks_python_install_and_sidecar() -> None:
    """crystaldba-postgres-mcp style: command 'postgres-mcp' as identity token.

    Two recipes fire on a python image:
      • ``postgres-mcp-python-install`` — pip-installs the PyPI package so
        ``uv run postgres-mcp`` finds it on PATH.
      • ``postgres-mcp-sidecar`` — declares the ephemeral postgres backend
        and the env redirect.
    """
    server = ServerConfig(
        command="uv",
        args=["run", "postgres-mcp", "--access-mode=unrestricted"],
    )
    runtime = ResolvedRuntime(image="mcp-sandbox-python312", command="uv", reason="t")

    plan = plan_bootstrap(server, runtime)

    assert plan is not None
    action_ids = [a.action_id for a in plan.actions]
    assert "postgres-mcp-python-install" in action_ids
    assert "postgres-mcp-sidecar" in action_ids
    # Image rebuild is needed because pip-install is in Dockerfile lines.
    assert plan.has_image_changes is True

    # Sidecar declaration still applies.
    aliases = [s.alias for s in plan.services]
    images = [s.image for s in plan.services]
    assert aliases == ["db"]
    assert images == ["postgres:16-alpine"]
    assert plan.services[0].health_cmd[0] == "pg_isready"
    env = merged_bootstrap_env(plan)
    assert env["DATABASE_URL"] == "postgres://scan:scan@db:5432/scan"


def test_postgres_mcp_recipe_does_not_match_unrelated_python_servers() -> None:
    """Substring 'postgres-mcp' inside file paths/configs must not match.

    Without bounded matching, ``python /data/postgres-mcp-handler.py`` would
    falsely fire the postgres recipe — installing the wrong package and
    spinning up an unwanted sidecar.
    """
    runtime = ResolvedRuntime(image="mcp-sandbox-python312", command="python", reason="t")
    fp_cases = [
        # ('postgres-mcp' appears as substring inside non-tool args)
        ServerConfig(command="python", args=["/data/postgres-mcp-handler.py"]),
        ServerConfig(command="uv", args=["run", "my-tool", "--config", "postgres-mcp.json"]),
        ServerConfig(command="python", args=["-m", "my_server", "--log", "postgres-mcp-events.log"]),
        ServerConfig(command="uvx", args=["some-tool", "--mode=postgres-mcp-compat"]),
        ServerConfig(command="uv", args=["run", "spotify-mcp"]),
        ServerConfig(command="python", args=["bridge_mcp_ghidra.py"]),
    ]
    for srv in fp_cases:
        plan = plan_bootstrap(srv, runtime)
        action_ids = [a.action_id for a in plan.actions] if plan else []
        assert not any("postgres" in aid for aid in action_ids), (
            f"FP: postgres recipe wrongly matched {srv.command} {srv.args}"
        )


def test_postgres_mcp_recipe_matches_real_invocation_patterns() -> None:
    """All legitimate ways to invoke postgres-mcp must still match."""
    runtime_py = ResolvedRuntime(image="mcp-sandbox-python312", command="python", reason="t")
    runtime_node = ResolvedRuntime(image="mcp-sandbox-node22", command="npx", reason="t")

    tp_cases = [
        (ServerConfig(command="uv", args=["run", "postgres-mcp", "--access-mode=unrestricted"]), runtime_py),
        (ServerConfig(command="uvx", args=["postgres-mcp"]), runtime_py),
        (ServerConfig(command="uv", args=["run", "postgres-mcp@1.2.3"]), runtime_py),
        (ServerConfig(command="/usr/local/bin/postgres-mcp", args=[]), runtime_py),
        (ServerConfig(command="npx", args=["-y", "@modelcontextprotocol/server-postgres"]), runtime_node),
    ]
    for srv, rt in tp_cases:
        plan = plan_bootstrap(srv, rt)
        action_ids = [a.action_id for a in plan.actions] if plan else []
        assert any("postgres-mcp-sidecar" in aid for aid in action_ids), (
            f"TP missed: {srv.command} {srv.args}"
        )


def test_postgres_mcp_node_variant_uses_npm_install_not_pip() -> None:
    """Node-flavor postgres MCP gets npm install, not pip install.

    The python install recipe is gated by ``runtime_prefix: mcp-sandbox-python``
    and the node install recipe is gated by ``runtime_prefix: mcp-sandbox-node``,
    so the right one fires for the right runtime. Both are needed for build-time
    install because the sidecar runs on a network with no external access.
    """
    server = ServerConfig(
        command="npx",
        args=["-y", "@modelcontextprotocol/server-postgres"],
    )
    runtime = ResolvedRuntime(image="mcp-sandbox-node22", command="npx", reason="t")

    plan = plan_bootstrap(server, runtime)

    assert plan is not None
    action_ids = [a.action_id for a in plan.actions]
    assert "postgres-mcp-python-install" not in action_ids
    assert "postgres-mcp-node-install" in action_ids
    assert "postgres-mcp-sidecar" in action_ids
    # Node variant rebuilds image to bake the npm package in (since the
    # ``--internal`` runtime network blocks npm registry access).
    assert plan.has_image_changes is True


def test_arg_rewrite_redirects_postgres_uri_to_sidecar() -> None:
    """Production credentials in args must be redirected to the sidecar URL."""
    server = ServerConfig(
        command="npx",
        args=[
            "-y",
            "@modelcontextprotocol/server-postgres",
            "postgresql://produser:Pr0d!Sup3r@db.prod.example.com:5432/customers",
        ],
    )
    sandbox = Sandbox(server, SandboxConfig())
    runtime = ResolvedRuntime(image="mcp-sandbox-node22", command="npx", reason="t")
    plan = plan_bootstrap(server, runtime)
    assert plan is not None
    sandbox._bootstrap_plan = plan

    rewritten = sandbox._apply_arg_rewrites(list(server.args))

    assert rewritten[0] == "-y"
    assert rewritten[1] == "@modelcontextprotocol/server-postgres"
    assert rewritten[2] == "postgres://scan:scan@db:5432/scan"
    assert "produser" not in rewritten[2]
    assert "prod.example.com" not in rewritten[2]


def test_arg_rewrite_is_noop_when_no_uri_in_args() -> None:
    """Recipes match by identity tokens but plain args pass through unchanged."""
    server = ServerConfig(
        command="uv",
        args=["run", "postgres-mcp", "--access-mode=unrestricted"],
    )
    sandbox = Sandbox(server, SandboxConfig())
    runtime = ResolvedRuntime(image="mcp-sandbox-python311", command="uv", reason="t")
    plan = plan_bootstrap(server, runtime)
    assert plan is not None
    sandbox._bootstrap_plan = plan

    rewritten = sandbox._apply_arg_rewrites(list(server.args))

    assert rewritten == list(server.args)


def test_redis_arg_rewrite_handles_password_only_uri() -> None:
    """Redis URIs with empty username (``redis://:pass@host``) still rewrite."""
    server = ServerConfig(
        command="npx",
        args=["-y", "redis-mcp", "redis://:supersecret@cache.prod.internal:6379/0"],
    )
    sandbox = Sandbox(server, SandboxConfig())
    runtime = ResolvedRuntime(image="mcp-sandbox-node22", command="npx", reason="t")
    plan = plan_bootstrap(server, runtime)
    assert plan is not None
    sandbox._bootstrap_plan = plan

    rewritten = sandbox._apply_arg_rewrites(list(server.args))

    assert rewritten[2] == "redis://cache:6379/0"


def test_non_db_server_gets_no_sidecar() -> None:
    """Negative control: context7 is not a DB-backed server."""
    server = ServerConfig(command="npx", args=["-y", "@upstash/context7-mcp"])
    runtime = ResolvedRuntime(image="mcp-sandbox-node22", command="npx", reason="t")

    plan = plan_bootstrap(server, runtime)

    # No matching recipe means no plan at all.
    assert plan is None or not plan.services


def test_sidecar_recipe_overrides_user_db_env() -> None:
    """Production credentials in user-supplied env must be redirected.

    Models the real cursor config:
      DATABASE_URI = postgresql://username:password@localhost:5432/dbname

    Without this override, the sandboxed server would connect to the user's
    own host database, defeating the sandbox.
    """
    server = ServerConfig(
        command="uv",
        args=["run", "postgres-mcp", "--access-mode=unrestricted"],
        env={
            "DATABASE_URI": "postgresql://username:password@localhost:5432/dbname",
        },
    )
    sandbox = Sandbox(server, SandboxConfig())
    runtime = sandbox._resolve_runtime()
    plan = plan_bootstrap(server, runtime)
    assert plan is not None
    sandbox._bootstrap_plan = plan

    env = sandbox._merged_env()

    assert env["DATABASE_URI"] == "postgres://scan:scan@db:5432/scan"
    assert "localhost" not in env["DATABASE_URI"]
    assert "username" not in env["DATABASE_URI"]
    # Variant env keys also redirect to the sidecar.
    assert env["DATABASE_URL"] == "postgres://scan:scan@db:5432/scan"
    assert env["PGHOST"] == "db"
    assert env["PGUSER"] == "scan"


def test_package_runner_uses_tmpfs_cwd_not_host_workspace() -> None:
    """Package runners (uv/uvx/npx/...) must NOT mount the host CWD.

    Regression: ``uv run postgres-mcp`` with cwd mapped to the analyzer's own
    repo would find the analyzer's ``.venv/`` and crash trying to refresh its
    lockfile against a read-only mount. Switching to a tmpfs cwd avoids the
    collision entirely.
    """
    server = ServerConfig(
        command="uv",
        args=["run", "postgres-mcp", "--access-mode=unrestricted"],
    )
    sandbox = Sandbox(server, SandboxConfig())
    sandbox._bootstrap_plan = plan_bootstrap(
        server,
        sandbox._resolve_runtime(),
    )

    cmd = sandbox._build_docker_cmd()

    # No host workspace mount.
    workspace_mount_present = any(
        ":/workspace:" in x for x in cmd if x.startswith("/")
    )
    assert not workspace_mount_present
    # cwd is the writable tmpfs.
    w_idx = cmd.index("-w")
    assert cmd[w_idx + 1] == "/tmp"
    # tmpfs is bumped to give uv room for venv + cache.
    assert any("size=512m" in x for x in cmd)
    # uv reads HOME / XDG_CACHE_HOME — must point inside the tmpfs.
    assert "HOME=/tmp" in cmd
    assert any(x.startswith("XDG_CACHE_HOME=") for x in cmd)


def test_non_runner_command_keeps_workspace_mount() -> None:
    """Local-script servers (e.g. python /path/to/server.py) still mount cwd."""
    server = ServerConfig(
        command="/usr/bin/python3",
        args=["server.py"],
    )
    sandbox = Sandbox(server, SandboxConfig())

    cmd = sandbox._build_docker_cmd()

    workspace_mount_present = any(
        x.endswith(":/workspace:ro") or x.endswith(":/workspace:rw")
        for x in cmd
    )
    assert workspace_mount_present
    w_idx = cmd.index("-w")
    assert cmd[w_idx + 1] == "/workspace"


def test_non_sidecar_recipe_env_remains_overridable_by_user() -> None:
    """Playwright recipe is sidecar-free → user override semantics preserved."""
    server = ServerConfig(
        command="npx",
        args=["@playwright/mcp@latest"],
        env={"PLAYWRIGHT_BROWSERS_PATH": "/custom/browsers"},
    )
    sandbox = Sandbox(server, SandboxConfig())
    runtime = sandbox._resolve_runtime()
    plan = plan_bootstrap(
        server,
        runtime,
        evidence=PreflightEvidence(
            source="local-manifest",
            manifest_path="/tmp/package.json",
            package_name="browser-mcp",
            package_version="1.49.0",
            node_dependencies=(("playwright", "^1.49.0"),),
        ),
    )
    assert plan is not None
    sandbox._bootstrap_plan = plan

    # Playwright recipe has no services, so user env wins (existing behavior).
    assert sandbox._merged_env()["PLAYWRIGHT_BROWSERS_PATH"] == "/custom/browsers"
