"""Prerequisite bootstrap planning for MCP server runtime environments.

Two-phase process
─────────────────
1. **Preflight inspection** – ``SourcePreflightInspector`` reads local
   manifests or queries remote registries (host-side ``npm view`` / PyPI JSON
   API) to collect the server's declared dependencies and source signals.

2. **Plan generation** – ``plan_bootstrap()`` passes that evidence to the
   ``RecipeRegistry``, which matches declarative YAML recipes against the
   evidence and returns ordered ``BootstrapAction`` steps.

All prerequisite knowledge lives in ``infrastructure/recipes/builtin.yaml``.
Adding support for a new tool only requires a new recipe entry there.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import tomllib
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import structlog

from mcp_dynamic_analyzer.config import ServerConfig
from mcp_dynamic_analyzer.infrastructure.recipes import (
    ArgRewrite,
    MatchContext,
    RecipeRegistry,
    ServiceSpec,
)
from mcp_dynamic_analyzer.infrastructure.runtime_resolver import ResolvedRuntime

log = structlog.get_logger()

_LOCAL_MANIFEST_NAMES = ("package.json", "pyproject.toml", "requirements.txt")
_MAX_LOCAL_MANIFEST_ASCENT = 5

_NODE_SKIP_FLAGS = {
    "-y", "--yes", "-q", "--quiet", "--quietly", "--no",
    "--shell-auto-fallback", "--ignore-existing",
}
_NODE_VALUE_FLAGS = {"-p", "--package", "-c", "--call"}
_PYTHON_SKIP_FLAGS = {"--python", "--from", "--with", "--index-url", "--extra-index-url"}

_SOURCE_SCAN_FILE_LIMIT = 200
_SOURCE_SCAN_BYTES_LIMIT = 256 * 1024
_SOURCE_SCAN_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs",
    ".ts", ".tsx", ".mts", ".cts", ".json", ".toml",
}
_SOURCE_SCAN_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build", ".next", ".turbo", ".cache",
}
# Source-code patterns that produce named signals used by recipe matching.
_SOURCE_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("playwright.channel.chrome",   re.compile(r"""channel\s*[:=]\s*["']chrome["']""",        re.IGNORECASE)),
    ("browser.exec.google-chrome",  re.compile(r"""\bgoogle-chrome(?:-stable)?\b""",           re.IGNORECASE)),
    ("browser.path.google-chrome",  re.compile(r"""/opt/google/chrome/chrome""",               re.IGNORECASE)),
    ("browser.selenium.chrome",     re.compile(r"""chrome(?:driver|options)\b""",              re.IGNORECASE)),
    ("browser.puppeteer.launch",    re.compile(r"""puppeteer\.launch\b""",                     re.IGNORECASE)),
)

_REGISTRY = RecipeRegistry()

_PYPI_API_TIMEOUT = 15


# ─────────────────────────────────────────────────────────────────────────────
# Public data classes
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BootstrapAction:
    """A prerequisite installation step layered onto a base sandbox image."""

    action_id: str
    description: str
    dockerfile_lines: tuple[str, ...]
    env: tuple[tuple[str, str], ...] = ()
    services: tuple[ServiceSpec, ...] = ()
    arg_rewrites: tuple[ArgRewrite, ...] = ()


@dataclass(frozen=True)
class BootstrapPlan:
    """Ordered bootstrap actions for a specific resolved runtime."""

    actions: tuple[BootstrapAction, ...]
    reason: str

    def image_tag(self, base_image: str) -> str:
        # Only image-mutating steps (Dockerfile lines / env) affect the base
        # image hash. Sidecars and arg rewrites are runtime concerns and
        # would otherwise force a needless image rebuild per recipe revision.
        image_relevant = [a for a in self.actions if a.dockerfile_lines]
        digest = hashlib.sha256(
            "|".join(a.action_id for a in image_relevant).encode(),
        ).hexdigest()[:12]
        return f"{base_image}-bootstrap-{digest}"

    @property
    def services(self) -> tuple[ServiceSpec, ...]:
        out: list[ServiceSpec] = []
        seen: set[str] = set()
        for action in self.actions:
            for svc in action.services:
                if svc.alias in seen:
                    continue
                seen.add(svc.alias)
                out.append(svc)
        return tuple(out)

    @property
    def arg_rewrites(self) -> tuple[ArgRewrite, ...]:
        out: list[ArgRewrite] = []
        for action in self.actions:
            out.extend(action.arg_rewrites)
        return tuple(out)

    @property
    def has_image_changes(self) -> bool:
        return any(a.dockerfile_lines for a in self.actions)

    @property
    def forced_runtime_env(self) -> dict[str, str]:
        """Env vars from sidecar-bearing recipes — must override user values.

        When a recipe declares ``services``, the recipe owns the connection
        endpoint by definition (the sidecar is the *only* legitimate target).
        Letting user-provided env (which may carry production credentials
        from their cursor/claude config) win would defeat the point of the
        sidecar redirect, so we hoist these env vars to highest priority.
        """
        out: dict[str, str] = {}
        for action in self.actions:
            if not action.services:
                continue
            for k, v in action.env:
                out[k] = v
        return out


@dataclass(frozen=True)
class PreflightEvidence:
    """Manifest or package metadata collected before the actual server run."""

    source: str
    manifest_path: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    node_dependencies: tuple[tuple[str, str], ...] = ()
    python_dependencies: tuple[str, ...] = ()
    source_signals: tuple[str, ...] = ()

    def node_dependency_map(self) -> dict[str, str]:
        return dict(self.node_dependencies)


# ─────────────────────────────────────────────────────────────────────────────
# Preflight inspection
# ─────────────────────────────────────────────────────────────────────────────


class SourcePreflightInspector:
    """Inspect local manifests or remote registry metadata before server start.

    Remote Node.js inspection uses the host-side ``npm view`` command (no
    docker required).  Remote Python inspection queries the PyPI JSON API.
    """

    async def inspect(
        self,
        server: ServerConfig,
        runtime: ResolvedRuntime,  # kept for API compatibility; runtime selection now uses recipe matching
        *,
        network_mode: str = "allowlist",
    ) -> PreflightEvidence | None:
        _ = runtime
        local = _inspect_local_manifests(server)
        if local is not None:
            return local

        if network_mode == "none":
            return None

        node_spec = _extract_node_package_spec(server)
        if node_spec:
            return await self._inspect_remote_node(node_spec)

        python_spec = _extract_python_package_spec(server)
        if python_spec:
            return await self._inspect_remote_python(python_spec)

        return None

    # ------------------------------------------------------------------
    # Remote Node.js – host-side npm view (no docker)
    # ------------------------------------------------------------------

    async def _inspect_remote_node(self, package_spec: str) -> PreflightEvidence | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "npm", "view", package_spec, "--json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except (FileNotFoundError, asyncio.TimeoutError) as exc:
            log.debug("bootstrap.preflight.npm_view_unavailable", package_spec=package_spec, exc=str(exc))
            return None

        if proc.returncode != 0:
            log.debug(
                "bootstrap.preflight.npm_view_failed",
                package_spec=package_spec,
                rc=proc.returncode,
                stderr=stderr.decode(errors="replace")[-400:],
            )
            return None

        try:
            data = json.loads(stdout.decode())
        except ValueError:
            log.debug("bootstrap.preflight.npm_view_invalid_json", package_spec=package_spec)
            return None

        if isinstance(data, list):
            data = data[-1] if data else {}
        if not isinstance(data, dict):
            return None

        deps = _collect_node_dependencies(data)
        return PreflightEvidence(
            source=f"npm-view:{package_spec}",
            manifest_path="npm registry (package.json metadata)",
            package_name=_maybe_str(data.get("name")),
            package_version=_maybe_str(data.get("version")),
            node_dependencies=tuple(sorted(deps.items())),
        )

    # ------------------------------------------------------------------
    # Remote Python – PyPI JSON API (no docker)
    # ------------------------------------------------------------------

    async def _inspect_remote_python(self, package_spec: str) -> PreflightEvidence | None:
        pkg_name = _python_spec_to_name(package_spec)
        if not pkg_name:
            return None

        url = f"https://pypi.org/pypi/{pkg_name}/json"
        try:
            loop = asyncio.get_event_loop()
            data = await asyncio.wait_for(
                loop.run_in_executor(None, _fetch_json_url, url),
                timeout=_PYPI_API_TIMEOUT,
            )
        except Exception as exc:
            log.debug("bootstrap.preflight.pypi_api_failed", pkg_name=pkg_name, exc=str(exc))
            return None

        if not isinstance(data, dict):
            return None

        info = data.get("info") or {}
        raw_deps: list[str] = info.get("requires_dist") or []
        deps = tuple(
            sorted(
                {_normalise_python_requirement(r) for r in raw_deps} - {None}  # type: ignore[arg-type]
            )
        )
        return PreflightEvidence(
            source=f"pypi-api:{package_spec}",
            manifest_path="PyPI package metadata",
            package_name=_maybe_str(info.get("name")),
            package_version=_maybe_str(info.get("version")),
            python_dependencies=deps,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Public API – plan generation
# ─────────────────────────────────────────────────────────────────────────────


def plan_bootstrap(
    server: ServerConfig,
    runtime: ResolvedRuntime,
    *,
    evidence: PreflightEvidence | None = None,
    stderr_snippet: str | None = None,
) -> BootstrapPlan | None:
    """Infer prerequisite bootstrap actions for a server/runtime pair."""
    ctx = _build_match_context(server, runtime, evidence, stderr_snippet)
    matched = _REGISTRY.match(ctx)
    if not matched:
        return None

    actions = tuple(
        BootstrapAction(
            action_id=a.action_id,
            description=a.description,
            dockerfile_lines=_pin_playwright_version(a.action_id, a.dockerfile_lines, evidence),
            env=a.env,
            services=a.services,
            arg_rewrites=a.arg_rewrites,
        )
        for a in matched
    )
    return BootstrapPlan(
        actions=actions,
        reason=", ".join(a.description for a in matched),
    )


def render_bootstrap_dockerfile(base_image: str, plan: BootstrapPlan) -> str:
    """Render a Dockerfile that extends *base_image* with *plan* actions."""
    lines = [f"FROM {base_image}"]
    seen_env: dict[str, str] = {}
    for action in plan.actions:
        lines.extend(action.dockerfile_lines)
        for key, value in action.env:
            seen_env[key] = value
    for key, value in seen_env.items():
        lines.append(f"ENV {key}={value}")
    lines.append("")
    return "\n".join(lines)


def merged_bootstrap_env(plan: BootstrapPlan | None) -> dict[str, str]:
    """Return env vars implied by the bootstrap plan."""
    if plan is None:
        return {}
    env: dict[str, str] = {}
    for action in plan.actions:
        for key, value in action.env:
            env[key] = value
    return env


# ─────────────────────────────────────────────────────────────────────────────
# Local manifest inspection
# ─────────────────────────────────────────────────────────────────────────────


def _inspect_local_manifests(server: ServerConfig) -> PreflightEvidence | None:
    root = _find_local_project_root(server)
    if root is None:
        return None

    manifest_paths: list[str] = []
    package_name: str | None = None
    package_version: str | None = None
    node_dependencies: dict[str, str] = {}
    python_dependencies: set[str] = set()
    source_signals = _scan_source_tree(root)

    package_json = root / "package.json"
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if isinstance(data, dict):
            manifest_paths.append(str(package_json))
            package_name = package_name or _maybe_str(data.get("name"))
            package_version = package_version or _maybe_str(data.get("version"))
            node_dependencies.update(_collect_node_dependencies(data))

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, ValueError, tomllib.TOMLDecodeError):
            data = {}
        if isinstance(data, dict):
            manifest_paths.append(str(pyproject))
            project = data.get("project") or {}
            if isinstance(project, dict):
                package_name = package_name or _maybe_str(project.get("name"))
                package_version = package_version or _maybe_str(project.get("version"))
            python_dependencies.update(_collect_pyproject_dependencies(data))

    requirements = root / "requirements.txt"
    if requirements.exists():
        try:
            manifest_paths.append(str(requirements))
            python_dependencies.update(
                _parse_requirements_lines(requirements.read_text(encoding="utf-8")),
            )
        except OSError:
            pass

    if not node_dependencies and not python_dependencies and not source_signals:
        return None

    return PreflightEvidence(
        source="local-manifest",
        manifest_path=", ".join(manifest_paths) or str(root),
        package_name=package_name,
        package_version=package_version,
        node_dependencies=tuple(sorted(node_dependencies.items())),
        python_dependencies=tuple(sorted(python_dependencies)),
        source_signals=tuple(sorted(source_signals)),
    )


def _find_local_project_root(server: ServerConfig) -> Path | None:
    for raw in (server.command, *server.args):
        path = Path(raw)
        if not path.is_absolute() or not path.exists():
            continue
        start = path if path.is_dir() else path.parent
        for candidate in [start, *list(start.parents)[:_MAX_LOCAL_MANIFEST_ASCENT]]:
            if any((candidate / name).exists() for name in _LOCAL_MANIFEST_NAMES):
                return candidate
    return None


def _scan_source_tree(root: Path) -> set[str]:
    signals: set[str] = set()
    scanned = 0
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SOURCE_SCAN_SKIP_DIRS]
        for name in files:
            path = Path(current) / name
            if name not in _LOCAL_MANIFEST_NAMES and path.suffix.lower() not in _SOURCE_SCAN_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > _SOURCE_SCAN_BYTES_LIMIT:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for signal, pattern in _SOURCE_SIGNAL_PATTERNS:
                if pattern.search(text):
                    signals.add(signal)
            scanned += 1
            if scanned >= _SOURCE_SCAN_FILE_LIMIT:
                return signals
    return signals


# ─────────────────────────────────────────────────────────────────────────────
# Recipe matching context builder
# ─────────────────────────────────────────────────────────────────────────────


def _build_match_context(
    server: ServerConfig,
    runtime: ResolvedRuntime,
    evidence: PreflightEvidence | None,
    stderr_snippet: str | None,
) -> MatchContext:
    node_deps: frozenset[str] = frozenset()
    python_deps: frozenset[str] = frozenset()
    source_signals: frozenset[str] = frozenset()
    package_name = ""

    if evidence is not None:
        node_deps = frozenset(evidence.node_dependency_map().keys())
        python_deps = frozenset(evidence.python_dependencies)
        source_signals = frozenset(evidence.source_signals)
        package_name = evidence.package_name or ""

    identity_tokens = tuple(
        t.lower() for t in (server.command, *server.args) if t
    )

    return MatchContext(
        runtime_image=runtime.image,
        node_deps=node_deps,
        python_deps=python_deps,
        source_signals=source_signals,
        identity_tokens=identity_tokens,
        stderr_snippet=(stderr_snippet or "").lower(),
        package_name=package_name.lower(),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Dependency collection helpers
# ─────────────────────────────────────────────────────────────────────────────


def _collect_node_dependencies(data: dict[str, object]) -> dict[str, str]:
    deps: dict[str, str] = {}
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        mapping = data.get(field)
        if not isinstance(mapping, dict):
            continue
        for name, version in mapping.items():
            if isinstance(name, str) and isinstance(version, str):
                deps[name] = version
    return deps


def _collect_pyproject_dependencies(data: dict[str, object]) -> set[str]:
    deps: set[str] = set()
    project = data.get("project")
    if isinstance(project, dict):
        for raw in project.get("dependencies") or []:
            if isinstance(raw, str):
                dep = _normalise_python_requirement(raw)
                if dep:
                    deps.add(dep)
        optional = project.get("optional-dependencies") or {}
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    for raw in group:
                        if isinstance(raw, str):
                            dep = _normalise_python_requirement(raw)
                            if dep:
                                deps.add(dep)
    groups = data.get("dependency-groups") or {}
    if isinstance(groups, dict):
        for group in groups.values():
            if isinstance(group, list):
                for raw in group:
                    if isinstance(raw, str):
                        dep = _normalise_python_requirement(raw)
                        if dep:
                            deps.add(dep)
    tool = data.get("tool") or {}
    if isinstance(tool, dict):
        poetry = tool.get("poetry") or {}
        if isinstance(poetry, dict):
            for name in (poetry.get("dependencies") or {}).keys():
                if isinstance(name, str) and name.lower() != "python":
                    deps.add(name.lower().replace("_", "-"))
    return deps


def _parse_requirements_lines(raw: str) -> set[str]:
    deps: set[str] = set()
    for line in raw.splitlines():
        dep = _normalise_python_requirement(line)
        if dep:
            deps.add(dep)
    return deps


# ─────────────────────────────────────────────────────────────────────────────
# Package spec extraction helpers
# ─────────────────────────────────────────────────────────────────────────────


def _extract_node_package_spec(server: ServerConfig) -> str | None:
    command = _basename(server.command).lower()
    if command not in {"npx", "pnpx", "bunx"}:
        return None
    skip_next = False
    for arg in server.args:
        if skip_next:
            skip_next = False
            continue
        if arg in _NODE_VALUE_FLAGS:
            skip_next = True
            continue
        if arg in _NODE_SKIP_FLAGS or (arg.startswith("-") and arg not in _NODE_SKIP_FLAGS):
            continue
        if arg.startswith((".", "/")) or "\\" in arg:
            return None
        return arg
    return None


def _extract_python_package_spec(server: ServerConfig) -> str | None:
    command = _basename(server.command).lower()
    if command not in {"uvx", "pipx"}:
        return None
    skip_next = False
    for arg in server.args:
        if skip_next:
            skip_next = False
            continue
        if arg in _PYTHON_SKIP_FLAGS:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if arg.startswith((".", "/")) or "\\" in arg:
            return None
        return arg
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Version pinning post-processor
# ─────────────────────────────────────────────────────────────────────────────

_PLAYWRIGHT_NODE_PACKAGES = ("playwright", "@playwright/test", "playwright-core")


def _pin_playwright_version(
    action_id: str,
    lines: tuple[str, ...],
    evidence: PreflightEvidence | None,
) -> tuple[str, ...]:
    """Substitute a pinned version into Playwright install commands when available."""
    if evidence is None:
        return lines
    if action_id.startswith("playwright-node"):
        node_deps = evidence.node_dependency_map()
        version: str | None = None
        for pkg in _PLAYWRIGHT_NODE_PACKAGES:
            if pkg in node_deps:
                version = _extract_semver(node_deps[pkg])
                break
        if version:
            return tuple(
                line.replace("npx -y playwright install", f"npx -y playwright@{version} install")
                for line in lines
            )
    elif action_id.startswith("playwright-python"):
        version = _extract_semver(evidence.package_version)
        if version:
            return tuple(
                line.replace(
                    "pip install --no-cache-dir playwright",
                    f"pip install --no-cache-dir playwright=={version}",
                )
                for line in lines
            )
    return lines


def _extract_semver(raw: str | None) -> str | None:
    if not raw:
        return None
    match = re.search(r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)", raw)
    return match.group(1) if match else None


# ─────────────────────────────────────────────────────────────────────────────
# Misc helpers
# ─────────────────────────────────────────────────────────────────────────────


def _normalise_python_requirement(raw: str) -> str | None:
    line = raw.split("#", 1)[0].split(";", 1)[0].strip()
    if not line or line.startswith("-"):
        return None
    if "@" in line and "://" in line:
        line = line.split("@", 1)[0].strip()
    match = re.match(r"([A-Za-z0-9_.-]+)", line)
    if not match:
        return None
    return match.group(1).lower().replace("_", "-")


def _python_spec_to_name(spec: str) -> str | None:
    """Extract bare package name from a pip/uvx spec (strips version constraints)."""
    return _normalise_python_requirement(spec)


def _fetch_json_url(url: str) -> object:
    """Blocking HTTP GET → parsed JSON. Run in an executor."""
    with urllib.request.urlopen(url, timeout=_PYPI_API_TIMEOUT) as resp:  # noqa: S310
        return json.loads(resp.read().decode())


def _maybe_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _basename(cmd: str) -> str:
    return Path(cmd.replace("\\", "/")).name
