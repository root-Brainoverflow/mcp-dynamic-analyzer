"""Declarative recipe registry for MCP server bootstrap prerequisites.

Recipes are defined in ``infrastructure/recipes/builtin.yaml``.  Each recipe
carries a ``match`` block (evaluated against collected evidence) and
``dockerfile_lines`` / ``env`` that extend the base sandbox image.

Match evaluation
────────────────
AND conditions (evaluated first; one failure short-circuits the recipe):
  runtime_prefix      – image must start with this string
  source_signals_any  – at least one of these signals must be present
  source_signals_none – none of these signals may be present

OR gate (at least one block in ``any_of`` must be fully satisfied):
  node_deps_any       – evidence.node_deps contains one of these
  python_deps_any     – evidence.python_deps contains one of these
  identity_tokens_any – server command/args contain one of these
  stderr_tokens_any   – stderr snippet contains one of these
  package_name_any    – evidence.package_name contains one of these (substring)

If ``any_of`` is absent the recipe matches whenever the AND conditions pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_BUILTIN_YAML = Path(__file__).parent / "recipes" / "builtin.yaml"


@dataclass(frozen=True)
class MatchContext:
    """Extracted evidence and server metadata passed to the recipe matcher."""

    runtime_image: str = ""
    node_deps: frozenset[str] = field(default_factory=frozenset)
    python_deps: frozenset[str] = field(default_factory=frozenset)
    source_signals: frozenset[str] = field(default_factory=frozenset)
    identity_tokens: tuple[str, ...] = ()
    stderr_snippet: str = ""
    package_name: str = ""


@dataclass(frozen=True)
class ServiceSpec:
    """Sidecar backend service the MCP server depends on (DB, cache, etc.)."""

    alias: str                                        # in-network DNS name
    image: str                                        # docker image, e.g. postgres:16-alpine
    env: tuple[tuple[str, str], ...] = ()
    health_cmd: tuple[str, ...] = ()                  # docker exec ... health probe
    port: int | None = None                           # informational
    startup_timeout_sec: float = 30.0


@dataclass(frozen=True)
class ArgRewrite:
    """Regex-based rewrite applied to each MCP server arg before launch.

    Used to redirect connection strings (e.g. postgres://localhost/real_db)
    to the ephemeral sidecar so the sandboxed server can never touch host
    resources, even if the user's config exposes credentials.
    """

    pattern: str           # re.Pattern source, applied with re.sub on each arg
    replacement: str       # replacement string


@dataclass(frozen=True)
class RecipeAction:
    """Resolved installation step produced by a matched recipe."""

    action_id: str
    description: str
    dockerfile_lines: tuple[str, ...]
    env: tuple[tuple[str, str], ...]
    services: tuple[ServiceSpec, ...] = ()
    arg_rewrites: tuple[ArgRewrite, ...] = ()


class RecipeRegistry:
    """Loads and matches prerequisite recipes from a YAML file."""

    def __init__(self, yaml_path: Path | None = None) -> None:
        self._recipes: list[dict[str, Any]] = _load_yaml(yaml_path or _BUILTIN_YAML)

    def match(self, ctx: MatchContext) -> list[RecipeAction]:
        """Return matched actions in recipe order, deduped by action_id."""
        seen: set[str] = set()
        actions: list[RecipeAction] = []
        for recipe in self._recipes:
            action_id = recipe.get("id", "")
            if not action_id or action_id in seen:
                continue
            if _matches(recipe, ctx):
                seen.add(action_id)
                env_raw = recipe.get("env") or {}
                actions.append(RecipeAction(
                    action_id=action_id,
                    description=recipe.get("description", action_id),
                    dockerfile_lines=tuple(recipe.get("dockerfile_lines") or []),
                    env=tuple(sorted(env_raw.items())) if isinstance(env_raw, dict) else (),
                    services=_parse_services(recipe.get("services")),
                    arg_rewrites=_parse_arg_rewrites(recipe.get("arg_rewrites")),
                ))
        return actions


def _parse_services(raw: Any) -> tuple[ServiceSpec, ...]:
    if not isinstance(raw, list):
        return ()
    out: list[ServiceSpec] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        alias = item.get("alias")
        image = item.get("image")
        if not isinstance(alias, str) or not isinstance(image, str):
            continue
        env_raw = item.get("env") or {}
        env_pairs: tuple[tuple[str, str], ...] = ()
        if isinstance(env_raw, dict):
            env_pairs = tuple(sorted(
                (str(k), str(v)) for k, v in env_raw.items()
            ))
        health_cmd = item.get("health_cmd") or ()
        if isinstance(health_cmd, list):
            health_cmd = tuple(str(x) for x in health_cmd)
        else:
            health_cmd = ()
        port = item.get("port")
        port_val = int(port) if isinstance(port, int) else None
        timeout = item.get("startup_timeout_sec", 30.0)
        try:
            timeout_val = float(timeout)
        except (TypeError, ValueError):
            timeout_val = 30.0
        out.append(ServiceSpec(
            alias=alias,
            image=image,
            env=env_pairs,
            health_cmd=health_cmd,
            port=port_val,
            startup_timeout_sec=timeout_val,
        ))
    return tuple(out)


def _parse_arg_rewrites(raw: Any) -> tuple[ArgRewrite, ...]:
    if not isinstance(raw, list):
        return ()
    out: list[ArgRewrite] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        pattern = item.get("pattern")
        replacement = item.get("replacement", "")
        if not isinstance(pattern, str):
            continue
        out.append(ArgRewrite(
            pattern=pattern,
            replacement=str(replacement),
        ))
    return tuple(out)


# ---------------------------------------------------------------------------
# Internal YAML loading
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if isinstance(data, dict):
        recipes = data.get("recipes", [])
    elif isinstance(data, list):
        recipes = data
    else:
        recipes = []
    return [r for r in recipes if isinstance(r, dict)]


# ---------------------------------------------------------------------------
# Match evaluation
# ---------------------------------------------------------------------------

def _matches(recipe: dict[str, Any], ctx: MatchContext) -> bool:
    match = recipe.get("match") or {}

    # AND: runtime image prefix
    prefix = match.get("runtime_prefix")
    if prefix and not ctx.runtime_image.startswith(str(prefix)):
        return False

    # AND: source signals must be absent
    signals_none: list[str] = match.get("source_signals_none") or []
    if signals_none and ctx.source_signals.intersection(signals_none):
        return False

    # AND: source signals must be present
    signals_any: list[str] = match.get("source_signals_any") or []
    if signals_any and not ctx.source_signals.intersection(signals_any):
        return False

    # OR gate: any_of blocks
    # Top-level trigger keys are treated as an implicit extra block.
    any_of: list[dict[str, Any]] = list(match.get("any_of") or [])
    top_block = _top_level_block(match)
    if top_block:
        any_of = [top_block, *any_of]

    if not any_of:
        return True  # No trigger conditions — AND checks passed, recipe applies.

    return any(_block_matches(block, ctx) for block in any_of)


_TRIGGER_KEYS = frozenset({
    "node_deps_any",
    "python_deps_any",
    "identity_tokens_any",
    "stderr_tokens_any",
    "package_name_any",
})


def _top_level_block(match: dict[str, Any]) -> dict[str, Any] | None:
    block = {k: match[k] for k in _TRIGGER_KEYS if k in match}
    return block or None


def _block_matches(block: dict[str, Any], ctx: MatchContext) -> bool:
    node_deps: list[str] = block.get("node_deps_any") or []
    if node_deps and ctx.node_deps.intersection(node_deps):
        return True

    python_deps: list[str] = block.get("python_deps_any") or []
    if python_deps and ctx.python_deps.intersection(python_deps):
        return True

    identity: list[str] = block.get("identity_tokens_any") or []
    if identity:
        haystack = " ".join(ctx.identity_tokens)
        if any(_bounded_match(token.lower(), haystack) for token in identity):
            return True

    # stderr matches stay loose because stack traces and apt errors put
    # tokens next to arbitrary punctuation; loosening here trades FP risk
    # against missing legitimate "command not found" hints.
    stderr: list[str] = block.get("stderr_tokens_any") or []
    if stderr and ctx.stderr_snippet:
        if any(token.lower() in ctx.stderr_snippet for token in stderr):
            return True

    pkg_names: list[str] = block.get("package_name_any") or []
    if pkg_names and ctx.package_name:
        pkg_lower = ctx.package_name.lower()
        if any(_bounded_match(name.lower(), pkg_lower) for name in pkg_names):
            return True

    return False


# Characters that delimit a "component" inside an identity token or package
# name. A needle must be flanked by one of these (or the string boundary) on
# each side. We deliberately exclude ``.`` so that a filename like
# ``postgres-mcp.json`` does not satisfy a match for ``postgres-mcp``; only
# tokens bordered by whitespace, slashes, ``@``-versions, or ``:`` count as
# the actual command being run.
_IDENTITY_BOUNDARY_CHARS = frozenset(" /@:\t")


def _bounded_match(needle: str, haystack: str) -> bool:
    """Return True iff *needle* appears in *haystack* as a complete component.

    Component boundaries are whitespace, ``/``, ``@``, ``:``, ``.``, ``,``
    or the string edges. Internal package-name characters like ``-`` and
    ``_`` are NOT boundaries, preventing ``postgres-mcp`` from matching
    inside ``postgres-mcp-config``.
    """
    if not needle:
        return False
    n = len(needle)
    h = len(haystack)
    start = 0
    while True:
        idx = haystack.find(needle, start)
        if idx < 0:
            return False
        left_ok = idx == 0 or haystack[idx - 1] in _IDENTITY_BOUNDARY_CHARS
        right_idx = idx + n
        right_ok = right_idx == h or haystack[right_idx] in _IDENTITY_BOUNDARY_CHARS
        if left_ok and right_ok:
            return True
        start = idx + 1
