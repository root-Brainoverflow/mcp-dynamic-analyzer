"""R4: Behavioral Inconsistency / Deception scanner.

Detects:
* **Rug Pull / response variability**: tools/list returns different tools
  across repeated calls within the same session.
* **Env-differential drift**: tools/list differs when the server is started
  with varied environment variables (detected via ``variation_tag``).
* **Capability mismatch**: server performs actions (file writes, network)
  not implied by its declared capabilities.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_dynamic_analyzer.models import (
    AnalysisContext,
    Event,
    Finding,
    RiskType,
    Severity,
)
from mcp_dynamic_analyzer.scanners.base import BaseScanner


class R4BehaviorDriftScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "r4_behavior_drift"

    @property
    def risk_type(self) -> RiskType:
        return RiskType.R4

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]

        findings.extend(await self._check_tools_list_drift(reader))
        findings.extend(await self._check_env_variation(reader))
        findings.extend(await self._check_capability_mismatch(ctx))

        return findings

    # -- tools/list variability within a single run --------------------------

    async def _check_tools_list_drift(self, reader: Any) -> list[Finding]:
        """Compare consecutive tools/list responses in the base run."""
        tools_responses: list[Event] = []
        async for evt in reader.events_by_type("mcp_response"):
            msg = evt.data.get("message", {})
            result = msg.get("result", {})
            if "tools" in result and evt.variation_tag in (None, "base"):
                tools_responses.append(evt)

        if len(tools_responses) < 2:
            return []

        findings: list[Finding] = []
        baseline = _tool_names(tools_responses[0])
        for subsequent in tools_responses[1:]:
            current = _tool_names(subsequent)
            if current != baseline:
                added = current - baseline
                removed = baseline - current
                findings.append(Finding(
                    risk_type=RiskType.R4,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title="Rug Pull: tools/list changed between calls",
                    description=(
                        f"tools/list returned different tool sets across calls. "
                        f"Added: {added or 'none'}, Removed: {removed or 'none'}"
                    ),
                    related_events=[tools_responses[0].event_id, subsequent.event_id],
                    reproduction="Call tools/list multiple times and compare results",
                ))

        return findings

    # -- env-variation drift -------------------------------------------------

    async def _check_env_variation(self, reader: Any) -> list[Finding]:
        """Compare tools/list between base run and env-variation runs."""
        by_tag: dict[str, set[str]] = {}

        async for evt in reader.events_by_type("mcp_response"):
            msg = evt.data.get("message", {})
            result = msg.get("result", {})
            if "tools" not in result:
                continue
            tag = evt.variation_tag or "base"
            names = {t["name"] for t in result.get("tools", []) if isinstance(t, dict)}
            if tag not in by_tag:
                by_tag[tag] = names

        if len(by_tag) < 2 or "base" not in by_tag:
            return []

        findings: list[Finding] = []
        base = by_tag["base"]
        for tag, names in by_tag.items():
            if tag == "base":
                continue
            if names != base:
                diff_added = names - base
                diff_removed = base - names
                findings.append(Finding(
                    risk_type=RiskType.R4,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    title=f"Env-conditional tool set (variation '{tag}')",
                    description=(
                        f"Server exposes different tools under env variation '{tag}'. "
                        f"Added: {diff_added or 'none'}, Removed: {diff_removed or 'none'}. "
                        f"This may indicate environment-dependent hidden functionality."
                    ),
                    reproduction=f"Run server with env variation '{tag}' and compare tools/list",
                ))

        return findings

    # -- capability mismatch -------------------------------------------------

    async def _check_capability_mismatch(self, ctx: AnalysisContext) -> list[Finding]:
        """Check if server actions exceed what its declared capabilities suggest."""
        reader = ctx.event_reader  # type: ignore[union-attr]
        declared = set()
        if ctx.static_context:
            declared = set(ctx.static_context.get("declared_capabilities", []))

        findings: list[Finding] = []

        if declared and "write" not in " ".join(declared).lower():
            write_count = 0
            async for _ in reader.events_by_type("file_write"):
                write_count += 1
            if write_count > 0:
                findings.append(Finding(
                    risk_type=RiskType.R4,
                    severity=Severity.MEDIUM,
                    confidence=0.7,
                    title="Capability mismatch: file writes without write capability",
                    description=f"Server performed {write_count} file_write syscalls but does not declare write capability.",
                    reproduction="Compare declared capabilities with observed syscalls",
                ))

        net_count = 0
        async for _ in reader.events_by_source("network"):
            net_count += 1
        if net_count > 0 and declared and "network" not in " ".join(declared).lower():
            findings.append(Finding(
                risk_type=RiskType.R4,
                severity=Severity.MEDIUM,
                confidence=0.7,
                title="Capability mismatch: network activity without network capability",
                description=f"Server made {net_count} network connections but does not declare network capability.",
                reproduction="Compare declared capabilities with observed network events",
            ))

        return findings


def _tool_names(evt: Event) -> set[str]:
    msg = evt.data.get("message", {})
    tools = msg.get("result", {}).get("tools", [])
    return {t["name"] for t in tools if isinstance(t, dict) and "name" in t}
