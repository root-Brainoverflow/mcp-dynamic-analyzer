"""Cross-layer correlation engine.

Takes the raw findings produced by individual scanners and *enriches*
them by linking related events from different sources (protocol ↔ syscall
↔ network ↔ test) using temporal proximity and causal heuristics.

For example, if R5 reports "command injection succeeded" and R2 reports
"shell execution detected" within a 5-second window, the engine merges
their evidence chains and elevates the combined finding.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import structlog

from mcp_dynamic_analyzer.correlation.event_store import EventReader
from mcp_dynamic_analyzer.models import Event, Finding, Severity

log = structlog.get_logger()

_CORRELATION_WINDOW = timedelta(seconds=5)

# Pairs of (scanner_A, scanner_B) that should be correlated.
_CORR_PAIRS: list[tuple[str, str]] = [
    ("R5", "R2"),  # input fuzzing → code execution
    ("R5", "R1"),  # input fuzzing → data access
    ("R3", "R1"),  # LLM manipulation → data exfiltration
    ("R3", "R2"),  # LLM manipulation → code execution
]

_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class CorrelationEngine:
    """Enrich and deduplicate findings via cross-layer event linking."""

    def __init__(self, reader: EventReader) -> None:
        self._reader = reader

    async def correlate(self, findings: list[Finding]) -> list[Finding]:
        """Return enriched findings list (may be shorter due to merging)."""
        if not findings:
            return findings

        event_index = await self._build_index()
        enriched = [self._enrich(f, event_index) for f in findings]
        merged = self._merge_correlated(enriched)
        deduped = self._deduplicate(merged)

        log.info(
            "correlation.done",
            input_findings=len(findings),
            output_findings=len(deduped),
        )
        return deduped

    # -- index ---------------------------------------------------------------

    async def _build_index(self) -> dict[str, Event]:
        """Build event_id → Event lookup for quick access."""
        idx: dict[str, Event] = {}
        async for evt in self._reader.all_events():
            idx[evt.event_id] = evt
        return idx

    # -- enrich --------------------------------------------------------------

    def _enrich(self, finding: Finding, index: dict[str, Event]) -> Finding:
        """Add nearby events from other sources to the finding's evidence."""
        if not finding.related_events:
            return finding

        anchor_events = [index[eid] for eid in finding.related_events if eid in index]
        if not anchor_events:
            return finding

        earliest = min(e.ts for e in anchor_events)
        latest = max(e.ts for e in anchor_events)
        window_start = earliest - _CORRELATION_WINDOW
        window_end = latest + _CORRELATION_WINDOW

        anchor_sources = {e.source for e in anchor_events}
        extra_ids: list[str] = []

        for eid, evt in index.items():
            if eid in finding.related_events:
                continue
            if evt.source in anchor_sources:
                continue
            if window_start <= evt.ts <= window_end:
                extra_ids.append(eid)

        if extra_ids:
            return finding.model_copy(
                update={"related_events": finding.related_events + extra_ids[:10]},
            )
        return finding

    # -- merge ---------------------------------------------------------------

    def _merge_correlated(self, findings: list[Finding]) -> list[Finding]:
        """Merge findings from correlated scanner pairs that share events."""
        merged: list[Finding] = list(findings)

        for type_a, type_b in _CORR_PAIRS:
            group_a = [f for f in merged if f.risk_type.value == type_a]
            group_b = [f for f in merged if f.risk_type.value == type_b]

            for fa in group_a:
                for fb in group_b:
                    if self._overlaps(fa, fb):
                        combined = self._combine(fa, fb)
                        if fb in merged:
                            merged.remove(fb)
                        idx = merged.index(fa) if fa in merged else -1
                        if idx >= 0:
                            merged[idx] = combined
                        break

        return merged

    def _overlaps(self, a: Finding, b: Finding) -> bool:
        return bool(set(a.related_events) & set(b.related_events))

    def _combine(self, primary: Finding, secondary: Finding) -> Finding:
        all_events = list(dict.fromkeys(primary.related_events + secondary.related_events))
        higher_sev = max(
            primary.severity,
            secondary.severity,
            key=lambda s: _SEVERITY_RANK.get(s, 0),
        )
        higher_conf = max(primary.confidence, secondary.confidence)

        return primary.model_copy(update={
            "severity": higher_sev,
            "confidence": min(higher_conf + 0.05, 1.0),
            "description": (
                f"{primary.description}\n\n"
                f"[Correlated with {secondary.risk_type.value}] {secondary.title}: "
                f"{secondary.description}"
            ),
            "related_events": all_events,
        })

    # -- deduplicate ---------------------------------------------------------

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Remove exact-duplicate findings (same title + same tool + same risk)."""
        seen: set[tuple[str, str, str | None]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.risk_type.value, f.title, f.tool_name)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
