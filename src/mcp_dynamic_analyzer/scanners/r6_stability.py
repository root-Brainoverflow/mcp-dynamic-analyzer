"""R6: Service Stability Threats scanner.

Analyses collected events for indicators of DoS / resource-exhaustion risks:
* Server crashes during testing (``server_crash`` events)
* Sequence timeouts (potential hang / infinite loop)
* Excessive error rates in tool-call responses
* MCP error responses with concerning patterns
"""

from __future__ import annotations

from typing import Any

from mcp_dynamic_analyzer.models import (
    AnalysisContext,
    Event,
    Finding,
    RiskType,
    Severity,
)
from mcp_dynamic_analyzer.scanners.base import BaseScanner


class R6StabilityScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "r6_stability"

    @property
    def risk_type(self) -> RiskType:
        return RiskType.R6

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]

        findings.extend(await self._check_crashes(reader))
        findings.extend(await self._check_timeouts(reader))
        findings.extend(await self._check_error_rate(reader))

        return findings

    async def _check_crashes(self, reader: Any) -> list[Finding]:
        findings: list[Finding] = []
        async for evt in reader.events_by_type("server_crash"):
            seq = evt.data.get("sequence", "unknown")
            findings.append(Finding(
                risk_type=RiskType.R6,
                severity=Severity.HIGH,
                confidence=0.9,
                title=f"Server crashed during sequence '{seq}'",
                description=(
                    f"The MCP server process terminated unexpectedly while "
                    f"running test sequence '{seq}'. This indicates fragile "
                    f"error handling that could be exploited for DoS."
                ),
                related_events=[evt.event_id],
                reproduction=f"Run sequence '{seq}' and observe server process",
            ))
        return findings

    async def _check_timeouts(self, reader: Any) -> list[Finding]:
        findings: list[Finding] = []
        async for evt in reader.events_by_type("sequence_timeout"):
            seq = evt.data.get("sequence", "unknown")
            findings.append(Finding(
                risk_type=RiskType.R6,
                severity=Severity.MEDIUM,
                confidence=0.7,
                title=f"Sequence timeout: '{seq}'",
                description=(
                    f"Test sequence '{seq}' did not complete within its timeout. "
                    f"The server may hang on certain inputs, enabling resource exhaustion."
                ),
                related_events=[evt.event_id],
                reproduction=f"Run sequence '{seq}' with its specific inputs",
            ))
        return findings

    async def _check_error_rate(self, reader: Any) -> list[Finding]:
        """Flag if a large fraction of tool calls returned errors."""
        total_calls = 0
        error_calls = 0

        async for evt in reader.events_by_type("mcp_response"):
            msg = evt.data.get("message", {})
            if evt.direction != "s2c":
                continue
            total_calls += 1
            if "error" in msg:
                error_calls += 1

        findings: list[Finding] = []
        if total_calls >= 5:
            rate = error_calls / total_calls
            if rate >= 0.5:
                findings.append(Finding(
                    risk_type=RiskType.R6,
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    title=f"High error rate: {error_calls}/{total_calls} ({rate:.0%})",
                    description=(
                        f"{error_calls} out of {total_calls} server responses were errors. "
                        f"This suggests poor input validation or unstable implementation."
                    ),
                    reproduction="Review error responses across all tool calls",
                ))

        return findings
