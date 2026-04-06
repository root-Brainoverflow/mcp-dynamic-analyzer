"""R2: Unauthorized Code/Command Execution scanner.

Analyses ``process_exec`` (execve) syscall events to detect:
* Execution of shells (sh, bash, zsh, cmd, powershell)
* Execution of package managers (pip, npm, curl, wget) that could install malware
* Correlation: execve shortly after a fuzzing test_input ⇒ command injection succeeded
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from mcp_dynamic_analyzer.models import (
    AnalysisContext,
    Event,
    Finding,
    RiskType,
    Severity,
)
from mcp_dynamic_analyzer.scanners.base import BaseScanner

_SHELLS = {"sh", "bash", "zsh", "dash", "csh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}
_INSTALLERS = {"pip", "pip3", "npm", "npx", "yarn", "curl", "wget", "gem", "cargo"}
_DANGEROUS = _SHELLS | _INSTALLERS | {"python", "python3", "node", "perl", "ruby", "php"}


class R2CodeExecScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "r2_code_exec"

    @property
    def risk_type(self) -> RiskType:
        return RiskType.R2

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]

        exec_events: list[Event] = []
        async for evt in reader.events_by_type("process_exec"):
            exec_events.append(evt)

        fuzz_events: list[Event] = []
        async for evt in reader.events_by_type("test_input"):
            fuzz_events.append(evt)

        for evt in exec_events:
            exe = _executable(evt)
            base = exe.rsplit("/", 1)[-1].lower() if exe else ""

            if base in _SHELLS:
                findings.append(Finding(
                    risk_type=RiskType.R2,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Shell execution detected: {exe}",
                    description=f"Server spawned shell '{exe}'. argv: {evt.data.get('argv', [])}",
                    related_events=[evt.event_id],
                    reproduction="Monitor execve syscalls during server execution",
                ))

            elif base in _INSTALLERS:
                findings.append(Finding(
                    risk_type=RiskType.R2,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    title=f"Package installer execution: {exe}",
                    description=f"Server ran installer '{exe}', potentially downloading malicious code.",
                    related_events=[evt.event_id],
                    reproduction="Monitor execve for package manager invocations",
                ))

            elif base in _DANGEROUS:
                correlated = _find_preceding_fuzz(evt, fuzz_events)
                if correlated:
                    findings.append(Finding(
                        risk_type=RiskType.R2,
                        severity=Severity.CRITICAL,
                        confidence=0.9,
                        title=f"Command injection → exec: {exe}",
                        description=(
                            f"execve('{exe}') occurred within 5 s of a fuzzing payload, "
                            f"suggesting successful command injection."
                        ),
                        related_events=[evt.event_id, correlated.event_id],
                        reproduction="Send command-injection payload and monitor execve",
                    ))

        return findings


def _executable(evt: Event) -> str:
    return evt.data.get("executable", evt.data.get("path", ""))


def _find_preceding_fuzz(exec_evt: Event, fuzz_events: list[Event]) -> Event | None:
    window = timedelta(seconds=5)
    for f in reversed(fuzz_events):
        if f.ts <= exec_evt.ts and (exec_evt.ts - f.ts) <= window:
            return f
    return None
