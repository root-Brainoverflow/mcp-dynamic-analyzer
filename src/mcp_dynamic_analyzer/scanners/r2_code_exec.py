"""R2: Unauthorized Code/Command Execution scanner.

Analyses:
* ``process_exec`` (execve) syscall events — shell / installer spawning
* ``test_result`` events from R5 fuzzing — RCE indicator strings in responses
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
from mcp_dynamic_analyzer.payloads._response_filters import (
    is_server_outcome,
    is_validation_rejection,
    strip_payload_echo,
)
from mcp_dynamic_analyzer.payloads.rce import (
    looks_like_rce_success,
    looks_like_rce_success_strict,
)
from mcp_dynamic_analyzer.scanners._tool_classification import (
    is_retrieval_tool,
    lookup_tool,
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

        # Syscall-level analysis.
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

        # Response-text analysis — RCE output in fuzz results.
        findings.extend(await self._check_rce_responses(ctx))

        return findings

    async def _check_rce_responses(self, ctx: AnalysisContext) -> list[Finding]:
        """Check fuzz test_result events for RCE-indicator strings in responses."""
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]
        # Server name is used by retrieval-tool classification (a tool literally
        # named ``search`` on ``wikipedia-mcp`` should be classified differently
        # from one on ``mcp-server-git``). ``static_context`` carries the
        # discovered ``serverInfo.name``; fall back to empty string when absent.
        # ``getattr`` keeps lightweight test stubs (no ``static_context``
        # attribute) working alongside the real ``AnalysisContext``.
        server_name = ""
        static = getattr(ctx, "static_context", None)
        if static:
            server_name = str(static.get("server_name", "") or "")

        async for evt in reader.events_by_type("test_result"):
            resp = evt.data.get("response_preview", "")
            if not resp:
                continue
            # Skip client-side wrappers (timeout / serialisation error / ...) —
            # those carry text we wrote ourselves, not server output.
            outcome = evt.data.get("outcome")
            if not is_server_outcome(outcome, resp):
                continue
            # If the server rejected the payload at the validation layer,
            # any RCE-looking string in the response is just payload reflection.
            if is_validation_rejection(resp):
                continue
            # Mask payload echoes so reflected canaries don't count as RCE.
            # A real RCE produces command output OUTSIDE the echo region,
            # which survives the mask and still fires the check.
            payload_repr = evt.data.get("payload_repr", "")
            masked = strip_payload_echo(resp, payload_repr)

            # Retrieval tools (search / wiki / fetch / docs / RAG / ...) return
            # external corpus content that legitimately reproduces every generic
            # RCE indicator. ses-50a348b0: wikipedia-mcp's ``search`` returned
            # articles about ``passwd`` (Unix command, mentions ``uid=``), PHP
            # (mentions ``PHP Version``), XXE (mentions ``file:///etc/passwd``)
            # → 3 CRITICAL FPs. For those tools, only the unique canary counts
            # as evidence: ``RCE_CANARY_7f3a9c`` isn't indexed by any corpus, so
            # appearing in the response means the payload was actually evaluated.
            tool_name = evt.data.get("tool", "unknown")
            tool_info = lookup_tool(ctx.tools, tool_name)
            strict = is_retrieval_tool(tool_info, server_name)
            matched = (
                looks_like_rce_success_strict(masked)
                if strict
                else looks_like_rce_success(masked)
            )
            if matched:
                cat = evt.data.get("category", "")
                findings.append(Finding(
                    risk_type=RiskType.R2,
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    title=f"RCE indicator in response for tool '{tool_name}' (category '{cat}')",
                    description=(
                        f"Tool '{tool_name}' returned content matching RCE success indicators "
                        f"after being sent a '{cat}' payload. "
                        f"Response excerpt: {resp[:300]}"
                    ),
                    related_events=[evt.event_id],
                    tool_name=tool_name,
                    reproduction=f"Send '{cat}' payload to tool '{tool_name}' and inspect response",
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
