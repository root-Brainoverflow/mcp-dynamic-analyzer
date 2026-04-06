"""R1: Unauthorized Data Access / Exfiltration scanner.

Analyses syscall, honeypot, and network events collected during the
execution phase to detect:

* Access to sensitive file paths (credentials, keys, configs)
* Honeypot canary file access or canary string leakage in responses
* Outbound network connections to unexpected destinations
* SSRF attempts (connections to internal IP ranges / cloud metadata)
"""

from __future__ import annotations

from typing import Any

import structlog

from mcp_dynamic_analyzer.models import (
    AnalysisContext,
    Event,
    Finding,
    RiskType,
    Severity,
)
from mcp_dynamic_analyzer.scanners.base import BaseScanner

log = structlog.get_logger()

# Sensitive paths that a well-behaved MCP server should never touch.
_SENSITIVE_PATHS: list[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    ".ssh/",
    ".aws/",
    ".kube/",
    ".git-credentials",
    ".env",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "credentials",
    "secrets",
]

# Internal IP ranges — connections here may indicate SSRF.
_INTERNAL_PREFIXES: list[str] = [
    "169.254.",      # link-local / cloud metadata
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "0.0.0.0",
]

_CLOUD_METADATA = "169.254.169.254"


class R1DataAccessScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "r1_data_access"

    @property
    def risk_type(self) -> RiskType:
        return RiskType.R1

    async def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        reader = ctx.event_reader  # type: ignore[union-attr]

        findings.extend(await self._check_file_access(reader))
        findings.extend(await self._check_honeypot(reader))
        findings.extend(await self._check_network(reader))

        return findings

    # -- file access ---------------------------------------------------------

    async def _check_file_access(self, reader: Any) -> list[Finding]:
        findings: list[Finding] = []
        file_types = ("file_open", "file_read", "file_write")

        for ft in file_types:
            async for evt in reader.events_by_type(ft):
                path = evt.data.get("path", "")
                if _is_sensitive(path):
                    findings.append(Finding(
                        risk_type=RiskType.R1,
                        severity=Severity.HIGH,
                        confidence=0.85,
                        title=f"Access to sensitive path: {path}",
                        description=(
                            f"Server performed '{evt.type}' on '{path}', "
                            f"which is a sensitive credential or config file."
                        ),
                        related_events=[evt.event_id],
                        reproduction=f"Monitor syscalls during server execution for {ft} on {path}",
                    ))

        return findings

    # -- honeypot ------------------------------------------------------------

    async def _check_honeypot(self, reader: Any) -> list[Finding]:
        findings: list[Finding] = []

        async for evt in reader.events_by_type("honeypot_access"):
            findings.append(Finding(
                risk_type=RiskType.R1,
                severity=Severity.CRITICAL,
                confidence=0.95,
                title=f"Honeypot file accessed: {evt.data.get('path', '?')}",
                description="Server accessed a honeypot decoy file planted for detection.",
                related_events=[evt.event_id],
                reproduction="Place honeypot files and monitor inotify events",
            ))

        async for evt in reader.events_by_type("canary_detected"):
            findings.append(Finding(
                risk_type=RiskType.R1,
                severity=Severity.CRITICAL,
                confidence=0.95,
                title="Canary string leaked in server response",
                description=(
                    f"A honeypot canary UUID was found in a server response, "
                    f"confirming data exfiltration. Canary: {evt.data.get('canary', '?')}"
                ),
                related_events=[evt.event_id],
                reproduction="Check server responses for honeypot canary UUIDs",
            ))

        return findings

    # -- network -------------------------------------------------------------

    async def _check_network(self, reader: Any) -> list[Finding]:
        findings: list[Finding] = []

        async for evt in reader.events_by_source("network"):
            dest = evt.data.get("destination", evt.data.get("address", ""))
            if not dest:
                continue

            if evt.type == "blocked_connection":
                findings.append(Finding(
                    risk_type=RiskType.R1,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    title=f"Blocked outbound connection to {dest}",
                    description="Server attempted a network connection that was blocked by policy.",
                    related_events=[evt.event_id],
                    reproduction=f"Monitor network connections for attempts to {dest}",
                ))
                continue

            if _CLOUD_METADATA in dest:
                findings.append(Finding(
                    risk_type=RiskType.R1,
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    title=f"SSRF: cloud metadata access attempt ({dest})",
                    description="Server attempted to reach cloud metadata endpoint 169.254.169.254.",
                    related_events=[evt.event_id],
                    reproduction="Check network events for 169.254.169.254 connections",
                ))
            elif _is_internal(dest):
                findings.append(Finding(
                    risk_type=RiskType.R1,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    title=f"SSRF: internal network access attempt ({dest})",
                    description=f"Server attempted to connect to internal address {dest}.",
                    related_events=[evt.event_id],
                    reproduction=f"Check network events for connections to {dest}",
                ))

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_sensitive(path: str) -> bool:
    lower = path.lower()
    return any(s in lower for s in _SENSITIVE_PATHS)


def _is_internal(address: str) -> bool:
    return any(address.startswith(p) for p in _INTERNAL_PREFIXES)
