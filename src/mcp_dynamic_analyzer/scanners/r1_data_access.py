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
        trusted_ips: set[str] = set()
        if ctx.static_context:
            raw = ctx.static_context.get("trusted_internal_ips") or []
            trusted_ips = {str(ip) for ip in raw}

        findings.extend(await self._check_file_access(reader))
        findings.extend(await self._check_honeypot(reader))
        findings.extend(await self._check_network(reader, trusted_ips))

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

    async def _check_network(
        self,
        reader: Any,
        trusted_ips: set[str],
    ) -> list[Finding]:
        # Bucket connection attempts by (was_blocked, destination_class) so a
        # single "server doesn't validate URLs" bug doesn't fan out into N
        # findings — one per distinct target IP — that each contribute their
        # own severity to the overall score. ses-4e4da42e (RSS server) showed
        # this as two separate HIGH findings for 169.254.169.254 and 10.0.0.1
        # which are the same underlying class (link-local + RFC1918 SSRF
        # surface) tested by the analyzer's egress honeypot.
        buckets: dict[tuple[bool, str], list[tuple[str, str]]] = {}

        async for evt in reader.events_by_source("network"):
            dest = evt.data.get("destination", evt.data.get("address", ""))
            if not dest:
                continue

            host = dest.rsplit(":", 1)[0] if dest.count(":") == 1 else dest
            if host in trusted_ips:
                continue

            klass = _classify_destination(host)
            if klass is None:
                # Non-internal, non-blocked connection — not in R1's scope.
                # (R1 only flags SSRF-shaped destinations or policy blocks.)
                if evt.type != "blocked_connection":
                    continue
                klass = "other"

            blocked = evt.type == "blocked_connection"
            buckets.setdefault((blocked, klass), []).append((evt.event_id, dest))

        return [
            _build_network_finding(blocked=blocked, klass=klass, hits=hits)
            for (blocked, klass), hits in buckets.items()
        ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_sensitive(path: str) -> bool:
    lower = path.lower()
    return any(s in lower for s in _SENSITIVE_PATHS)


def _is_internal(address: str) -> bool:
    return any(address.startswith(p) for p in _INTERNAL_PREFIXES)


def _classify_destination(host: str) -> str | None:
    """Bucket *host* into a severity-relevant SSRF class.

    Returns one of:
      * ``"cloud_metadata"`` — 169.254.169.254, the AWS/GCP IMDS endpoint
        (a credential-disclosure pivot specifically, not just any internal IP).
      * ``"link_local"`` — 169.254.x.x other than the metadata endpoint.
      * ``"rfc1918"`` — 10/8, 172.16/12, 192.168/16 (broad sense of "internal
        network the host can reach").
      * ``"loopback"`` — 127.x.x.x, ::1, 0.0.0.0 (less impactful — anything
        bound on loopback is generally only reachable from the host already).
      * ``None`` — public address, not an SSRF concern.

    The distinction matters for severity: cloud-metadata access is materially
    worse than RFC1918 access (the former is a known IAM credential leak path,
    the latter just lets you scan the LAN). Lumping them together as "HIGH"
    obscures the real differential — see ses-4e4da42e for the regression.
    """
    if host == _CLOUD_METADATA:
        return "cloud_metadata"
    if host.startswith("169.254."):
        return "link_local"
    if host.startswith("10.") or host.startswith("192.168."):
        return "rfc1918"
    for p in (
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
    ):
        if host.startswith(p):
            return "rfc1918"
    if host.startswith("127.") or host == "::1" or host == "0.0.0.0":
        return "loopback"
    return None


# Severity table: (was_blocked_by_policy, destination_class) -> (Severity, conf).
# A "reached" connection scores one notch higher than a "blocked attempt" —
# the latter only proves the server *tried*, while the former proves the
# pivot actually completed.
_NETWORK_SEVERITY: dict[tuple[bool, str], tuple[Severity, float]] = {
    (False, "cloud_metadata"): (Severity.CRITICAL, 0.95),
    (False, "link_local"):     (Severity.HIGH,     0.85),
    (False, "rfc1918"):        (Severity.HIGH,     0.80),
    (False, "loopback"):       (Severity.MEDIUM,   0.70),
    (False, "other"):          (Severity.MEDIUM,   0.70),
    (True,  "cloud_metadata"): (Severity.HIGH,     0.90),
    (True,  "link_local"):     (Severity.MEDIUM,   0.80),
    (True,  "rfc1918"):        (Severity.MEDIUM,   0.80),
    (True,  "loopback"):       (Severity.LOW,      0.70),
    (True,  "other"):          (Severity.MEDIUM,   0.75),
}

_CLASS_LABEL: dict[str, str] = {
    "cloud_metadata": "cloud metadata endpoint (169.254.169.254)",
    "link_local":     "link-local addresses (169.254.0.0/16)",
    "rfc1918":        "RFC1918 private network addresses",
    "loopback":       "loopback / localhost",
    "other":          "external addresses",
}


def _build_network_finding(
    *,
    blocked: bool,
    klass: str,
    hits: list[tuple[str, str]],
) -> Finding:
    severity, confidence = _NETWORK_SEVERITY[(blocked, klass)]
    label = _CLASS_LABEL[klass]
    targets = sorted({dest for _, dest in hits})
    targets_preview = ", ".join(targets[:5]) + (f" (+{len(targets) - 5} more)" if len(targets) > 5 else "")
    verb = "blocked by policy" if blocked else "reached"
    # Cardinality-aware title: show the concrete IP when there's only one
    # target (more actionable for a reader skimming the report), the count
    # plus class label when several distinct destinations collapsed into the
    # bucket. The full target list is always in the description either way.
    if klass == "cloud_metadata":
        title = f"SSRF — cloud metadata access {verb} ({targets[0]})"
    elif len(targets) == 1:
        title = f"SSRF attempt — {targets[0]} {verb}"
    else:
        title = f"SSRF attempt — {verb} {len(targets)} {label.split(' (')[0]} destination(s)"
    description = (
        f"Server attempted to connect to {label}; the network monitor "
        f"{'blocked' if blocked else 'observed'} {len(hits)} connection attempts across "
        f"{len(targets)} distinct destination(s): {targets_preview}. "
        f"This typically indicates the server fetches user-supplied URLs without "
        f"validating against private / metadata IP ranges — a single missing-validation "
        f"bug, not N independent issues."
    )
    return Finding(
        risk_type=RiskType.R1,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        related_events=[evt_id for evt_id, _ in hits],
        reproduction=(
            f"Pass a URL containing one of the listed destinations to a tool "
            f"that fetches user-supplied URLs"
        ),
    )
