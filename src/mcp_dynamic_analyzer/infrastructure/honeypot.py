"""Honeypot file generation and access monitoring.

Creates decoy credential files (SSH keys, AWS creds, .env, etc.)
in a temporary directory.  Each file contains a unique UUID *canary*
so that if its content appears in a server response, we can pinpoint
exactly which file was exfiltrated.

Access monitoring uses a polling loop (cross-platform) that checks
file access times.  On Linux, inotifywait is used when available.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Any
from uuid import uuid4

import structlog

from mcp_dynamic_analyzer.correlation.event_store import EventWriter
from mcp_dynamic_analyzer.models import Event

log = structlog.get_logger()

# Template: (relative_path, content_template)
# ``{canary}`` is replaced with a unique UUID per session.
_TEMPLATES: list[tuple[str, str]] = [
    (
        ".ssh/id_rsa",
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "CANARY:{canary}\n"
        "MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF\n"
        "-----END RSA PRIVATE KEY-----\n",
    ),
    (
        ".aws/credentials",
        "[default]\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = CANARY:{canary}\n",
    ),
    (
        ".env",
        "DATABASE_URL=postgres://user:CANARY:{canary}@localhost/db\n"
        "SECRET_KEY=CANARY:{canary}\n",
    ),
    (
        ".kube/config",
        "apiVersion: v1\nclusters:\n- cluster:\n"
        "    server: https://k8s.example.com\n"
        "    certificate-authority-data: CANARY:{canary}\n",
    ),
    (
        ".git-credentials",
        "https://user:CANARY:{canary}@github.com\n",
    ),
]


class Honeypot:
    """Manages honeypot decoy files and monitors their access.

    Usage::

        hp = Honeypot(writer, session_id)
        hp.create()                     # generates files in a temp dir
        path = hp.directory             # mount this into the sandbox
        canaries = hp.canaries          # {canary_uuid: file_path}
        await hp.start_monitoring()     # begin access polling
        ...
        await hp.stop_monitoring()
        hp.cleanup()
    """

    def __init__(self, writer: EventWriter, session_id: str) -> None:
        self._writer = writer
        self._session_id = session_id
        self._dir: Path | None = None
        self._canaries: dict[str, str] = {}  # canary_uuid → relative_path
        self._task: asyncio.Task[None] | None = None
        self._stop = False

    @property
    def directory(self) -> Path:
        assert self._dir is not None
        return self._dir

    @property
    def canaries(self) -> dict[str, str]:
        return dict(self._canaries)

    # -- lifecycle -----------------------------------------------------------

    def create(self) -> Path:
        """Generate honeypot files in a fresh temp directory."""
        self._dir = Path(tempfile.mkdtemp(prefix="mcp-honeypot-"))

        for rel_path, template in _TEMPLATES:
            canary = str(uuid4())
            self._canaries[canary] = rel_path

            full = self._dir / rel_path
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(template.format(canary=canary))
            os.chmod(full, 0o644)

        log.info("honeypot.created", dir=str(self._dir), files=len(self._canaries))
        return self._dir

    def cleanup(self) -> None:
        """Remove all honeypot files."""
        if self._dir and self._dir.exists():
            import shutil
            shutil.rmtree(self._dir, ignore_errors=True)
            log.info("honeypot.cleaned")

    # -- monitoring ----------------------------------------------------------

    async def start_monitoring(self) -> None:
        """Begin polling for file access changes."""
        self._stop = False
        self._snapshot = self._take_snapshot()
        self._task = asyncio.create_task(self._poll_loop(), name="honeypot-monitor")

    async def stop_monitoring(self) -> None:
        self._stop = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _poll_loop(self) -> None:
        """Poll access times every 0.5 s and emit events on change."""
        try:
            while not self._stop:
                await asyncio.sleep(0.5)
                current = self._take_snapshot()
                for rel_path, atime in current.items():
                    prev = self._snapshot.get(rel_path)
                    if prev is not None and atime > prev:
                        await self._emit_access(rel_path)
                self._snapshot = current
        except asyncio.CancelledError:
            pass

    def _take_snapshot(self) -> dict[str, float]:
        """Return {relative_path: last_access_time} for all honeypot files."""
        if not self._dir:
            return {}
        snap: dict[str, float] = {}
        for canary, rel_path in self._canaries.items():
            full = self._dir / rel_path
            if full.exists():
                snap[rel_path] = full.stat().st_atime
        return snap

    async def _emit_access(self, rel_path: str) -> None:
        canary = next((c for c, p in self._canaries.items() if p == rel_path), None)
        await self._writer.write(Event(
            session_id=self._session_id,
            source="honeypot",
            type="honeypot_access",
            data={"path": rel_path, "canary": canary},
        ))
        log.warning("honeypot.access", path=rel_path)

    # -- canary scanning (called from R1 or R3 analysis) ---------------------

    def scan_text_for_canaries(self, text: str) -> list[str]:
        """Return list of canary UUIDs found in *text*."""
        return [c for c in self._canaries if c in text]
