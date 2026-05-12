"""Tests for protocol interceptors."""

from __future__ import annotations

import asyncio

from mcp_dynamic_analyzer.protocol.interceptor import StdioInterceptor


class _DummyWriter:
    def __init__(self) -> None:
        self.buffer = bytearray()

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None


class _RecordingEventWriter:
    def __init__(self) -> None:
        self.events = []

    async def write(self, event) -> None:
        self.events.append(event)


async def test_stdio_interceptor_escapes_surrogates_on_wire() -> None:
    stdin = _DummyWriter()
    stdout = asyncio.StreamReader()
    writer = _RecordingEventWriter()
    interceptor = StdioInterceptor(stdin, stdout, writer, "ses-test")

    await interceptor._write_to_server(  # noqa: SLF001 - unit test on wire serializer
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"arguments": {"text": "\ud800"}},
        },
        direction="c2s",
    )

    raw = stdin.buffer.decode("utf-8")
    assert "\\ud800" in raw
    assert len(writer.events) == 1


async def test_read_loop_survives_oversized_line() -> None:
    """A response line larger than the StreamReader limit must NOT crash the
    interceptor or be mistaken for a server crash.

    Regression: a well-behaved server (mcp-server-time) echoed our 10 MB
    ``memory_bomb`` payload back inside its "Invalid timezone" error, making
    a single response line ~10 MB. With an 8 MB read limit, ``readline()``
    raised ``LimitOverrunError`` -> ``ValueError``; ``_read_loop`` crashed
    and the orchestrator reported a phantom R6 ``server_crash``. The fix
    catches the ValueError, skips the oversized line, and keeps reading.
    """
    import json

    stdin = _DummyWriter()
    # Small limit so we can trigger the overflow with a modest line.
    stdout = asyncio.StreamReader(limit=4096)
    writer = _RecordingEventWriter()
    interceptor = StdioInterceptor(stdin, stdout, writer, "ses-test")
    await interceptor.start()

    # 1) Feed an oversized line (>4 KB, no chance for readline to find \n
    #    within the limit) — this is the "server echoed a huge payload" case.
    oversized = b'{"jsonrpc":"2.0","id":1,"result":{"x":"' + b"A" * 8192 + b'"}}\n'
    stdout.feed_data(oversized)
    await asyncio.sleep(0.05)

    # 2) Feed a normal, well-formed response afterwards.
    normal = json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"ok": True}}).encode() + b"\n"
    stdout.feed_data(normal)
    await asyncio.sleep(0.05)

    # The interceptor must NOT have flagged a server crash.
    assert interceptor.server_died is False

    # The normal response after the oversized one must have been recorded —
    # proving the read loop survived and kept going.
    s2c_ids = [
        e.data.get("message", {}).get("id")
        for e in writer.events
        if e.direction == "s2c"
    ]
    assert 2 in s2c_ids

    stdout.feed_eof()
    await interceptor.close()
