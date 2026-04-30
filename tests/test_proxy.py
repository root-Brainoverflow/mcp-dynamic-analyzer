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
