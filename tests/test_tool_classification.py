"""Retrieval-tool classification + strict RCE check.

ses-50a348b0 regression: ``wikipedia-mcp``'s ``search`` tool returned
articles whose bodies legitimately contained generic exploit indicators
(Unix passwd article describes ``root:x:0:0``, XXE article quotes
``file:///etc/passwd``, PHP article contains ``PHP Version``), causing
3 CRITICAL false positives. Retrieval tools require canary-only
exploitation checks because the corpus reproduces every generic
indicator string.
"""

from __future__ import annotations

import asyncio
import pathlib
import tempfile

import pytest

from mcp_dynamic_analyzer.correlation.event_store import EventStore
from mcp_dynamic_analyzer.models import AnalysisContext, Event, ToolInfo
from mcp_dynamic_analyzer.payloads.rce import (
    looks_like_rce_success,
    looks_like_rce_success_strict,
)
from mcp_dynamic_analyzer.scanners._tool_classification import (
    is_retrieval_tool,
    lookup_tool,
)


# ---------------------------------------------------------------------------
# Unit: is_retrieval_tool
# ---------------------------------------------------------------------------

def _tool(name: str, description: str = "") -> ToolInfo:
    return ToolInfo(name=name, description=description, input_schema={})


def test_is_retrieval_tool_matches_search_name() -> None:
    assert is_retrieval_tool(_tool("search")) is True
    assert is_retrieval_tool(_tool("wiki_search")) is True
    assert is_retrieval_tool(_tool("fetch_article")) is True
    assert is_retrieval_tool(_tool("scrape_url")) is True


def test_is_retrieval_tool_matches_via_description() -> None:
    # Tool literally named ``get`` (too generic to match) but described
    # as a retrieval tool — should classify via description.
    assert is_retrieval_tool(_tool("get", "Look up a Wikipedia article")) is True
    assert is_retrieval_tool(_tool("query", "Query the knowledge base")) is True


def test_is_retrieval_tool_matches_via_server_name() -> None:
    # Tool name is bland (``call``) but the host server is clearly a
    # retrieval / search server — server identity gives it away.
    assert is_retrieval_tool(_tool("call"), server_name="wikipedia-mcp") is True
    assert is_retrieval_tool(_tool("call"), server_name="Tavily MCP") is True


def test_is_retrieval_tool_excludes_calculator() -> None:
    assert is_retrieval_tool(_tool("calculate", "Evaluate math expressions")) is False
    assert is_retrieval_tool(_tool("evaluate", "Run code")) is False


def test_is_retrieval_tool_excludes_filesystem() -> None:
    # File-system / DB tools return SERVER-controlled content. Their
    # responses should be checked with normal exploitation indicators.
    assert is_retrieval_tool(_tool("read_file", "Read a local file")) is False
    assert is_retrieval_tool(_tool("git_log", "Show git history")) is False
    assert is_retrieval_tool(_tool("list_tables", "List database tables")) is False


def test_is_retrieval_tool_none_safe() -> None:
    # Missing tool metadata → conservative False (use normal indicators).
    assert is_retrieval_tool(None) is False


# ---------------------------------------------------------------------------
# Unit: looks_like_rce_success_strict
# ---------------------------------------------------------------------------

def test_strict_rce_ignores_generic_indicators() -> None:
    """The whole reason for strict mode: generic indicators are corpus
    content on retrieval tools and must NOT fire.

    Both Wikipedia excerpts below DO match generic ``RCE_INDICATORS``
    (Passwd article contains ``root:x:0:0`` which is in the XXE-leak
    indicators, PHP article contains ``PHP Version``). They're the
    canonical FP shapes from ses-50a348b0. Strict mode rejects both
    because the unique canary is absent.
    """
    wikipedia_passwd_excerpt = (
        "**Passwd**\n\npasswd is a command on Unix, Plan 9, Inferno, and "
        "most Unix-like operating systems used to change a user's password. "
        "The /etc/passwd file lists every user account with fields like "
        "root:x:0:0:root:/root:/bin/bash..."
    )
    wikipedia_php_excerpt = (
        "**PHP**\n\nPHP 8.5's release. PHP Version 8.5: 0.50% of PHP 8 ..."
    )
    # Lenient check fires on both — this IS the bug we are gating around.
    assert looks_like_rce_success(wikipedia_passwd_excerpt) is True
    assert looks_like_rce_success(wikipedia_php_excerpt) is True
    # Strict check rejects both — no canary present.
    assert looks_like_rce_success_strict(wikipedia_passwd_excerpt) is False
    assert looks_like_rce_success_strict(wikipedia_php_excerpt) is False


def test_strict_rce_still_fires_on_canary() -> None:
    """The canary IS the discriminator — when it appears in a retrieval
    tool's response, the payload was actually evaluated (Wikipedia
    cannot index a string we randomised once)."""
    # Bare canary in command output:
    assert looks_like_rce_success_strict("Output: RCE_CANARY_7f3a9c\n") is True
    # Canary embedded in a JSON-RPC response shape:
    assert looks_like_rce_success_strict(
        '{"content":[{"type":"text","text":"RCE_CANARY_7f3a9c"}]}'
    ) is True


# ---------------------------------------------------------------------------
# Unit: lookup_tool
# ---------------------------------------------------------------------------

def test_lookup_tool_finds_by_name() -> None:
    tools = [_tool("search"), _tool("calculate")]
    assert lookup_tool(tools, "search").name == "search"
    assert lookup_tool(tools, "missing") is None
    assert lookup_tool(None, "search") is None
    assert lookup_tool([], "search") is None


# ---------------------------------------------------------------------------
# End-to-end: ses-50a348b0 scenario must produce 0 findings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_wikipedia_search_produces_no_r2_rce_findings() -> None:
    """The exact response shapes from ses-50a348b0 must not produce R2
    RCE findings now that ``search`` on ``wikipedia-mcp`` classifies as
    a retrieval tool and the strict canary-only check applies."""
    from mcp_dynamic_analyzer.scanners.r2_code_exec import R2CodeExecScanner

    with tempfile.TemporaryDirectory() as td:
        store = EventStore(pathlib.Path(td))
        async with store.writer as w:
            # PHP article returned for an rce_eval_php payload — body
            # contains "PHP Version" which would normally fire RCE.
            await w.write(Event(
                session_id="s", source="test", type="test_result",
                data={
                    "tool": "search",
                    "category": "rce_eval_php",
                    "outcome": "server_response",
                    "payload_repr": "<?php system('id'); ?>",
                    "response_preview": (
                        '{"content":[{"type":"text","text":"**PHP**\\n\\n'
                        'PHP 8.5 release. PHP Version 8.5: 0.50% ..."}],'
                        '"isError":false}'
                    ),
                    "sequence": "fuzz_input_validation",
                },
            ))
            # Passwd article returned for a path_traversal-like payload —
            # body mentions root:x:0:0.
            await w.write(Event(
                session_id="s", source="test", type="test_result",
                data={
                    "tool": "search",
                    "category": "path_traversal",
                    "outcome": "server_response",
                    "payload_repr": "../etc/passwd",
                    "response_preview": (
                        '{"content":[{"type":"text","text":"**Passwd**\\n\\n'
                        'passwd is a command on Unix. The /etc/passwd file '
                        'lists every user account with fields like '
                        'root:x:0:0:root:/root:/bin/bash..."}],'
                        '"isError":false}'
                    ),
                    "sequence": "fuzz_input_validation",
                },
            ))

        ctx = AnalysisContext(
            session_id="s",
            event_reader=store.reader,
            tools=[_tool("search", "Search Wikipedia and return matching articles")],
            static_context={"server_name": "wikipedia-mcp"},
        )
        findings = await R2CodeExecScanner()._check_rce_responses(ctx)
        assert findings == [], (
            f"Expected zero RCE findings on wikipedia-mcp search results, "
            f"got: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_wikipedia_search_produces_no_r5_path_traversal_finding() -> None:
    """The same retrieval-tool gate must suppress the R5 path-traversal
    branch — a Wikipedia article on Passwd mentioning ``root:x:0:0`` is
    corpus content, not disclosure."""
    from mcp_dynamic_analyzer.scanners.r5_input_validation import R5InputValidationScanner

    with tempfile.TemporaryDirectory() as td:
        store = EventStore(pathlib.Path(td))
        async with store.writer as w:
            await w.write(Event(
                session_id="s", source="test", type="test_result",
                data={
                    "tool": "search",
                    "category": "path_traversal",
                    "outcome": "server_response",
                    "payload_repr": "../../../etc/passwd",
                    "response_preview": (
                        '{"content":[{"type":"text","text":"**Passwd**\\n\\n'
                        'The /etc/passwd file format: root:x:0:0:root:/root:/bin/bash"}],'
                        '"isError":false}'
                    ),
                    "sequence": "fuzz_input_validation",
                },
            ))
        ctx = AnalysisContext(
            session_id="s",
            event_reader=store.reader,
            tools=[_tool("search", "Search Wikipedia")],
            static_context={"server_name": "wikipedia-mcp"},
        )
        findings = await R5InputValidationScanner().analyze(ctx)
        assert not any("traversal" in f.title.lower() for f in findings), (
            f"Path traversal FP on wikipedia-mcp: {[f.title for f in findings]}"
        )


@pytest.mark.asyncio
async def test_non_retrieval_tool_keeps_normal_rce_detection() -> None:
    """The gate must not weaken detection for tools that AREN'T retrieval.
    A file-reader returning ``root:x:0:0`` from a path-traversal payload
    is a real disclosure and still fires."""
    from mcp_dynamic_analyzer.scanners.r5_input_validation import R5InputValidationScanner

    with tempfile.TemporaryDirectory() as td:
        store = EventStore(pathlib.Path(td))
        async with store.writer as w:
            await w.write(Event(
                session_id="s", source="test", type="test_result",
                data={
                    "tool": "read_file",
                    "category": "path_traversal",
                    "outcome": "server_response",
                    "payload_repr": "../../etc/passwd",
                    "response_preview": (
                        '{"content":[{"type":"text","text":"root:x:0:0:root:/root:/bin/bash\\n'
                        'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"}],'
                        '"isError":false}'
                    ),
                    "sequence": "fuzz_input_validation",
                },
            ))
        ctx = AnalysisContext(
            session_id="s",
            event_reader=store.reader,
            tools=[_tool("read_file", "Read a local file by absolute path")],
            static_context={"server_name": "filesystem-mcp"},
        )
        findings = await R5InputValidationScanner().analyze(ctx)
        assert any("traversal" in f.title.lower() for f in findings), (
            "Path-traversal TP regressed on a non-retrieval tool: "
            f"{[f.title for f in findings]}"
        )
