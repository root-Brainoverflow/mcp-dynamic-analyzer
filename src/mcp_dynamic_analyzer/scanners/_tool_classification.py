"""Heuristics for classifying MCP tool capabilities.

The exploitation-indicator scanners (R2 RCE, R5 path-traversal /
SQL / NoSQL) assume the server *produces* response text from its own
internal evaluation — a server that returns ``uid=1000`` is leaking shell
output, a server that returns ``root:x:0:0`` is leaking ``/etc/passwd``.

That assumption breaks for **retrieval tools** whose entire purpose is
to return *external corpus* content. Wikipedia's ``search`` tool returns
article bodies; arxiv returns paper abstracts; YouTube returns transcript
text. Such corpora legitimately contain every exploitation-indicator
string ever invented — the Wikipedia article on XXE attacks contains
``file:///etc/passwd`` as a literal example, the PHP article contains
``PHP Version 8.5``, the Unix passwd article contains the passwd-file
format. Pattern-matching these against ``looks_like_rce_success`` /
``looks_like_traversal_success`` produces 100 %% false positives.

ses-50a348b0 regression: ``wikipedia-mcp`` produced 3 CRITICAL findings
(RCE on PHP article, RCE on passwd article, path-traversal on XXE
article). All 3 were Wikipedia returning relevant articles for our
payload keywords — no exploitation, just retrieval doing its job.

The fix is to *recognise* retrieval tools and apply stricter checks:

* RCE detection switches to canary-only mode (``RCE_CANARY_7f3a9c``
  cannot occur in any external corpus we know of, so a match IS evidence).
* Path-traversal / SQL / NoSQL error indicators are skipped entirely —
  none of them have a canary mechanism and all rely on generic text
  patterns that retrieval-tool output reproduces by construction.
* Other R5 checks (NoSQL leak, type-confusion unhandled-error) remain;
  those depend on response *shape* rather than content keywords.
"""

from __future__ import annotations

from mcp_dynamic_analyzer.models import ToolInfo


# Patterns that suggest a tool's purpose is returning external content.
# Matched as substrings (lowercased) against tool name + description +
# server name. Kept short and recognisable — over-broad patterns
# (``get``, ``read``, ``list``) would sweep up file-system / DB tools
# whose responses ARE server-controlled and SHOULD be checked normally.
_RETRIEVAL_PATTERNS: tuple[str, ...] = (
    "search",
    "lookup",
    "retrieve",
    "fetch",
    "scrape",
    "crawl",
    "query",            # commonly used for "query a knowledge base"
    "wiki",
    "wikipedia",
    "article",
    "documentation",
    "knowledge base",
    "knowledge_base",
    "rag",
    "news",
    "feed",
    "rss",
    "arxiv",
    "youtube",
    "reddit",
    "hackernews",
    "stack overflow",
    "stackoverflow",
    "duckduckgo",
    "google search",
    "brave search",
    "tavily",
)


def is_retrieval_tool(tool: ToolInfo | None, server_name: str = "") -> bool:
    """Best-effort: does this tool primarily return external corpus content?

    Looks for retrieval-purpose keywords in the tool's name, description,
    and the host server's self-declared name. The lattermost is important
    — ``wikipedia-mcp`` exposes a tool literally named ``search`` whose
    own description ("Search Wikipedia") matches anyway, but a hypothetical
    ``wiki_get_page`` (no "search" / "wiki" in the tool name) would still
    be classified correctly via the server's identity.

    Returns False on ``None`` for safety: missing tool metadata means we
    can't classify, and falling back to "treat as normal" preserves all
    existing detection. False positives here are *under-detection* on a
    real exploit (low concern: retrieval tools are read-only API
    wrappers, not exploitation targets); false negatives waste fuzz
    budget but produce noise instead of CRITICAL FPs.
    """
    if tool is None:
        return False
    haystack_parts = [
        (tool.name or "").lower(),
        (tool.description or "").lower(),
        server_name.lower(),
    ]
    haystack = " ".join(haystack_parts)
    return any(p in haystack for p in _RETRIEVAL_PATTERNS)


def lookup_tool(tools: list[ToolInfo] | None, tool_name: str) -> ToolInfo | None:
    """Find a ToolInfo by name — small helper kept here so scanners don't
    each reimplement the linear-scan + None fallback."""
    if not tools or not tool_name:
        return None
    for t in tools:
        if t.name == tool_name:
            return t
    return None
