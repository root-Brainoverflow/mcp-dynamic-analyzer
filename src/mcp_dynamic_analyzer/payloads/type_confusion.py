"""Type-confusion fuzzing payloads for R5 input validation testing.

Sends values of unexpected types to detect missing input validation:
strings where numbers are expected, nested objects, huge values,
prototype-pollution sigils, format-string sinks, and serialisation
gotchas.
"""

from __future__ import annotations

from typing import Any

PAYLOADS: dict[str, list[Any]] = {
    "null_values": [
        None,
        "",
        " ",
        [],
        {},
        (),
        0,
        False,
        "null",
        "None",
        "undefined",
        "NaN",
    ],
    "type_mismatch_string": [
        "not_a_number",
        "true",
        "false",
        "null",
        "undefined",
        "NaN",
        "Infinity",
        "-Infinity",
        "0x1337",
        "1e308",
        "1.7976931348623157e+308",
        "[]",
        "{}",
        "()",
        "/",
        "..",
        "...",
        "0o755",
        "0b1010",
    ],
    "type_mismatch_number": [
        0,
        -1,
        1,
        99999999999999,
        -99999999999999,
        2 ** 31,
        2 ** 31 - 1,
        2 ** 32,
        2 ** 53,
        2 ** 53 + 1,            # JS Number max-safe + 1 — silent precision loss
        2 ** 63 - 1,
        -(2 ** 63),
        2 ** 64,
        1.7976931348623157e308,  # float max
        5e-324,                  # smallest positive subnormal
        float("inf"),
        float("-inf"),
        # NaN intentionally absent — many JSON libs reject; included where allowed
    ],
    "type_mismatch_bool": [
        True,
        False,
        "true",
        "false",
        "True",
        "False",
        "1",
        "0",
        "yes",
        "no",
        "on",
        "off",
        1,
        0,
    ],
    "boundary_strings": [
        "",
        " ",
        "\t",
        "\n",
        "\r\n",
        "\x00",
        "\x00" * 100,
        "\xff" * 100,
        "a" * 256,
        "a" * 1_024,
        "a" * 4_096,
        "a" * 65_535,
        "a" * 65_536,             # 16-bit boundary
        "a" * 100_000,
        "a" * 1_000_000,
        "\n" * 1_000,
        "\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007",
    ],
    "nested_objects": [
        {"a": {"b": {"c": {"d": {"e": "deep"}}}}},
        [[[[[]]]]],
        # Prototype-pollution sigils
        {"__proto__": {"polluted": True}},
        {"constructor": {"prototype": {"polluted": True}}},
        {"__proto__.polluted": True},
        # Mass-assignment / framework footguns
        {"_id": "x", "isAdmin": True, "role": "admin"},
        {"$ref": "#/definitions/X"},
        # Recursive self-reference would explode JSON serialisation; we just
        # send the empty-shell shape that catches naïve recursion checks.
        {"self": "[Circular]"},
    ],
    "json_special": [
        # Duplicate keys — RFC 8259 says SHOULD be unique but parsers vary;
        # last-wins vs first-wins ambiguity is a security smell.
        '{"role":"user","role":"admin"}',
        # Trailing comma — strict parsers reject, lenient accept
        '{"a":1,}',
        # Comment in JSON — JSON5/HJSON accept, RFC 8259 rejects
        '{"a":1 /* comment */}',
        # Single-quoted keys
        "{'a':1}",
        # NaN / Infinity literals
        '{"x":NaN}',
        '{"x":Infinity}',
        # BOM prefix
        "\ufeff{\"a\":1}",
    ],
    "special_strings": [
        # XSS / template / format-string sinks
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "${7*7}",
        "{{7*7}}",
        "<%= 7*7 %>",
        "#{7*7}",
        "%s%s%s%s%s",
        "%n%n%n%n",
        "%x%x%x%x",
        "{0}{1}{2}",
        # SQL fragments (should be quoted, but type-confusion sometimes leaks)
        "1; DROP TABLE x",
        # Language-specific footguns
        "__proto__",
        "constructor.prototype",
        "toString",
        "valueOf",
        "hasOwnProperty",
    ],
    "encoding_traps": [
        # Lone surrogate — not valid UTF-8, breaks most JSON encoders
        "\ud800",
        "\udfff",
        # Surrogate pair encoded as two chars (correct UTF-16)
        "\ud83d\ude00",
        # NBSP and other invisible spaces
        "\u00a0",
        "\u2028",      # LINE SEPARATOR — JS source-injection hazard
        "\u2029",      # PARAGRAPH SEPARATOR
        "\ufeff",      # BOM mid-string
        # Bidi controls
        "test\u202etxt",
        # Combining-mark zalgo
        "z" + "\u0301" * 100,
    ],
    "id_format": [
        # Tools that expect UUID/numeric IDs often blow up on these
        "../../../etc/passwd",
        "00000000-0000-0000-0000-000000000000",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "-1",
        "9999999999999999999",
        "0",
        "true",
        "[1,2,3]",
        "{$ne: null}",
    ],
    "url_format": [
        "",
        "not a url",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "http://",
        "http:///",
        "://example.com",
        "http://[::1]/",
        "http://0/",
        "//evil.example",
    ],
    "date_format": [
        "",
        "not a date",
        "0000-00-00",
        "9999-99-99",
        "0",
        -1,
        "1970-01-01T00:00:00Z",
        "2038-01-19T03:14:08Z",      # 32-bit time_t boundary
        "9999-12-31T23:59:59Z",
        "Tue, 31 Dec 1969 23:59:59 GMT",
    ],
}


def generate_type_payloads() -> list[tuple[str, Any]]:
    """Yield ``(category, value)`` tuples for all type-confusion payloads."""
    result: list[tuple[str, Any]] = []
    for category, values in PAYLOADS.items():
        for v in values:
            result.append((category, v))
    return result


ERROR_INDICATORS: list[str] = [
    # Python
    "traceback",
    "typeerror",
    "valueerror",
    "keyerror",
    "attributeerror",
    "indexerror",
    "zerodivisionerror",
    "overflowerror",
    "recursionerror",
    "unicodedecodeerror",
    "unicodeencodeerror",
    "json.decoder.jsondecodeerror",
    "pydantic",
    "validationerror",

    # Node / JS
    "referenceerror",
    "rangeerror",
    "syntaxerror",
    "uncaught (in promise)",
    "unhandledpromiserejection",
    "stack overflow",
    "maximum call stack",
    "cannot read property",
    "cannot read properties of",
    "is not a function",
    "is not iterable",

    # Go
    "panic:",
    "runtime error:",
    "invalid memory address",
    "nil pointer dereference",
    "index out of range",

    # Java / JVM
    "nullpointerexception",
    "classcastexception",
    "numberformatexception",
    "arrayindexoutofbounds",
    "java.lang.",

    # Generic server failures
    "unhandled",
    "unhandled exception",
    "internal server error",
    "500 internal",
    "segmentation fault",
    "segfault",
    "core dumped",
]


def looks_like_unhandled_error(response_text: str) -> bool:
    """Heuristic: does the response contain an unhandled exception or crash trace?"""
    lower = response_text.lower()
    return any(ind in lower for ind in ERROR_INDICATORS)
