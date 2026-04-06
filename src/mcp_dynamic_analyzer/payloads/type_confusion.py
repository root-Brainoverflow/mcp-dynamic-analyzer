"""Type-confusion fuzzing payloads for R5 input validation testing.

Sends values of unexpected types to detect missing input validation:
strings where numbers are expected, nested objects, huge values, etc.
"""

from __future__ import annotations

from typing import Any

PAYLOADS: dict[str, list[Any]] = {
    "null_values": [None, "", [], {}],
    "type_mismatch_string": [
        "not_a_number",
        "true",
        "null",
        "undefined",
        "NaN",
        "Infinity",
        "-Infinity",
    ],
    "type_mismatch_number": [
        0,
        -1,
        99999999999999,
        -99999999999999,
        1.7976931348623157e308,  # float max
        float("inf"),
        float("-inf"),
    ],
    "boundary_strings": [
        "",
        " ",
        "a" * 10_000,
        "a" * 100_000,
        "\x00",
        "\x00" * 100,
        "\n" * 1000,
    ],
    "nested_objects": [
        {"a": {"b": {"c": {"d": {"e": "deep"}}}}},
        [[[[[]]]]],
        {"__proto__": {"polluted": True}},
        {"constructor": {"prototype": {"polluted": True}}},
    ],
    "special_strings": [
        "<script>alert(1)</script>",
        "${7*7}",
        "{{7*7}}",
        "%s%s%s%s%s",
        "%n%n%n%n",
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
    "traceback",
    "typeerror",
    "valueerror",
    "keyerror",
    "attributeerror",
    "referenceerror",
    "rangeerror",
    "stack overflow",
    "maximum call stack",
    "unhandled",
    "internal server error",
    "panic:",
]


def looks_like_unhandled_error(response_text: str) -> bool:
    """Heuristic: does the response contain an unhandled exception or crash trace?"""
    lower = response_text.lower()
    return any(ind in lower for ind in ERROR_INDICATORS)
