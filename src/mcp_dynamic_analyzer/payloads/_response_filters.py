"""Filters that distinguish real exploit success from payload reflection.

When a server rejects a fuzzing payload at validation (Pydantic, JSON Schema,
etc.) its error response often echoes the original input. RCE / disclosure
indicators inside that echo look identical to a real exploit hit but the
payload never executed — the server short-circuited at the schema layer.

Two complementary helpers:

``is_validation_rejection``
    True when the response is *clearly* a validation rejection. Used by
    scanners to short-circuit ``looks_like_*_success`` checks entirely.

``strip_input_echoes``
    Removes framework-specific ``input_value=...`` / ``instance: ...``
    spans before substring matching. Used by the ``looks_like_*`` heuristics
    so any indicator that survives the strip is more likely real output.
"""

from __future__ import annotations

import re

# Pydantic v2 emits ``... input_value=<value>, input_type=<type> ...`` in its
# validation errors. The value can span multi-line so use DOTALL and stop at
# the first ``, input_type=`` boundary or end-of-line.
_PYDANTIC_INPUT_ECHO_RE = re.compile(
    r"input_value=.*?(?=,\s*input_type=|\n|$)",
    re.DOTALL,
)

# jsonschema's ValidationError formats the offending value as
# ``... instance: <value> ...`` (typically followed by ``schema:`` or EOL).
_JSONSCHEMA_INSTANCE_RE = re.compile(
    r"instance:\s*.*?(?=\n\s*(?:schema|on instance)|\n|$)",
    re.DOTALL,
)

# PostgreSQL syntax / parse errors echo the offending SQL as
# ``LINE 1: <sql>`` followed by an optional caret marker. The same regex
# also catches MySQL ``near '<sql>' at line N`` and SQLite parser dumps.
# This is the second-most common reflection vector after Pydantic.
_POSTGRES_QUERY_ECHO_RE = re.compile(
    r"LINE \d+:[^\n]*(?:\n[ \t]*\^[ \t]*)?",
)
_MYSQL_NEAR_ECHO_RE = re.compile(
    r"near '[^']*' at line \d+",
)

# Substrings that mean "the server refused this input before doing anything
# observable". If any appears, the canary / RCE indicator that came along with
# the payload is reflection, not execution.
_VALIDATION_REJECTION_MARKERS: tuple[str, ...] = (
    "validation error for",
    "field required",
    "type=missing",
    "type_error",
    "value_error",
    "pydantic.error",
    "errors.pydantic.dev",
    "jsonschemavalidationerror",
    "schema validation",
    "validationerror",
    "extra fields not permitted",
    "value is not a valid",
    "input should be",      # pydantic v2 phrasing
    "missing required",
)


def is_validation_rejection(response_text: str) -> bool:
    """True iff *response_text* is clearly a schema-validation rejection."""
    if not response_text:
        return False
    lower = response_text.lower()
    return any(marker in lower for marker in _VALIDATION_REJECTION_MARKERS)


def strip_input_echoes(response_text: str) -> str:
    """Mask framework input-value echoes that reflect the original payload.

    Removes the regions where Pydantic, jsonschema, or SQL parsers echo the
    user-supplied input back into their error messages. After stripping, any
    surviving exploit indicator is more likely from the server's own behaviour
    than from a payload echo.
    """
    if not response_text:
        return response_text
    out = _PYDANTIC_INPUT_ECHO_RE.sub("input_value=<redacted>", response_text)
    out = _JSONSCHEMA_INSTANCE_RE.sub("instance: <redacted>", out)
    out = _POSTGRES_QUERY_ECHO_RE.sub("LINE <redacted>", out)
    out = _MYSQL_NEAR_ECHO_RE.sub("near <redacted>", out)
    return out
