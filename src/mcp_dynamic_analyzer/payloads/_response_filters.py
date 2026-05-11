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

# Hand-written enum validation: ``Invalid <field> provided: '<payload>'.``
# Strip the quoted payload so RCE / SQL indicators inside don't leak through
# to the success heuristics.
_ENUM_INVALID_ECHO_RE = re.compile(
    r"[Ii]nvalid\s+[^:]+?:\s*'[^']*'",
)

# Substrings that mean "the server refused this input before doing anything
# observable". If any appears, the canary / RCE indicator that came along with
# the payload is reflection, not execution.
_VALIDATION_REJECTION_MARKERS: tuple[str, ...] = (
    # Pydantic
    "validation error for",
    "field required",
    "type=missing",
    "type_error",
    "value_error",
    "pydantic.error",
    "errors.pydantic.dev",
    "input should be",      # pydantic v2 phrasing
    # jsonschema
    "jsonschemavalidationerror",
    "schema validation",
    "validationerror",
    "extra fields not permitted",
    "value is not a valid",
    "missing required",
    # Generic / hand-written enum validation messages.
    # Servers like crystaldba/postgres-mcp's ``analyze_db_health`` echo
    # the rejected payload back inside ``Invalid X provided: '<payload>'.
    # Valid values are: ...`` style errors, which then false-matches every
    # RCE / command-injection / SQL indicator in the payload.
    "valid values are",
    "valid options are",
    "must be one of",
    "please try again",
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
    out = _ENUM_INVALID_ECHO_RE.sub("Invalid <redacted>", out)
    return out


# Minimum length of a payload substring before we mask its echo in the
# response. Below this threshold, common short tokens (``id``, ``ls``,
# single chars) would coincidentally appear in legitimate output and we'd
# wrongly strip them.
_MIN_REFLECTION_LEN = 12

_SLASH_RUN_RE = re.compile(r"/{2,}")
_BACKSLASH_RUN_RE = re.compile(r"\\{2,}")
_WS_RUN_RE = re.compile(r"\s{2,}")


def _payload_echo_variants(payload_repr: str) -> list[str]:
    """Plausible forms of *payload_repr* after common server normalisation.

    Servers routinely transform input before echoing it back in an error:
      * ``os.path.normpath`` / ``pathlib`` collapse ``//`` -> ``/``
        (mcp-server-git: ``${jndi:ldap://...}`` echoed as ``${jndi:ldap:/...}``)
      * Windows path joins collapse ``\\\\`` -> ``\\``
      * Whitespace runs collapse to a single space

    We replicate each transform on the payload (cheaper and more precise
    than normalising the whole response, which would shift offsets and
    break a clean ``.replace``). Only variants long enough to be
    meaningful are returned.
    """
    variants: list[str] = []
    seen: set[str] = set()

    def _add(v: str) -> None:
        if len(v) >= _MIN_REFLECTION_LEN and v not in seen:
            seen.add(v)
            variants.append(v)

    _add(payload_repr)
    _add(_SLASH_RUN_RE.sub("/", payload_repr))
    _add(_BACKSLASH_RUN_RE.sub("\\\\", payload_repr))
    _add(_WS_RUN_RE.sub(" ", payload_repr))
    # Combined slash + whitespace collapse.
    _add(_WS_RUN_RE.sub(" ", _SLASH_RUN_RE.sub("/", payload_repr)))
    return variants


def strip_payload_echo(response: str, payload_repr: str) -> str:
    """Mask occurrences of *payload_repr* in *response* with ``<payload>``.

    Server-agnostic reflection handling — replaces every hand-written
    ``strip_*_echo`` regex (``Repository path 'X' is outside``,
    ``Invalid X provided: 'Y'``, Pydantic ``input_value={...}``, ...).

    Also masks common *normalised* forms of the payload (slash-collapse,
    whitespace-collapse), because servers often run input through
    ``os.path.normpath`` / similar before echoing — a byte-exact match
    alone misses those (``${jndi:ldap://...}`` -> echoed ``${jndi:ldap:/...}``).

    Unlike a blanket skip-on-echo, this preserves any indicator that
    survives outside the echoed region. So a real exploitation that ALSO
    echoes the payload (``Executed '<payload>': RCE_CANARY``) still fires
    because the canary lives outside the masked region. Only the
    "rejected and reflected" pattern (indicator ONLY inside the echo)
    is silenced.

    Short payloads (<12 chars) are left untouched so legitimate output
    containing common tokens (``id``, ``ls``) isn't masked away.
    """
    if not payload_repr or not response:
        return response
    if len(payload_repr) < _MIN_REFLECTION_LEN:
        return response
    out = response
    for variant in _payload_echo_variants(payload_repr):
        out = out.replace(variant, "<payload>")
    return out


def response_echoes_payload(response: str, payload_repr: str) -> bool:
    """Diagnostic: does *response* contain *payload_repr* verbatim?

    Used as a *boolean* signal for legacy callers; prefer
    ``strip_payload_echo`` + indicator matching for correctness. Kept
    because backward-compat and explicit "this WAS a reflection event"
    logging is occasionally useful.
    """
    if not payload_repr or not response:
        return False
    if len(payload_repr) < _MIN_REFLECTION_LEN:
        return False
    return payload_repr in response


# Outcomes whose ``response_preview`` is text the server actually produced.
# Indicator matching (RCE / SSTI / OOM / traceback / ...) is only meaningful
# on these. Running it on client-side wrappers (``ClientSerializationError:
# ValueError: ...``) would falsely match indicators in our own message —
# which is exactly the bug that produced 18 phantom R5 findings on
# playwright-mcp in session ses-32f4a3fd.
_SERVER_OUTCOMES = frozenset({"server_response", "server_error"})


_LEGACY_CLIENT_PREFIXES = (
    "ClientSerializationError:",
    "CallTimeout:",
    "Exception:",
)


def is_server_outcome(outcome: str | None, response: str = "") -> bool:
    """True iff the response text was sent by the server.

    For events written by current code, ``outcome`` is the source of truth.
    Legacy events (no ``outcome`` field) fall back to scanning the response
    prefix for known client-side wrapper markers — ``ClientSerializationError:``,
    ``CallTimeout:``, ``Exception:`` — so re-analysing old session logs
    doesn't suddenly produce phantom findings on our own wrapper text.
    """
    if outcome is not None:
        return outcome in _SERVER_OUTCOMES
    # Legacy compat path.
    for prefix in _LEGACY_CLIENT_PREFIXES:
        if response.startswith(prefix):
            return False
    return True
