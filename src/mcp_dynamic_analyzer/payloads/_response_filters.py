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

import json
import re
from urllib.parse import quote, quote_plus

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


def is_clean_success_envelope(response_text: str) -> bool:
    """True iff *response_text* is a *successful* structured tool result.

    A server that returns clean data is, by definition, not malfunctioning —
    whatever error-looking strings the data happens to contain (GitHub issue
    titles like ``"Cannot read properties of undefined"``, Stack Overflow
    links, log excerpts, ...). This gate is used by the **server-malfunction**
    indicators (unhandled-error / OOM / stack-overflow / parser-failure) so
    they don't fire on legitimate returned content. It is **not** applied to
    the exploitation-success indicators (RCE / injection / traversal), which
    legitimately match on a successful response carrying command output.

    Heuristic: the preview parses as a JSON object, carries no ``isError: true``
    flag and no top-level ``error`` key. (``response_preview`` is the tool
    *result* dict — typically ``{"content": [...], "isError": false}`` — not
    the JSON-RPC envelope.)

    The preview is truncated (~2 KB), so a large successful result won't parse.
    Fallback: it starts with the MCP success-result wrapper ``{"content"`` and
    the visible portion shows no ``"isError": true`` — true of a truncated data
    response, false of a (short, fully-visible) error envelope.
    """
    if not response_text:
        return False
    s = response_text.lstrip()
    try:
        obj = json.loads(s)
    except (json.JSONDecodeError, ValueError):
        obj = None
    if isinstance(obj, dict):
        return obj.get("isError") is not True and "error" not in obj
    # Truncated preview — couldn't parse. Treat as success only if it opens
    # with the content wrapper, shows no error flag in what we can see, and the
    # visible text carries no unmistakable error marker (``Traceback (most
    # recent ...``, FastMCP's ``Error executing tool ...`` wrapper). This keeps
    # us from suppressing a finding on a server that dumped a huge traceback
    # whose ``isError:true`` got truncated off the end.
    if not s.startswith('{"content"'):
        return False
    low = s.lower()
    if '"iserror": true' in low or '"iserror":true' in low:
        return False
    if "traceback (most recent" in low or "error executing tool" in low:
        return False
    return True


def is_handled_tool_error(response_text: str) -> bool:
    """True iff the response is an error the server *caught and returned*.

    FastMCP-style servers wrap a tool-handler exception as
    ``{"content": [{"type": "text", "text": "Error executing tool <name>: <exc>"}], "isError": true}``.
    When such a wrapper carries an OOM / stack-overflow / abort-looking
    message, that message is a *handled* exception — the process is alive and
    reporting an error, not a real process crash / unbounded OOM. R6 should
    still surface it, but at a lower severity than an *unhandled* malfunction
    (raw traceback, segfault, ...); R5's "unhandled error" check should skip it
    entirely (there's nothing unhandled about a caught-and-returned exception).
    """
    if not response_text:
        return False
    low = response_text.lower()
    # Strong, specific signal: the FastMCP wrapper phrase + an error envelope.
    if "error executing tool" in low and ('"iserror": true' in low or '"iserror":true' in low):
        return True
    # General: parses as a dict the server explicitly flagged as an error. An
    # ``isError: true`` response *is* the server choosing to report rather than
    # crash — that's "handled" for our purposes.
    try:
        obj = json.loads(response_text)
    except (json.JSONDecodeError, ValueError):
        return False
    return isinstance(obj, dict) and obj.get("isError") is True


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
# ``; id``, single chars) would coincidentally appear in legitimate output
# and we'd wrongly strip them. Kept low enough that concrete short payloads
# like ``/.dockerenv`` (11) or ``[$where]`` (8) are still masked when the
# server merely echoes them back in a rejection message.
_MIN_REFLECTION_LEN = 6

_SLASH_RUN_RE = re.compile(r"/{2,}")
_BACKSLASH_RUN_RE = re.compile(r"\\{2,}")
_WS_RUN_RE = re.compile(r"\s{2,}")
_ESCAPE_RE = re.compile(r"\\(.)")


def _collapse_escapes(text: str, passes: int = 5) -> str:
    """Strip backslash-escapes so ``\\'`` / ``\\\\'`` collapse back to ``'``.

    Servers commonly ``repr()`` the offending input before putting it in an
    exception message (``key <#assign cl=\\'freemarker...`` instead of
    ``key <#assign cl='freemarker...``), and the captured ``response_preview``
    may be JSON-encoded on top of that — doubling every backslash. Both layers
    defeat a byte-exact ``payload_repr in response`` check. Collapsing ``\\X``
    -> ``X`` repeatedly (idempotent once no escape remains) lets the echo line
    up again. Used only as a fallback when the verbatim/normalised match fails.
    """
    for _ in range(passes):
        collapsed = _ESCAPE_RE.sub(r"\1", text)
        if collapsed == text:
            break
        text = collapsed
    return text


def _escape_variant(text: str) -> str | None:
    """``repr()``-style escaped form of *text* (control chars / non-ASCII).

    A server that puts the offending value in an exception message via
    ``repr()`` / ``str(exc)`` turns real control characters into their
    escape sequences — a real newline ``\\n`` becomes the two-char literal
    ``\\n``. Our ``payload_repr`` keeps the *raw* characters, so the
    byte-exact echo check misses it (newline != backslash-n). Mimicking the
    escaping on the payload restores the match. ``unicode_escape`` is the
    closest stdlib analogue of CPython's ``repr`` for this purpose.
    """
    try:
        escaped = text.encode("unicode_escape").decode("ascii")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return None
    return escaped if escaped != text else None


def _payload_echo_variants(payload_repr: str) -> list[str]:
    """Plausible forms of *payload_repr* after common server normalisation.

    Servers routinely transform input before echoing it back in an error:
      * ``os.path.normpath`` / ``pathlib`` collapse ``//`` -> ``/``
        (mcp-server-git: ``${jndi:ldap://...}`` echoed as ``${jndi:ldap:/...}``)
      * Windows path joins collapse ``\\\\`` -> ``\\``
      * Whitespace runs collapse to a single space
      * ``repr()`` / ``str(exc)`` escape control chars
        (mcp-server-git: ``\\necho CANARY\\n`` echoed as ``\\necho CANARY\\n``
        — a real newline rendered as the literal two-char ``\\n``)
      * URL / percent encoding when the input lands in a request URL
        (github-mcp-server: ``__import__('os').system('echo CANARY')`` echoed
        as ``__import__%28%27os%27%29.system%28%27echo%20CANARY%27%29`` inside
        a ``GET https://api.github.com/orgs/<payload>/...: 404`` error)

    We replicate each transform on the payload (cheaper and more precise
    than normalising the whole response, which would shift offsets and
    break a clean ``.replace``). Only variants long enough to be
    meaningful are returned.
    """
    variants: list[str] = []
    seen: set[str] = set()

    def _add(v: str | None) -> None:
        if v and len(v) >= _MIN_REFLECTION_LEN and v not in seen:
            seen.add(v)
            variants.append(v)

    _add(payload_repr)
    _add(_SLASH_RUN_RE.sub("/", payload_repr))
    _add(_BACKSLASH_RUN_RE.sub("\\\\", payload_repr))
    _add(_WS_RUN_RE.sub(" ", payload_repr))
    # Combined slash + whitespace collapse.
    _add(_WS_RUN_RE.sub(" ", _SLASH_RUN_RE.sub("/", payload_repr)))
    # ``repr()``-escaped form, and that form once more JSON-encoded (the
    # preview is JSON, so an already-escaped echo gets its backslash doubled).
    esc = _escape_variant(payload_repr)
    _add(esc)
    if esc is not None:
        _add(esc.replace("\\", "\\\\"))
    # URL/percent-encoded forms — for servers that drop the input into a
    # request URL. ``safe=""`` encodes ``/`` too (path-component escaping);
    # ``quote`` (default ``safe="/"``) and ``quote_plus`` cover the other
    # common variants. ``quote`` UTF-8-encodes first, so a lone-surrogate
    # payload raises ``UnicodeEncodeError`` — such a payload can't end up in a
    # URL anyway, so just skip the URL variants for it.
    try:
        _add(quote(payload_repr, safe=""))
        _add(quote(payload_repr))
        _add(quote_plus(payload_repr))
    except (TypeError, UnicodeError):
        pass
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

    Short payloads (<6 chars) are left untouched so legitimate output
    containing common tokens (``id``, ``ls``, ``; id``) isn't masked away.

    Final fallback: if neither the verbatim nor the normalised forms match,
    collapse backslash-escapes on both sides (servers ``repr()`` the input;
    the captured preview may also be JSON-encoded) and try once more — see
    ``_collapse_escapes``.
    """
    if not payload_repr or not response:
        return response
    if len(payload_repr) < _MIN_REFLECTION_LEN:
        return response
    out = response
    for variant in _payload_echo_variants(payload_repr):
        out = out.replace(variant, "<payload>")
    if out != response:
        return out
    # Nothing matched verbatim — try with backslash-escapes collapsed away.
    collapsed_resp = _collapse_escapes(response)
    collapsed_payload = _collapse_escapes(payload_repr)
    if (
        len(collapsed_payload) >= _MIN_REFLECTION_LEN
        and collapsed_payload in collapsed_resp
        and collapsed_resp != response
    ):
        return collapsed_resp.replace(collapsed_payload, "<payload>")
    return response


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
