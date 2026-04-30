"""Tests for the validation-rejection / input-echo response filters.

Regression coverage for the FP class found in session
``ses-d7d82a7d-607c-4249-88ef-81c7451ce412``: Pydantic and PostgreSQL
parsers echo the rejected payload verbatim, which falsely matched RCE,
command-injection and path-traversal success heuristics.
"""

from __future__ import annotations

from mcp_dynamic_analyzer.payloads._response_filters import (
    is_validation_rejection,
    strip_input_echoes,
)
from mcp_dynamic_analyzer.payloads.command_injection import looks_like_injection_success
from mcp_dynamic_analyzer.payloads.path_traversal import looks_like_traversal_success
from mcp_dynamic_analyzer.payloads.rce import looks_like_rce_success


# ---- raw response samples taken from real scan output -----------------------

PYDANTIC_RCE_ECHO = (
    "Error executing tool list_objects: 1 validation error for list_objectsArguments\n"
    "schema_name\n  Field required [type=missing, "
    "input_value={'object_type': \"__import__('os').system('echo RCE_CANARY_7f3a9c')\"}, "
    "input_type=dict]\n"
    "    For further information visit https://errors.pydantic.dev/2.13/v/missing"
)

PYDANTIC_CMDINJ_ECHO = (
    "Error executing tool list_objects: 1 validation error for list_objectsArguments\n"
    "schema_name\n  Field required [type=missing, "
    "input_value={'object_type': '$(uname -a)'}, input_type=dict]\n"
)

PYDANTIC_TRAVERSAL_ECHO = (
    "Error executing tool get_object_details: 1 validation error\n"
    "object_name\n  Field required [type=missing, "
    "input_value={'schema_name': '../../etc/passwd'}, input_type=dict]\n"
)

POSTGRES_PARSER_ECHO = (
    'Error: Error executing explain plan: syntax error at or near ";"\n'
    "LINE 1: EXPLAIN (FORMAT JSON) ; uname -a\n"
    "                              ^"
)

# Real exploit hits — the indicator must NOT be inside an echoed input region.
REAL_RCE_OUTPUT = (
    "Linux mcp-host 5.15.0-89-generic #99-Ubuntu SMP x86_64 GNU/Linux\n"
    "uid=0(root) gid=0(root) groups=0(root)"
)

REAL_CANARY_OUTPUT = "RCE_CANARY_7f3a9c"

REAL_PASSWD_LEAK = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
)


# ---- is_validation_rejection -----------------------------------------------


def test_pydantic_response_is_validation_rejection() -> None:
    assert is_validation_rejection(PYDANTIC_RCE_ECHO)
    assert is_validation_rejection(PYDANTIC_CMDINJ_ECHO)
    assert is_validation_rejection(PYDANTIC_TRAVERSAL_ECHO)


def test_real_exploit_output_is_not_classified_as_rejection() -> None:
    assert not is_validation_rejection(REAL_RCE_OUTPUT)
    assert not is_validation_rejection(REAL_CANARY_OUTPUT)
    assert not is_validation_rejection(REAL_PASSWD_LEAK)


def test_postgres_parser_error_is_not_pydantic_rejection() -> None:
    """Postgres syntax errors aren't Pydantic validation errors — strip-echo
    handles them via the LINE pattern instead."""
    assert not is_validation_rejection(POSTGRES_PARSER_ECHO)


# ---- looks_like_rce_success after filter -----------------------------------


def test_rce_indicator_in_pydantic_echo_no_longer_matches() -> None:
    # CANARY survives in PYDANTIC_RCE_ECHO if not stripped.
    # After strip_input_echoes, the canary is replaced with <redacted>.
    assert not looks_like_rce_success(PYDANTIC_RCE_ECHO)


def test_rce_indicator_in_postgres_echo_no_longer_matches() -> None:
    # "uname -a" appears inside the LINE 1: ... echo.
    assert not looks_like_rce_success(POSTGRES_PARSER_ECHO)


def test_real_rce_output_still_detected() -> None:
    assert looks_like_rce_success(REAL_RCE_OUTPUT)
    assert looks_like_rce_success(REAL_CANARY_OUTPUT)


# ---- looks_like_injection_success ------------------------------------------


def test_command_injection_indicator_in_pydantic_echo_no_longer_matches() -> None:
    assert not looks_like_injection_success(PYDANTIC_CMDINJ_ECHO)


def test_command_injection_indicator_in_postgres_echo_no_longer_matches() -> None:
    assert not looks_like_injection_success(POSTGRES_PARSER_ECHO)


def test_real_command_injection_output_still_detected() -> None:
    assert looks_like_injection_success(REAL_RCE_OUTPUT)


# ---- looks_like_traversal_success ------------------------------------------


def test_traversal_indicator_in_pydantic_echo_no_longer_matches() -> None:
    # /etc/passwd appears inside the input echo — should be stripped.
    assert not looks_like_traversal_success(PYDANTIC_TRAVERSAL_ECHO)


def test_real_traversal_leak_still_detected() -> None:
    assert looks_like_traversal_success(REAL_PASSWD_LEAK)


# ---- strip_input_echoes raw behaviour --------------------------------------


def test_strip_redacts_pydantic_input_value() -> None:
    out = strip_input_echoes(PYDANTIC_CMDINJ_ECHO)
    assert "$(uname -a)" not in out
    assert "<redacted>" in out


def test_strip_redacts_postgres_line_echo() -> None:
    out = strip_input_echoes(POSTGRES_PARSER_ECHO)
    assert "uname -a" not in out


def test_strip_preserves_text_outside_echo() -> None:
    text = "uid=0(root)\nplus some more output"
    assert strip_input_echoes(text) == text
