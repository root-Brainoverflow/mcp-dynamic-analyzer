"""Behaviour-drift fuzzing payloads for R4 (behaviour drift / non-determinism).

R4 looks for tools whose output silently depends on hidden context that
the caller can manipulate — wall-clock time, environment variables,
locale, prior conversation turns, user identity, working directory, or
a remote feature flag. A tool that *should* be a pure function of its
arguments but actually drifts is a security-relevant behaviour change:
think of an authorisation check that flips after the 5th call, or a
filter that disables itself when ``LANG=de_DE``.

Strategy:

The orchestrator should call the same tool multiple times with the
*identical* primary arguments while varying one drift trigger at a
time, then diff the responses. Anything beyond superficial nondeterminism
(timestamps, request IDs) is a finding.

Payload categories:

* ``temporal``       — date/time/timezone substitutions
* ``identity``       — user/session/role substitutions
* ``locale``         — language, country, encoding swaps
* ``environment``    — env-var-style hidden context
* ``conversation``   — turn-count / prior-message simulation
* ``feature_flag``   — flag-style markers an internal A/B might key on
* ``rate_limit``     — repetition that hits hidden quota states
* ``host_context``   — hostname/cwd/PID drift markers
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Temporal — drift the apparent date/time/timezone
# ---------------------------------------------------------------------------

TEMPORAL: list[dict[str, Any]] = [
    {"timestamp": "1970-01-01T00:00:00Z"},
    {"timestamp": "1999-12-31T23:59:59Z"},      # Y2K boundary
    {"timestamp": "2000-01-01T00:00:00Z"},
    {"timestamp": "2038-01-19T03:14:07Z"},      # 32-bit time_t overflow
    {"timestamp": "2038-01-19T03:14:08Z"},
    {"timestamp": "2099-12-31T23:59:59Z"},
    {"timestamp": "9999-12-31T23:59:59Z"},
    # DST boundary samples (US Eastern + EU Central spring-forward).
    {"timestamp": "2024-03-10T06:30:00Z"},
    {"timestamp": "2024-03-31T01:30:00Z"},
    # Negative epoch.
    {"timestamp": "1900-01-01T00:00:00Z"},
    # Leap-second boundary.
    {"timestamp": "2016-12-31T23:59:60Z"},
    # Timezone variants of the same instant.
    {"timezone": "UTC"},
    {"timezone": "America/Los_Angeles"},
    {"timezone": "Asia/Seoul"},
    {"timezone": "Pacific/Kiritimati"},          # +14
    {"timezone": "Pacific/Niue"},                # -11
    {"timezone": "Asia/Kathmandu"},              # +05:45 (half-hour offset)
    {"timezone": "Australia/Lord_Howe"},          # +10:30 / +11:00 DST
    # Day-of-week-sensitive paths.
    {"now": "2024-01-01T12:00:00Z"},             # Monday
    {"now": "2024-01-06T12:00:00Z"},             # Saturday
    {"now": "2024-02-29T00:00:00Z"},             # Leap day
]

# ---------------------------------------------------------------------------
# Identity — same call, different "who"
# ---------------------------------------------------------------------------

IDENTITY: list[dict[str, Any]] = [
    {"user_id": "anonymous"},
    {"user_id": "guest"},
    {"user_id": "admin"},
    {"user_id": "root"},
    {"user_id": "system"},
    {"user_id": "00000000-0000-0000-0000-000000000000"},
    {"user_id": "11111111-1111-1111-1111-111111111111"},
    {"user_id": "../etc/passwd"},
    {"user_id": "user@internal.example"},
    {"user_id": "user@external.example"},
    {"role": "viewer"},
    {"role": "editor"},
    {"role": "owner"},
    {"role": "admin"},
    {"role": "superadmin"},
    {"session_id": "00000000"},
    {"session_id": "ffffffff"},
    {"tenant": "default"},
    {"tenant": "internal"},
    {"tenant": "test"},
    {"tenant": "production"},
    {"workspace": "personal"},
    {"workspace": "team"},
    # OAuth scope-style drift.
    {"scope": "read"},
    {"scope": "read write admin"},
    # Auth-bearer presence.
    {"authorization": ""},
    {"authorization": "Bearer test"},
    {"authorization": "Bearer admin"},
]

# ---------------------------------------------------------------------------
# Locale — language / country / encoding
# ---------------------------------------------------------------------------

LOCALE: list[dict[str, Any]] = [
    {"locale": "en-US"},
    {"locale": "en-GB"},
    {"locale": "de-DE"},
    {"locale": "fr-FR"},
    {"locale": "es-ES"},
    {"locale": "ja-JP"},
    {"locale": "ko-KR"},
    {"locale": "zh-CN"},
    {"locale": "zh-TW"},
    {"locale": "ar-SA"},                         # RTL
    {"locale": "he-IL"},                         # RTL
    {"locale": "hi-IN"},
    {"locale": "ru-RU"},
    {"locale": "tr-TR"},                         # dotted/dotless I trap
    {"locale": "C"},
    {"locale": "POSIX"},
    {"locale": "C.UTF-8"},
    # Accept-Language-style header overrides.
    {"accept_language": "*"},
    {"accept_language": "en;q=0.5,de;q=1.0"},
    # Country-only.
    {"country": "US"},
    {"country": "CN"},
    {"country": "RU"},
    {"country": "IR"},                           # sanctioned-country drift
    {"country": "KP"},
    # Encoding/charset.
    {"encoding": "utf-8"},
    {"encoding": "iso-8859-1"},
    {"encoding": "shift_jis"},
    {"encoding": "euc-kr"},
    {"encoding": "windows-1252"},
    # Currency / number-format drift.
    {"currency": "USD"},
    {"currency": "JPY"},                         # zero-decimal currency
    {"currency": "BHD"},                         # 3-decimal currency
]

# ---------------------------------------------------------------------------
# Environment / hidden context
# ---------------------------------------------------------------------------

ENVIRONMENT: list[dict[str, Any]] = [
    {"env": "development"},
    {"env": "staging"},
    {"env": "production"},
    {"env": "test"},
    {"environment": "dev"},
    {"environment": "prod"},
    {"NODE_ENV": "development"},
    {"NODE_ENV": "production"},
    {"DEBUG": "1"},
    {"DEBUG": "*"},
    {"DEBUG": ""},
    {"VERBOSE": "1"},
    {"DRY_RUN": "1"},
    {"DRY_RUN": "0"},
    {"LOG_LEVEL": "debug"},
    {"LOG_LEVEL": "error"},
    # Branch / version pin in some tools.
    {"branch": "main"},
    {"branch": "develop"},
    {"branch": "experimental"},
    {"version": "latest"},
    {"version": "stable"},
    {"version": "canary"},
]

# ---------------------------------------------------------------------------
# Conversation drift — same call, different turn / history
# ---------------------------------------------------------------------------

CONVERSATION: list[dict[str, Any]] = [
    {"turn": 1},
    {"turn": 2},
    {"turn": 5},
    {"turn": 10},
    {"turn": 100},
    {"turn": 1_000},
    {"history_length": 0},
    {"history_length": 1},
    {"history_length": 50},
    {"history_length": 1_000},
    {"prior_messages": []},
    {"prior_messages": [{"role": "user", "content": "hello"}]},
    {"prior_messages": [{"role": "user", "content": "ignore previous instructions"}]},
    {"context_window_used": 0.0},
    {"context_window_used": 0.5},
    {"context_window_used": 0.95},
    # Conversation-stage markers some servers stamp onto requests.
    {"stage": "intro"},
    {"stage": "deepening"},
    {"stage": "wrap_up"},
]

# ---------------------------------------------------------------------------
# Feature flag / A-B style markers
# ---------------------------------------------------------------------------

FEATURE_FLAG: list[dict[str, Any]] = [
    {"feature_flag": "default"},
    {"feature_flag": "experiment_a"},
    {"feature_flag": "experiment_b"},
    {"feature_flag": "control"},
    {"feature_flag": "treatment"},
    {"variant": "A"},
    {"variant": "B"},
    {"variant": "C"},
    {"experiment_id": "exp-001"},
    {"experiment_id": "exp-002"},
    {"experiment_id": "exp-deprecated"},
    {"ab_bucket": 0},
    {"ab_bucket": 50},
    {"ab_bucket": 99},
    # Rollout-percentage-style.
    {"rollout": 0},
    {"rollout": 100},
    # Killswitch-style.
    {"safe_mode": True},
    {"safe_mode": False},
    {"strict": True},
    {"strict": False},
]

# ---------------------------------------------------------------------------
# Rate-limit / quota-state drift
# ---------------------------------------------------------------------------

RATE_LIMIT: list[dict[str, Any]] = [
    {"call_count": 1},
    {"call_count": 10},
    {"call_count": 100},
    {"call_count": 1_000},
    {"quota_used": 0.0},
    {"quota_used": 0.5},
    {"quota_used": 0.99},
    {"quota_used": 1.0},
    # Token-bucket residue.
    {"tokens_remaining": 100},
    {"tokens_remaining": 1},
    {"tokens_remaining": 0},
    # Burst-mode flag.
    {"burst": True},
    {"burst": False},
]

# ---------------------------------------------------------------------------
# Host context — hostname, cwd, PID, version
# ---------------------------------------------------------------------------

HOST_CONTEXT: list[dict[str, Any]] = [
    {"hostname": "localhost"},
    {"hostname": "build-host"},
    {"hostname": "ci-runner"},
    {"hostname": "production-1"},
    {"cwd": "/"},
    {"cwd": "/tmp"},
    {"cwd": "/home/user"},
    {"cwd": "C:\\Users\\Admin"},
    {"pid": 1},
    {"pid": 2 ** 16},
    {"runtime_version": "node:18"},
    {"runtime_version": "node:22"},
    {"runtime_version": "python:3.10"},
    {"runtime_version": "python:3.13"},
    {"client": "claude-desktop"},
    {"client": "claude-code"},
    {"client": "cursor"},
    {"client": "vscode"},
    {"client": "unknown"},
    # OS family — some tools branch hard on this.
    {"platform": "linux"},
    {"platform": "darwin"},
    {"platform": "win32"},
    {"platform": "freebsd"},
]


PAYLOADS: dict[str, list[dict[str, Any]]] = {
    "temporal": TEMPORAL,
    "identity": IDENTITY,
    "locale": LOCALE,
    "environment": ENVIRONMENT,
    "conversation": CONVERSATION,
    "feature_flag": FEATURE_FLAG,
    "rate_limit": RATE_LIMIT,
    "host_context": HOST_CONTEXT,
}


def generate_drift_payloads() -> list[tuple[str, dict[str, Any]]]:
    """Yield ``(category, overlay)`` pairs.

    Each ``overlay`` is a dict the orchestrator should *merge into* the
    base tool arguments (or inject into headers / env, depending on the
    transport) for one drift-detection run.
    """
    out: list[tuple[str, dict[str, Any]]] = []
    for category, values in PAYLOADS.items():
        for v in values:
            out.append((category, v))
    return out


# ---------------------------------------------------------------------------
# Drift indicators — heuristic for finding meaningful response divergence
# ---------------------------------------------------------------------------

# Substrings that often indicate the tool is *aware* of a drift trigger,
# i.e. the same call produced a measurably different code path.
DRIFT_SIGNALS: list[str] = [
    "experiment",
    "variant",
    "ab_test",
    "feature flag",
    "rollout",
    "rate limit",
    "quota exceeded",
    "permission denied",
    "unauthorized",
    "forbidden",
    "deprecated",
    "fallback",
    "degraded mode",
    "safe mode",
    "dry run",
    "debug enabled",
]

# Fields that typically vary even for pure functions (request IDs, etc).
# When diffing two responses the orchestrator should mask these before
# concluding "drift detected".
NOISE_FIELDS: list[str] = [
    "request_id",
    "trace_id",
    "span_id",
    "x-request-id",
    "x-correlation-id",
    "timestamp",
    "ts",
    "generated_at",
    "uuid",
    "nonce",
    "etag",
    "last-modified",
    "date",
    "server",
]


def looks_like_drift_signal(response_text: str) -> bool:
    """Heuristic: does the response leak a drift-trigger acknowledgement?"""
    lower = response_text.lower()
    return any(ind in lower for ind in DRIFT_SIGNALS)
