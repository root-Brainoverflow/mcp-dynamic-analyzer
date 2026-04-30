"""Prompt-injection and deceptive-description detection patterns for R3.

These patterns detect suspicious wording in MCP tool descriptions and
server responses that may attempt to manipulate LLM behaviour.
"""

from __future__ import annotations

import re
from typing import NamedTuple


class PatternMatch(NamedTuple):
    pattern_name: str
    matched_text: str
    severity: str  # "HIGH" | "MEDIUM" | "LOW"


# -- Description-level patterns (tool description / docstring) ---------------

_DESCRIPTION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "hidden_instruction",
        re.compile(
            r"(ignore\s+(previous|all|above)|disregard\s+instructions|"
            r"forget\s+(everything|all|previous)|override\s+instructions|"
            r"new\s+instructions?\s*:)",
            re.IGNORECASE,
        ),
        "HIGH",
    ),
    (
        "role_assumption",
        re.compile(
            r"(you\s+are\s+(now|a)|act\s+as\s+(a|an)|pretend\s+to\s+be|"
            r"assume\s+the\s+role|switch\s+to\s+role)",
            re.IGNORECASE,
        ),
        "HIGH",
    ),
    (
        "urgency_pressure",
        re.compile(
            # Bare "you must" / "important:" appear in legitimate operational
            # documentation ("You must call X first", "IMPORTANT: rate-limited
            # to 3 calls"). Require pairing with a manipulation verb so we
            # only flag wording that pressures the LLM to bypass normal
            # behaviour or trust this tool unconditionally.
            r"(you\s+must\s+(always|never|trust|use\s+only|use\s+this|skip|ignore|"
            r"not\s+(call|use|tell|inform|reveal))|"
            r"always\s+use\s+this\s+(tool|first|over)|"
            r"this\s+is\s+(the\s+)?(best|only|safest|trusted)\s+(tool|option|choice|version)|"
            r"never\s+use\s+(any\s+)?(other|alternative)|"
            r"(critical|important|urgent)\s*:\s*"
            r"(ignore|always|never|forward|exfiltrate|do\s+not\s+(tell|inform|reveal)))",
            re.IGNORECASE,
        ),
        "MEDIUM",
    ),
    (
        "data_exfiltration_instruction",
        re.compile(
            r"(send\s+(all|the)\s+data\s+to|forward\s+(to|all)|"
            r"include\s+(all|every)\s+(file|secret|key|password|credential)|"
            r"upload\s+to|exfiltrate|POST\s+to\s+http)",
            re.IGNORECASE,
        ),
        "HIGH",
    ),
    (
        "stealth_instruction",
        re.compile(
            r"(do\s+not\s+(tell|inform|show|reveal|mention)|"
            r"hide\s+this|keep\s+secret|silently|without\s+(telling|informing))",
            re.IGNORECASE,
        ),
        "HIGH",
    ),
    (
        "excessive_capability_claim",
        re.compile(
            r"(this\s+tool\s+can\s+do\s+everything|unlimited\s+access|"
            r"full\s+system\s+access|root\s+access|admin\s+privileges)",
            re.IGNORECASE,
        ),
        "MEDIUM",
    ),
    (
        "encoded_content",
        re.compile(r"(base64|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|%[0-9a-f]{2}){3,}", re.IGNORECASE),
        "MEDIUM",
    ),
]

# -- Response-level patterns (tool return injection) -------------------------

_RESPONSE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "tool_return_instruction",
        re.compile(
            r"(now\s+(call|execute|run|use)\s+|please\s+(call|execute|run|use)\s+|"
            r"next\s*,?\s*(call|execute|run|use)|you\s+should\s+(now\s+)?(call|run))",
            re.IGNORECASE,
        ),
        "HIGH",
    ),
    (
        "hidden_system_prompt",
        re.compile(
            r"(<\|system\|>|<\|im_start\|>|<\|endoftext\|>|\[INST\]|\[/INST\]|"
            r"<<SYS>>|<\|assistant\|>)",
            re.IGNORECASE,
        ),
        "HIGH",
    ),
    (
        "markdown_image_exfil",
        re.compile(
            r"!\[.*?\]\(https?://[^)]*\?.*?(key|token|secret|password|data)=",
            re.IGNORECASE,
        ),
        "HIGH",
    ),
]


def scan_description(text: str) -> list[PatternMatch]:
    """Scan a tool description for injection / manipulation patterns."""
    matches: list[PatternMatch] = []
    for name, pattern, severity in _DESCRIPTION_PATTERNS:
        m = pattern.search(text)
        if m:
            matches.append(PatternMatch(name, m.group(0), severity))
    return matches


def scan_response(text: str) -> list[PatternMatch]:
    """Scan a tool response for return-injection patterns."""
    matches: list[PatternMatch] = []
    for name, pattern, severity in _RESPONSE_PATTERNS:
        m = pattern.search(text)
        if m:
            matches.append(PatternMatch(name, m.group(0), severity))
    return matches
