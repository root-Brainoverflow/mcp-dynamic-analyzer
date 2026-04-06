"""SQL-injection fuzzing payloads for R5 input validation testing."""

from __future__ import annotations

PAYLOADS: list[str] = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "'; DROP TABLE users; --",
    "1; SELECT * FROM information_schema.tables --",
    "' UNION SELECT null,null,null --",
    "' UNION SELECT username,password,null FROM users --",
    "1' AND SLEEP(3) --",
    "1' AND 1=1 --",
    "1' AND 1=2 --",
    "admin'--",
    "1 OR 1=1",
]

ERROR_INDICATORS: list[str] = [
    "sql syntax",
    "sqlite3.operationalerror",
    "mysql",
    "postgresql",
    "ora-",
    "unclosed quotation",
    "unterminated string",
    "syntax error",
    "sqlstate",
    "database error",
    "query failed",
]


def looks_like_sql_error(response_text: str) -> bool:
    """Heuristic: does the response leak SQL error details?"""
    lower = response_text.lower()
    return any(ind in lower for ind in ERROR_INDICATORS)
