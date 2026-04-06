"""Payload sub-package: fuzzing payloads and injection pattern detection."""

from mcp_dynamic_analyzer.payloads.path_traversal import (
    UNIX_PAYLOADS as PATH_TRAVERSAL_PAYLOADS,
    SENSITIVE_TARGETS,
    looks_like_traversal_success,
)
from mcp_dynamic_analyzer.payloads.command_injection import (
    looks_like_injection_success,
)
from mcp_dynamic_analyzer.payloads.sql_injection import (
    looks_like_sql_error,
)
from mcp_dynamic_analyzer.payloads.type_confusion import (
    generate_type_payloads,
    looks_like_unhandled_error,
)
from mcp_dynamic_analyzer.payloads.injection_patterns import (
    PatternMatch,
    scan_description,
    scan_response,
)

__all__ = [
    "PATH_TRAVERSAL_PAYLOADS",
    "SENSITIVE_TARGETS",
    "looks_like_traversal_success",
    "looks_like_injection_success",
    "looks_like_sql_error",
    "generate_type_payloads",
    "looks_like_unhandled_error",
    "PatternMatch",
    "scan_description",
    "scan_response",
]
