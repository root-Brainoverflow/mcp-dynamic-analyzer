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
from mcp_dynamic_analyzer.payloads.ssrf import (
    generate_ssrf_payloads,
    looks_like_ssrf_success,
)
from mcp_dynamic_analyzer.payloads.stability import (
    SLOW_RESPONSE_THRESHOLD_SEC,
    generate_stability_payloads,
    looks_like_oom,
    looks_like_stack_overflow,
    looks_like_timeout,
    looks_like_parser_failure,
    looks_like_crash,
)
from mcp_dynamic_analyzer.payloads.behavior_drift import (
    generate_drift_payloads,
    looks_like_drift_signal,
    NOISE_FIELDS,
)
from mcp_dynamic_analyzer.payloads.nosql_injection import (
    generate_nosql_payloads,
    looks_like_nosql_error,
    looks_like_nosql_leak,
)
from mcp_dynamic_analyzer.payloads.rce import (
    generate_rce_payloads,
    looks_like_rce_success,
)
from mcp_dynamic_analyzer.payloads.tool_poisoning import (
    TOOL_POISONING_CANARY,
    generate_tool_poisoning_payloads,
    looks_like_poisoned_description,
    scan_tool_list,
)
from mcp_dynamic_analyzer.payloads.resource_poisoning import (
    RESOURCE_POISONING_CANARY,
    generate_resource_poisoning_payloads,
    looks_like_poisoned_resource,
    scan_resource_response,
)

__all__ = [
    # path traversal
    "PATH_TRAVERSAL_PAYLOADS",
    "SENSITIVE_TARGETS",
    "looks_like_traversal_success",
    # command injection
    "looks_like_injection_success",
    # sql
    "looks_like_sql_error",
    # type confusion
    "generate_type_payloads",
    "looks_like_unhandled_error",
    # injection patterns
    "PatternMatch",
    "scan_description",
    "scan_response",
    # ssrf
    "generate_ssrf_payloads",
    "looks_like_ssrf_success",
    # stability
    "SLOW_RESPONSE_THRESHOLD_SEC",
    "generate_stability_payloads",
    "looks_like_oom",
    "looks_like_stack_overflow",
    "looks_like_timeout",
    "looks_like_parser_failure",
    "looks_like_crash",
    # behavior drift
    "generate_drift_payloads",
    "looks_like_drift_signal",
    "NOISE_FIELDS",
    # nosql
    "generate_nosql_payloads",
    "looks_like_nosql_error",
    "looks_like_nosql_leak",
    # rce
    "generate_rce_payloads",
    "looks_like_rce_success",
    # tool poisoning
    "TOOL_POISONING_CANARY",
    "generate_tool_poisoning_payloads",
    "looks_like_poisoned_description",
    "scan_tool_list",
    # resource poisoning
    "RESOURCE_POISONING_CANARY",
    "generate_resource_poisoning_payloads",
    "looks_like_poisoned_resource",
    "scan_resource_response",
]
