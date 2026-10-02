"""Controlled scanner error taxonomy and retry policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ErrorCategory(str, Enum):
    """Stable categories used to group controlled scanner failures."""

    CONFIGURATION = "configuration"
    TARGET_INTEGRITY = "target-integrity"
    NETWORK_TRANSIENT = "network-transient"
    TLS = "tls"
    HTTP_PROTOCOL = "http-protocol"
    RESPONSE_POLICY = "response-policy"
    RESPONSE_LIMIT = "response-limit"
    RESPONSE_FORMAT = "response-format"
    REQUEST_LIMIT = "request-limit"
    ANALYSIS = "analysis"
    MIXED = "mixed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ErrorPolicy:
    """Classification assigned to one controlled error code."""

    category: ErrorCategory
    retryable: bool


_NON_RETRYABLE = False
_RETRYABLE = True

_REQUEST_POLICIES: dict[str, ErrorPolicy] = {
    # Request configuration.
    "timeout_invalid": ErrorPolicy(
        ErrorCategory.CONFIGURATION,
        _NON_RETRYABLE,
    ),
    "body_limit_invalid": ErrorPolicy(
        ErrorCategory.CONFIGURATION,
        _NON_RETRYABLE,
    ),
    "header_limit_invalid": ErrorPolicy(
        ErrorCategory.CONFIGURATION,
        _NON_RETRYABLE,
    ),
    "request_body_limit_invalid": ErrorPolicy(
        ErrorCategory.CONFIGURATION,
        _NON_RETRYABLE,
    ),
    "header_count_invalid": ErrorPolicy(
        ErrorCategory.CONFIGURATION,
        _NON_RETRYABLE,
    ),

    # Target and request integrity.
    "validated_address_invalid": ErrorPolicy(
        ErrorCategory.TARGET_INTEGRITY,
        _NON_RETRYABLE,
    ),
    "validated_addresses_empty": ErrorPolicy(
        ErrorCategory.TARGET_INTEGRITY,
        _NON_RETRYABLE,
    ),
    "validated_target_mismatch": ErrorPolicy(
        ErrorCategory.TARGET_INTEGRITY,
        _NON_RETRYABLE,
    ),
    "fragment_not_allowed": ErrorPolicy(
        ErrorCategory.TARGET_INTEGRITY,
        _NON_RETRYABLE,
    ),
    "scheme_not_allowed": ErrorPolicy(
        ErrorCategory.TARGET_INTEGRITY,
        _NON_RETRYABLE,
    ),
    "method_not_allowed": ErrorPolicy(
        ErrorCategory.TARGET_INTEGRITY,
        _NON_RETRYABLE,
    ),
    "proxy_tunnel_not_allowed": ErrorPolicy(
        ErrorCategory.TARGET_INTEGRITY,
        _NON_RETRYABLE,
    ),

    # Transient network failures.
    "connection_timeout": ErrorPolicy(
        ErrorCategory.NETWORK_TRANSIENT,
        _RETRYABLE,
    ),
    "request_deadline_exceeded": ErrorPolicy(
        ErrorCategory.NETWORK_TRANSIENT,
        _RETRYABLE,
    ),
    "connection_refused": ErrorPolicy(
        ErrorCategory.NETWORK_TRANSIENT,
        _RETRYABLE,
    ),
    "connection_interrupted": ErrorPolicy(
        ErrorCategory.NETWORK_TRANSIENT,
        _RETRYABLE,
    ),
    "network_unreachable": ErrorPolicy(
        ErrorCategory.NETWORK_TRANSIENT,
        _RETRYABLE,
    ),
    "connection_failed": ErrorPolicy(
        ErrorCategory.NETWORK_TRANSIENT,
        _RETRYABLE,
    ),

    # TLS and HTTP protocol failures.
    "tls_certificate_invalid": ErrorPolicy(
        ErrorCategory.TLS,
        _NON_RETRYABLE,
    ),
    "tls_handshake_failed": ErrorPolicy(
        ErrorCategory.TLS,
        _NON_RETRYABLE,
    ),
    "tls_context_insecure": ErrorPolicy(
        ErrorCategory.TLS,
        _NON_RETRYABLE,
    ),
    "tls_metadata_unavailable": ErrorPolicy(
        ErrorCategory.TLS,
        _NON_RETRYABLE,
    ),
    "tls_certificate_metadata_invalid": ErrorPolicy(
        ErrorCategory.TLS,
        _NON_RETRYABLE,
    ),
    "tls_certificate_metadata_too_large": ErrorPolicy(
        ErrorCategory.TLS,
        _NON_RETRYABLE,
    ),
    "http_protocol_error": ErrorPolicy(
        ErrorCategory.HTTP_PROTOCOL,
        _NON_RETRYABLE,
    ),
    "connection_failed_mixed": ErrorPolicy(
        ErrorCategory.MIXED,
        _NON_RETRYABLE,
    ),

    # Response policy and safety limits.
    "redirect_blocked": ErrorPolicy(
        ErrorCategory.RESPONSE_POLICY,
        _NON_RETRYABLE,
    ),
    "response_body_too_large": ErrorPolicy(
        ErrorCategory.RESPONSE_LIMIT,
        _NON_RETRYABLE,
    ),
    "response_headers_too_many": ErrorPolicy(
        ErrorCategory.RESPONSE_LIMIT,
        _NON_RETRYABLE,
    ),
    "response_headers_too_large": ErrorPolicy(
        ErrorCategory.RESPONSE_LIMIT,
        _NON_RETRYABLE,
    ),

    # Request-body safety limit (Slice 6: POST/JSON mutation).
    "request_body_too_large": ErrorPolicy(
        ErrorCategory.REQUEST_LIMIT,
        _NON_RETRYABLE,
    ),

    # Header-injection guard (Slice 7: authentication support).
    "forbidden_request_header": ErrorPolicy(
        ErrorCategory.CONFIGURATION,
        _NON_RETRYABLE,
    ),

    # Malformed response metadata.
    "content_length_invalid": ErrorPolicy(
        ErrorCategory.RESPONSE_FORMAT,
        _NON_RETRYABLE,
    ),
    "content_length_ambiguous": ErrorPolicy(
        ErrorCategory.RESPONSE_FORMAT,
        _NON_RETRYABLE,
    ),
    "response_status_invalid": ErrorPolicy(
        ErrorCategory.RESPONSE_FORMAT,
        _NON_RETRYABLE,
    ),
}

_ANALYSIS_POLICIES: dict[str, ErrorPolicy] = {
    "validated_target_mismatch": ErrorPolicy(
        ErrorCategory.ANALYSIS,
        _NON_RETRYABLE,
    ),
    "tls_metadata_missing": ErrorPolicy(
        ErrorCategory.ANALYSIS,
        _NON_RETRYABLE,
    ),
    "tls_metadata_inconsistent": ErrorPolicy(
        ErrorCategory.ANALYSIS,
        _NON_RETRYABLE,
    ),
    "tls_certificate_time_invalid": ErrorPolicy(
        ErrorCategory.ANALYSIS,
        _NON_RETRYABLE,
    ),
    "tls_target_not_https": ErrorPolicy(
        ErrorCategory.ANALYSIS,
        _NON_RETRYABLE,
    ),
}

_UNKNOWN_POLICY = ErrorPolicy(
    ErrorCategory.UNKNOWN,
    _NON_RETRYABLE,
)


def classify_error(
    *,
    stage: str,
    code: str,
) -> ErrorPolicy:
    """Return the reviewed policy for one controlled error.

    Unknown stage/code combinations deliberately fail closed as
    non-retryable.
    """

    normalised_stage = stage.strip().lower()
    normalised_code = code.strip().lower()

    if normalised_stage == "request":
        return _REQUEST_POLICIES.get(
            normalised_code,
            _UNKNOWN_POLICY,
        )

    if normalised_stage == "analysis":
        return _ANALYSIS_POLICIES.get(
            normalised_code,
            _UNKNOWN_POLICY,
        )

    return _UNKNOWN_POLICY


def is_retryable_error(
    *,
    stage: str,
    code: str,
) -> bool:
    """Return whether a controlled error is safe to retry."""

    return classify_error(
        stage=stage,
        code=code,
    ).retryable


def known_error_codes(
    *,
    stage: str,
) -> tuple[str, ...]:
    """Return reviewed error codes for a scanner stage."""

    normalised_stage = stage.strip().lower()

    if normalised_stage == "request":
        policies = _REQUEST_POLICIES
    elif normalised_stage == "analysis":
        policies = _ANALYSIS_POLICIES
    else:
        return ()

    return tuple(sorted(policies))
