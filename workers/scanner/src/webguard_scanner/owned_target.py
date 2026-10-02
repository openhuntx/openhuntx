"""External owned-target authorization and readiness gate."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

from webguard_contracts import (
    OWNED_TARGET_STOP_CONDITIONS,
    OwnedTargetAuditRecord,
    OwnedTargetAuthorization,
    OwnedTargetExecutionPolicy,
)

from .crawler import CrawlPolicy
from .retry_policy import RetryPolicy
from .safe_http import FetchPolicy
from .scope_validator import CanonicalTarget, ValidatedTarget


OWNED_DEFAULT_CRAWL_PAGES = 10
OWNED_DEFAULT_CRAWL_DEPTH = 1
OWNED_DEFAULT_CRAWL_LINKS_PER_PAGE = 50
OWNED_DEFAULT_CRAWL_DELAY_SECONDS = 1.0
OWNED_DEFAULT_CRAWL_EXECUTION_SECONDS = 60.0
OWNED_DEFAULT_CRAWL_REQUEST_ATTEMPTS = 15


class OwnedTargetPreflightError(ValueError):
    """Controlled failure from the external owned-target readiness gate."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class OwnedTargetPreflight:
    """Validated evidence that an owned-target scan may start."""

    authorization: OwnedTargetAuthorization
    target: ValidatedTarget
    execution_policy: OwnedTargetExecutionPolicy
    audit_record: OwnedTargetAuditRecord

    @property
    def authorization_sha256(self) -> str:
        return self.authorization.fingerprint


def _public_addresses(target: ValidatedTarget) -> tuple[str, ...]:
    addresses: list[str] = []
    for value in target.resolved_addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise OwnedTargetPreflightError(
                "owned_target_resolved_address_invalid",
                "Target validation returned an invalid IP address.",
            ) from exc
        classified = address.ipv4_mapped if getattr(address, "ipv4_mapped", None) else address
        if (
            not classified.is_global
            or classified.is_private
            or classified.is_loopback
            or classified.is_link_local
            or classified.is_multicast
            or classified.is_reserved
            or classified.is_unspecified
        ):
            raise OwnedTargetPreflightError(
                "owned_target_public_address_required",
                "Owned production targets must resolve only to public addresses.",
            )
        addresses.append(address.compressed)
    if not addresses:
        raise OwnedTargetPreflightError(
            "owned_target_resolved_addresses_missing",
            "Owned production target did not resolve to any public address.",
        )
    return tuple(
        sorted(
            set(addresses),
            key=lambda item: (
                ipaddress.ip_address(item).version,
                int(ipaddress.ip_address(item)),
            ),
        )
    )


def _execution_policy(
    *,
    fetch_policy: FetchPolicy,
    retry_policy: RetryPolicy,
    crawl_policy: CrawlPolicy | None,
) -> OwnedTargetExecutionPolicy:
    if crawl_policy is None:
        return OwnedTargetExecutionPolicy(
            timeout_seconds=fetch_policy.timeout_seconds,
            maximum_body_bytes=fetch_policy.maximum_body_bytes,
            maximum_header_bytes=fetch_policy.maximum_header_bytes,
            maximum_header_count=fetch_policy.maximum_header_count,
            maximum_attempts_per_request=retry_policy.maximum_attempts,
            crawl_enabled=False,
        )
    return OwnedTargetExecutionPolicy(
        timeout_seconds=fetch_policy.timeout_seconds,
        maximum_body_bytes=fetch_policy.maximum_body_bytes,
        maximum_header_bytes=fetch_policy.maximum_header_bytes,
        maximum_header_count=fetch_policy.maximum_header_count,
        maximum_attempts_per_request=retry_policy.maximum_attempts,
        crawl_enabled=True,
        maximum_pages=crawl_policy.maximum_pages,
        maximum_depth=crawl_policy.maximum_depth,
        maximum_links_per_page=crawl_policy.maximum_links_per_page,
        minimum_delay_seconds=crawl_policy.minimum_delay_seconds,
        maximum_execution_seconds=crawl_policy.maximum_execution_seconds,
        maximum_request_attempts=crawl_policy.maximum_request_attempts,
        query_mode=crawl_policy.query_mode.value,
    )


def validate_owned_target_authorization_static(
    authorization: OwnedTargetAuthorization,
    canonical_target: CanonicalTarget,
    *,
    confirmation: str,
    now: datetime | None = None,
) -> datetime:
    """Validate authorization identity, validity window, and target match.

    Covers every owned-target authorization check that needs only the
    authorization document and a canonicalised (not yet DNS-resolved) target
    URL: confirmation-ID match, the authorization's validity window, scheme,
    and whether the canonical target and host match what the authorization
    actually authorizes. Deliberately excludes the resolved-address and
    per-request/crawl-limit checks, which need a fully resolved
    ValidatedTarget and live in validate_owned_target_preflight below.

    Callable before any DNS resolution, so a malformed, expired, or
    out-of-scope authorization is rejected without the scan ever touching
    the network. Raises OwnedTargetPreflightError on failure. Returns the
    UTC clock value used for the validity check, so a caller that goes on
    to build an audit record uses the exact same timestamp rather than
    reading the clock a second time.
    """

    if not isinstance(authorization, OwnedTargetAuthorization):
        raise OwnedTargetPreflightError(
            "owned_target_authorization_invalid",
            "A validated owned-target authorization is required.",
        )
    if confirmation != authorization.authorization_id:
        raise OwnedTargetPreflightError(
            "owned_target_confirmation_mismatch",
            "--confirm-authorization must exactly match the authorization ID.",
        )
    effective_now = datetime.now(timezone.utc) if now is None else now
    if effective_now.tzinfo is None or effective_now.utcoffset() is None:
        raise OwnedTargetPreflightError(
            "owned_target_clock_invalid",
            "Preflight clock must be timezone-aware.",
        )
    effective_now = effective_now.astimezone(timezone.utc)
    if effective_now < authorization.issued_at:
        raise OwnedTargetPreflightError(
            "owned_target_authorization_not_yet_valid",
            "Owned-target authorization is not valid yet.",
        )
    if effective_now >= authorization.expires_at:
        raise OwnedTargetPreflightError(
            "owned_target_authorization_expired",
            "Owned-target authorization has expired.",
        )
    if canonical_target.scheme != "https":
        raise OwnedTargetPreflightError(
            "owned_target_https_required",
            "Owned production scans require HTTPS.",
        )
    if canonical_target.normalised_url != authorization.target:
        raise OwnedTargetPreflightError(
            "owned_target_canonical_target_mismatch",
            "The validated target must exactly match the authorization's canonical target.",
        )
    target_hostname = urlsplit(canonical_target.normalised_url).hostname
    if target_hostname not in authorization.allowed_hosts:
        raise OwnedTargetPreflightError(
            "owned_target_host_not_authorized",
            "The target hostname is not present in the authorization allowlist.",
        )
    return effective_now


def _as_canonical_target(target: ValidatedTarget) -> CanonicalTarget:
    return CanonicalTarget(
        original_url=target.original_url,
        normalised_url=target.normalised_url,
        scheme=target.scheme,
        hostname=target.hostname,
        port=target.port,
    )


def validate_owned_target_preflight(
    authorization: OwnedTargetAuthorization,
    target: ValidatedTarget,
    *,
    confirmation: str,
    scan_id: str,
    fetch_policy: FetchPolicy,
    retry_policy: RetryPolicy,
    crawl_policy: CrawlPolicy | None,
    now: datetime | None = None,
) -> OwnedTargetPreflight:
    """Validate authorization, scope, budgets, and operator confirmation."""

    if not isinstance(authorization, OwnedTargetAuthorization):
        raise OwnedTargetPreflightError(
            "owned_target_authorization_invalid",
            "A validated owned-target authorization is required.",
        )
    if not isinstance(target, ValidatedTarget):
        raise OwnedTargetPreflightError(
            "owned_target_validated_target_invalid",
            "A validated target is required.",
        )
    effective_now = validate_owned_target_authorization_static(
        authorization,
        _as_canonical_target(target),
        confirmation=confirmation,
        now=now,
    )
    addresses = _public_addresses(target)
    limits = authorization.limits
    if fetch_policy.timeout_seconds > limits.timeout_seconds:
        raise OwnedTargetPreflightError(
            "owned_target_timeout_limit_exceeded",
            "Per-request timeout exceeds the authorization limit.",
        )
    if fetch_policy.maximum_body_bytes > limits.maximum_body_bytes:
        raise OwnedTargetPreflightError(
            "owned_target_body_limit_exceeded",
            "Response body limit exceeds the authorization limit.",
        )
    if fetch_policy.maximum_header_bytes > limits.maximum_header_bytes:
        raise OwnedTargetPreflightError(
            "owned_target_header_bytes_limit_exceeded",
            "Response header byte limit exceeds the authorization limit.",
        )
    if fetch_policy.maximum_header_count > limits.maximum_header_count:
        raise OwnedTargetPreflightError(
            "owned_target_header_count_limit_exceeded",
            "Response header count exceeds the authorization limit.",
        )
    if retry_policy.maximum_attempts > limits.maximum_attempts_per_request:
        raise OwnedTargetPreflightError(
            "owned_target_retry_limit_exceeded",
            "Per-request attempts exceed the authorization limit.",
        )
    if crawl_policy is not None:
        comparisons = (
            (
                crawl_policy.maximum_pages,
                limits.maximum_pages,
                "owned_target_page_limit_exceeded",
                "Crawl page limit exceeds the authorization limit.",
            ),
            (
                crawl_policy.maximum_depth,
                limits.maximum_depth,
                "owned_target_depth_limit_exceeded",
                "Crawl depth exceeds the authorization limit.",
            ),
            (
                crawl_policy.maximum_links_per_page,
                limits.maximum_links_per_page,
                "owned_target_link_limit_exceeded",
                "Per-page link limit exceeds the authorization limit.",
            ),
            (
                crawl_policy.maximum_execution_seconds,
                limits.maximum_execution_seconds,
                "owned_target_execution_limit_exceeded",
                "Crawl execution time exceeds the authorization limit.",
            ),
            (
                crawl_policy.maximum_request_attempts,
                limits.maximum_request_attempts,
                "owned_target_request_budget_exceeded",
                "Crawl request budget exceeds the authorization limit.",
            ),
        )
        for actual, maximum, code, message in comparisons:
            if actual > maximum:
                raise OwnedTargetPreflightError(code, message)
        if crawl_policy.minimum_delay_seconds < limits.minimum_delay_seconds:
            raise OwnedTargetPreflightError(
                "owned_target_delay_below_minimum",
                "Crawl delay is below the authorization minimum.",
            )
    policy = _execution_policy(
        fetch_policy=fetch_policy,
        retry_policy=retry_policy,
        crawl_policy=crawl_policy,
    )
    audit = OwnedTargetAuditRecord(
        scan_id=scan_id,
        authorization_id=authorization.authorization_id,
        authorization_sha256=authorization.fingerprint,
        organization=authorization.organization,
        authorized_by=authorization.authorized_by,
        target=target.normalised_url,
        resolved_addresses=addresses,
        created_at=effective_now,
        execution_policy=policy,
        stop_conditions=OWNED_TARGET_STOP_CONDITIONS,
    )
    return OwnedTargetPreflight(
        authorization=authorization,
        target=target,
        execution_policy=policy,
        audit_record=audit,
    )


__all__ = [
    "OWNED_DEFAULT_CRAWL_DELAY_SECONDS",
    "OWNED_DEFAULT_CRAWL_DEPTH",
    "OWNED_DEFAULT_CRAWL_EXECUTION_SECONDS",
    "OWNED_DEFAULT_CRAWL_LINKS_PER_PAGE",
    "OWNED_DEFAULT_CRAWL_PAGES",
    "OWNED_DEFAULT_CRAWL_REQUEST_ATTEMPTS",
    "OwnedTargetPreflight",
    "OwnedTargetPreflightError",
    "validate_owned_target_authorization_static",
    "validate_owned_target_preflight",
]
