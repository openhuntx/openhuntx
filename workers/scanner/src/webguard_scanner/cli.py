"""Command-line interface for OpenHuntX WebGuard."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import math
import os
import platform
import shutil
import signal
import stat
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import current_thread, main_thread
from typing import Sequence, TextIO
from uuid import uuid4
from urllib.parse import urlsplit

from webguard_contracts import (
    CrawlCheckpoint,
    CrawlCheckpointError,
    CrawlCheckpointFetchPolicy,
    CrawlCheckpointRetryPolicy,
    CrawlScanPolicy,
    CrawlScanResult,
    OwnedTargetAuthorization,
    OwnedTargetContractError,
    OwnedTargetLimits,
    ReportComparisonError,
    ScanReportLoadError,
    ScanResult,
    ScanStatus,
    WebGuardReport,
    load_crawl_checkpoint_file,
    load_crawl_checkpoint_key_file,
    canonicalize_owned_target_hostname,
    canonicalize_owned_target_url,
    load_owned_target_authorization_file,
    load_report_comparison_file,
    load_webguard_report_file,
    write_crawl_checkpoint_file,
    write_owned_target_audit_file,
    write_owned_target_authorization_file,
)

from .crawl_scan import run_passive_crawl_scan
from .crawler import (
    CrawlCancellationToken,
    CrawlPolicy,
    CrawlPolicyError,
    CrawlQueryMode,
    DEFAULT_CRAWL_EXECUTION_SECONDS,
    DEFAULT_CRAWL_REQUEST_ATTEMPTS,
    MAXIMUM_CRAWL_DELAY_SECONDS,
    MAXIMUM_CRAWL_DEPTH,
    MAXIMUM_CRAWL_EXECUTION_SECONDS,
    MAXIMUM_CRAWL_PAGES,
    MAXIMUM_CRAWL_REQUEST_ATTEMPTS,
    MAXIMUM_LINKS_PER_PAGE,
)
from .owned_target import (
    OWNED_DEFAULT_CRAWL_DELAY_SECONDS,
    OWNED_DEFAULT_CRAWL_DEPTH,
    OWNED_DEFAULT_CRAWL_EXECUTION_SECONDS,
    OWNED_DEFAULT_CRAWL_LINKS_PER_PAGE,
    OWNED_DEFAULT_CRAWL_PAGES,
    OWNED_DEFAULT_CRAWL_REQUEST_ATTEMPTS,
    OwnedTargetPreflight,
    OwnedTargetPreflightError,
    validate_owned_target_authorization_static,
    validate_owned_target_preflight,
)
from .passive_scan import ENGINE_VERSION, run_passive_header_scan
from .professional_report import (
    DEFAULT_REPORT_CLASSIFICATION,
    DEFAULT_REPORT_TITLE,
    ProfessionalReportError,
    ProfessionalReportProfile,
    build_report_comparison,
    render_professional_html,
)
from .retry_policy import RetryPolicy
from .safe_http import FetchPolicy
from .scope_validator import (
    TargetValidationError,
    ValidationMode,
    ValidationPolicy,
    canonicalize_target_url,
    validate_target_url,
)


EXIT_SUCCESS = 0
EXIT_SCAN_FAILED = 1
EXIT_USAGE = 2
EXIT_PREFLIGHT_FAILED = 3
EXIT_REPORT_INVALID = 4
EXIT_OUTPUT_FAILED = 5
EXIT_UNEXPECTED_ERROR = 6
EXIT_DOCTOR_CHECK_FAILED = 7

DEFAULT_OUTPUT_DIRECTORY = Path("scan-results")
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAXIMUM_BODY_BYTES = 1_048_576
DEFAULT_MAXIMUM_HEADER_BYTES = 65_536
DEFAULT_MAXIMUM_HEADER_COUNT = 100

MAXIMUM_CLI_TIMEOUT_SECONDS = 60.0
MAXIMUM_CLI_BODY_BYTES = 16 * 1024 * 1024
MAXIMUM_CLI_HEADER_BYTES = 1024 * 1024
MAXIMUM_CLI_HEADER_COUNT = 1000

DEFAULT_OWNED_AUTHORIZATION_VALIDITY_DAYS = 30
MAXIMUM_OWNED_AUTHORIZATION_VALIDITY_DAYS = 366
DEFAULT_OWNED_AUDIT_SUFFIX = ".authorization-audit.json"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CliControlledError(ValueError):
    """A bounded user-facing CLI failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


def _positive_bounded_float(
    value: object,
    *,
    name: str,
    maximum: float,
) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
    ):
        raise CliControlledError(
            f"{name}_invalid",
            f"{name.replace('_', ' ')} must be a number.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    number = float(value)

    if not math.isfinite(number) or not 0 < number <= maximum:
        raise CliControlledError(
            f"{name}_invalid",
            f"{name.replace('_', ' ')} must be greater than zero and "
            f"no more than {maximum:g}.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    return number


def _positive_bounded_integer(
    value: object,
    *,
    name: str,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise CliControlledError(
            f"{name}_invalid",
            f"{name.replace('_', ' ')} must be an integer from 1 to "
            f"{maximum}.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    return value


def _build_fetch_policy(args: argparse.Namespace) -> FetchPolicy:
    return FetchPolicy(
        timeout_seconds=_positive_bounded_float(
            args.timeout_seconds,
            name="timeout_seconds",
            maximum=MAXIMUM_CLI_TIMEOUT_SECONDS,
        ),
        maximum_body_bytes=_positive_bounded_integer(
            args.maximum_body_bytes,
            name="maximum_body_bytes",
            maximum=MAXIMUM_CLI_BODY_BYTES,
        ),
        maximum_header_bytes=_positive_bounded_integer(
            args.maximum_header_bytes,
            name="maximum_header_bytes",
            maximum=MAXIMUM_CLI_HEADER_BYTES,
        ),
        maximum_header_count=_positive_bounded_integer(
            args.maximum_header_count,
            name="maximum_header_count",
            maximum=MAXIMUM_CLI_HEADER_COUNT,
        ),
    )


def _build_retry_policy(args: argparse.Namespace) -> RetryPolicy:
    try:
        return RetryPolicy(
            maximum_attempts=args.maximum_attempts,
            initial_backoff_seconds=args.initial_backoff_seconds,
            backoff_multiplier=args.backoff_multiplier,
            maximum_backoff_seconds=args.maximum_backoff_seconds,
        )
    except ValueError as exc:
        raise CliControlledError(
            "retry_policy_invalid",
            str(exc),
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc




def _load_owned_authorization(path: Path) -> OwnedTargetAuthorization:
    try:
        return load_owned_target_authorization_file(path)
    except OwnedTargetContractError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc


def _owned_authorization_options_configured(
    args: argparse.Namespace,
) -> bool:
    return any(
        value is not None
        for value in (
            args.authorization_file,
            args.confirm_authorization,
            args.audit_output,
        )
    ) or bool(args.preflight_only)


def _normalise_audit_path(
    configured_path: Path | None,
    *,
    output_path: Path,
) -> Path:
    if configured_path is not None:
        try:
            return configured_path.expanduser()
        except (RuntimeError, ValueError) as exc:
            raise CliControlledError(
                "owned_target_audit_path_invalid",
                "The owned-target audit path is invalid.",
                exit_code=EXIT_OUTPUT_FAILED,
            ) from exc
    return output_path.with_name(
        output_path.name + DEFAULT_OWNED_AUDIT_SUFFIX
    )


def _paths_resolve_equal(first: Path, second: Path) -> bool:
    try:
        return first.resolve(strict=False) == second.resolve(strict=False)
    except OSError as exc:
        raise CliControlledError(
            "path_resolution_failed",
            "Unable to resolve one or more output paths.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc


def _write_owned_audit(
    preflight: OwnedTargetPreflight,
    path: Path,
    *,
    overwrite: bool,
) -> None:
    try:
        write_owned_target_audit_file(
            preflight.audit_record,
            path,
            overwrite=overwrite,
        )
    except OwnedTargetContractError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc


def _render_owned_preflight(
    preflight: OwnedTargetPreflight,
    *,
    stream: TextIO,
    audit_path: Path | None = None,
) -> None:
    authorization = preflight.authorization
    policy = preflight.execution_policy
    print("Owned-target readiness: approved", file=stream)
    print(
        f"Authorization ID: {authorization.authorization_id}",
        file=stream,
    )
    print(f"Organization: {authorization.organization}", file=stream)
    print(f"Authorized by: {authorization.authorized_by}", file=stream)
    print(f"Canonical target: {authorization.target}", file=stream)
    print(
        "Authorized hosts: "
        + ", ".join(authorization.allowed_hosts),
        file=stream,
    )
    print(
        "Authorization validity: "
        f"{authorization.issued_at.isoformat()} to "
        f"{authorization.expires_at.isoformat()}",
        file=stream,
    )
    print(
        "Resolved public addresses: "
        + ", ".join(preflight.audit_record.resolved_addresses),
        file=stream,
    )
    print(
        "Mode: "
        + ("passive same-origin crawl" if policy.crawl_enabled else "passive single page"),
        file=stream,
    )
    print(
        "Request policy: "
        f"timeout {policy.timeout_seconds:g}s, "
        f"attempts {policy.maximum_attempts_per_request}, "
        f"body {policy.maximum_body_bytes} bytes",
        file=stream,
    )
    if policy.crawl_enabled:
        print(
            "Crawl policy: "
            f"pages {policy.maximum_pages}, depth {policy.maximum_depth}, "
            f"links/page {policy.maximum_links_per_page}, "
            f"delay {policy.minimum_delay_seconds:g}s, "
            f"time {policy.maximum_execution_seconds:g}s, "
            f"request budget {policy.maximum_request_attempts}",
            file=stream,
        )
    print(
        "Stop conditions: "
        + ", ".join(preflight.audit_record.stop_conditions),
        file=stream,
    )
    print(
        f"Authorization SHA-256: {preflight.authorization_sha256}",
        file=stream,
    )
    if audit_path is not None:
        print(f"Audit record: {audit_path}", file=stream)


def _crawl_limit_options_configured(
    args: argparse.Namespace,
) -> bool:
    return any(
        value is not None
        for value in (
            args.crawl_maximum_pages,
            args.crawl_maximum_depth,
            args.crawl_maximum_links_per_page,
            args.crawl_minimum_delay_seconds,
            args.crawl_query_mode,
            args.crawl_maximum_execution_seconds,
            args.crawl_maximum_request_attempts,
        )
    )


def _checkpoint_options_configured(
    args: argparse.Namespace,
) -> bool:
    return any(
        value is not None
        for value in (
            args.checkpoint,
            args.resume_from,
            args.checkpoint_key_file,
        )
    ) or bool(args.checkpoint_overwrite)


def _crawl_policy_from_checkpoint(
    policy: CrawlScanPolicy,
) -> CrawlPolicy:
    try:
        return CrawlPolicy(
            maximum_pages=policy.maximum_pages,
            maximum_depth=policy.maximum_depth,
            maximum_links_per_page=policy.maximum_links_per_page,
            maximum_url_length=policy.maximum_url_length,
            minimum_delay_seconds=policy.minimum_delay_seconds,
            maximum_execution_seconds=(
                policy.maximum_execution_seconds
            ),
            maximum_request_attempts=(
                policy.maximum_request_attempts
            ),
            query_mode=CrawlQueryMode(policy.query_mode),
            allowed_content_types=frozenset(
                policy.allowed_content_types
            ),
            blocked_path_segments=frozenset(
                policy.blocked_path_segments
            ),
        )
    except (CrawlPolicyError, ValueError) as exc:
        raise CliControlledError(
            getattr(exc, "code", "checkpoint_policy_invalid"),
            str(exc),
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc


def _checkpoint_fetch_snapshot(
    policy: FetchPolicy,
) -> CrawlCheckpointFetchPolicy:
    return CrawlCheckpointFetchPolicy(
        timeout_seconds=policy.timeout_seconds,
        maximum_body_bytes=policy.maximum_body_bytes,
        maximum_header_bytes=policy.maximum_header_bytes,
        maximum_header_count=policy.maximum_header_count,
    )


def _checkpoint_retry_snapshot(
    policy: RetryPolicy,
) -> CrawlCheckpointRetryPolicy:
    return CrawlCheckpointRetryPolicy(
        maximum_attempts=policy.maximum_attempts,
        initial_backoff_seconds=policy.initial_backoff_seconds,
        backoff_multiplier=policy.backoff_multiplier,
        maximum_backoff_seconds=policy.maximum_backoff_seconds,
    )


def _load_checkpoint_key(path: Path) -> bytes:
    try:
        return load_crawl_checkpoint_key_file(path)
    except CrawlCheckpointError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc


def _load_resume_checkpoint(
    path: Path,
    key: bytes,
) -> CrawlCheckpoint:
    try:
        return load_crawl_checkpoint_file(path, key)
    except CrawlCheckpointError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc


def _check_checkpoint_destination(
    path: Path,
    *,
    overwrite: bool,
) -> None:
    try:
        exists = os.path.lexists(path)
    except OSError as exc:
        raise CliControlledError(
            "checkpoint_path_inspection_failed",
            f"Unable to inspect checkpoint path {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc

    if not exists:
        return

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CliControlledError(
            "checkpoint_path_inspection_failed",
            f"Unable to inspect checkpoint path {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise CliControlledError(
            "checkpoint_symlink_not_allowed",
            f"Refusing to use symbolic link {path} as a checkpoint.",
            exit_code=EXIT_OUTPUT_FAILED,
        )
    if not stat.S_ISREG(metadata.st_mode):
        raise CliControlledError(
            "checkpoint_not_regular_file",
            f"Checkpoint path {path} is not a regular file.",
            exit_code=EXIT_OUTPUT_FAILED,
        )
    if not overwrite:
        raise CliControlledError(
            "checkpoint_exists",
            f"Checkpoint file {path} already exists. Use "
            "--checkpoint-overwrite to replace it.",
            exit_code=EXIT_OUTPUT_FAILED,
        )


def _build_crawl_policy(
    args: argparse.Namespace,
    *,
    owned_limits: OwnedTargetLimits | None = None,
) -> CrawlPolicy | None:
    configured = _crawl_limit_options_configured(args)

    if not args.crawl:
        if configured:
            raise CliControlledError(
                "crawl_option_requires_crawl",
                "Crawl limit options require --crawl.",
                exit_code=EXIT_PREFLIGHT_FAILED,
            )
        return None

    if owned_limits is None:
        default_pages = 10
        default_depth = 1
        default_links = 100
        default_delay = 0.1
        default_execution = DEFAULT_CRAWL_EXECUTION_SECONDS
        default_requests = DEFAULT_CRAWL_REQUEST_ATTEMPTS
    else:
        default_pages = min(
            OWNED_DEFAULT_CRAWL_PAGES,
            owned_limits.maximum_pages,
        )
        default_depth = min(
            OWNED_DEFAULT_CRAWL_DEPTH,
            owned_limits.maximum_depth,
        )
        default_links = min(
            OWNED_DEFAULT_CRAWL_LINKS_PER_PAGE,
            owned_limits.maximum_links_per_page,
        )
        default_delay = max(
            OWNED_DEFAULT_CRAWL_DELAY_SECONDS,
            owned_limits.minimum_delay_seconds,
        )
        default_execution = min(
            OWNED_DEFAULT_CRAWL_EXECUTION_SECONDS,
            owned_limits.maximum_execution_seconds,
        )
        default_requests = min(
            OWNED_DEFAULT_CRAWL_REQUEST_ATTEMPTS,
            owned_limits.maximum_request_attempts,
        )

    try:
        return CrawlPolicy(
            maximum_pages=(
                default_pages
                if args.crawl_maximum_pages is None
                else args.crawl_maximum_pages
            ),
            maximum_depth=(
                default_depth
                if args.crawl_maximum_depth is None
                else args.crawl_maximum_depth
            ),
            maximum_links_per_page=(
                default_links
                if args.crawl_maximum_links_per_page is None
                else args.crawl_maximum_links_per_page
            ),
            minimum_delay_seconds=(
                default_delay
                if args.crawl_minimum_delay_seconds is None
                else args.crawl_minimum_delay_seconds
            ),
            maximum_execution_seconds=(
                default_execution
                if args.crawl_maximum_execution_seconds is None
                else args.crawl_maximum_execution_seconds
            ),
            maximum_request_attempts=(
                default_requests
                if args.crawl_maximum_request_attempts is None
                else args.crawl_maximum_request_attempts
            ),
            query_mode=CrawlQueryMode(
                "drop"
                if args.crawl_query_mode is None
                else args.crawl_query_mode
            ),
        )
    except (CrawlPolicyError, ValueError) as exc:
        raise CliControlledError(
            getattr(exc, "code", "crawl_policy_invalid"),
            str(exc),
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc


def _build_validation_policy(args: argparse.Namespace) -> ValidationPolicy:
    allowed_hosts = frozenset(args.allowed_hosts)

    if args.lab:
        if not allowed_hosts:
            raise CliControlledError(
                "lab_allowlist_required",
                "Laboratory mode requires at least one explicit "
                "--allow-host value.",
                exit_code=EXIT_PREFLIGHT_FAILED,
            )

        return ValidationPolicy(
            mode=ValidationMode.LAB,
            allowed_lab_hosts=allowed_hosts,
        )

    if allowed_hosts:
        raise CliControlledError(
            "allow_host_requires_lab_mode",
            "--allow-host can only be used together with --lab.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    return ValidationPolicy(mode=ValidationMode.COMMERCIAL)


def _normalise_output_path(
    configured_path: Path | None,
    *,
    scan_id: str,
) -> Path:
    if configured_path is None:
        return DEFAULT_OUTPUT_DIRECTORY / f"{scan_id}.json"

    try:
        return configured_path.expanduser()
    except (RuntimeError, ValueError) as exc:
        raise CliControlledError(
            "output_path_invalid",
            "The output path is invalid.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc


def _check_output_path(path: Path, *, overwrite: bool) -> None:
    try:
        exists = os.path.lexists(path)
    except (OSError, TypeError, ValueError) as exc:
        raise CliControlledError(
            "output_path_invalid",
            f"Unable to inspect output path {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc

    if not exists:
        return

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CliControlledError(
            "output_path_inspection_failed",
            f"Unable to inspect output path {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc

    if stat.S_ISLNK(metadata.st_mode):
        raise CliControlledError(
            "output_symlink_not_allowed",
            f"Refusing to write a scan report through symbolic link {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        )

    if not stat.S_ISREG(metadata.st_mode):
        raise CliControlledError(
            "output_not_regular_file",
            f"Output path {path} is not a regular file.",
            exit_code=EXIT_OUTPUT_FAILED,
        )

    if not overwrite:
        raise CliControlledError(
            "output_exists",
            f"Output file {path} already exists. Use --overwrite to "
            "replace it explicitly.",
            exit_code=EXIT_OUTPUT_FAILED,
        )


def _write_report(
    result: WebGuardReport,
    path: Path,
    *,
    overwrite: bool,
) -> None:
    _check_output_path(path, overwrite=overwrite)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CliControlledError(
            "output_directory_create_failed",
            f"Unable to create output directory {path.parent}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc

    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if overwrite else os.O_EXCL

    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    file_descriptor: int | None = None

    try:
        file_descriptor = os.open(path, flags, 0o600)
        with os.fdopen(
            file_descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as output_file:
            file_descriptor = None
            output_file.write(result.to_json())
            output_file.write("\n")
    except FileExistsError as exc:
        raise CliControlledError(
            "output_exists",
            f"Output file {path} already exists.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc
    except OSError as exc:
        raise CliControlledError(
            "output_write_failed",
            f"Unable to write scan report {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)


def _write_text_output(
    content: str,
    path: Path,
    *,
    overwrite: bool,
) -> None:
    """Write a UTF-8 report artifact without following symbolic links."""

    _check_output_path(path, overwrite=overwrite)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CliControlledError(
            "output_directory_create_failed",
            f"Unable to create output directory {path.parent}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc

    flags = os.O_WRONLY | os.O_CREAT
    flags |= os.O_TRUNC if overwrite else os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as output_file:
            descriptor = None
            output_file.write(content)
            if not content.endswith("\n"):
                output_file.write("\n")
    except FileExistsError as exc:
        raise CliControlledError(
            "output_exists",
            f"Output file {path} already exists.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc
    except OSError as exc:
        raise CliControlledError(
            "output_write_failed",
            f"Unable to write report artifact {path}.",
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _display_values(values: tuple[object, ...]) -> str:
    if not values:
        return "none"
    return ", ".join(str(value) for value in values)


def _render_scan_result(
    result: ScanResult,
    *,
    stream: TextIO,
    output_path: Path | None = None,
) -> None:
    completion = result.coverage.completion_percent
    completion_text = "not applicable" if completion is None else f"{completion}%"

    print(f"Scan ID: {result.scan_id}", file=stream)
    print(f"Status: {result.status.value}", file=stream)
    print(f"Target: {result.target}", file=stream)
    print(f"Engine: {result.engine} {result.engine_version}", file=stream)
    print(
        "Connected addresses: "
        f"{_display_values(result.connected_addresses)}",
        file=stream,
    )
    print(
        f"HTTP statuses: {_display_values(result.http_statuses)}",
        file=stream,
    )
    print(
        "Requests: "
        f"{result.coverage.requests_attempted} attempted, "
        f"{result.coverage.requests_succeeded} succeeded",
        file=stream,
    )
    print(f"Coverage: {completion_text}", file=stream)
    print(f"Findings: {len(result.findings)}", file=stream)
    print(f"Errors: {len(result.errors)}", file=stream)

    for finding in result.findings:
        print(
            f"- [{finding.severity.value.upper()}] "
            f"{finding.title} ({finding.identity.rule_id})",
            file=stream,
        )

    for skipped in result.coverage.skipped_checks:
        print(
            f"- [SKIPPED] {skipped.check_id}: {skipped.reason}",
            file=stream,
        )

    for error in result.errors:
        print(
            f"- [ERROR] {error.stage}/{error.code}: {error.message} "
            f"(retryable: {'yes' if error.retryable else 'no'})",
            file=stream,
        )

    for attempt in result.request_attempts:
        if attempt.outcome.value == "succeeded":
            print(
                f"- [ATTEMPT {attempt.attempt_number}] succeeded: "
                f"{attempt.connected_address}, HTTP {attempt.http_status}, "
                f"{attempt.duration_milliseconds} ms",
                file=stream,
            )
        else:
            print(
                f"- [ATTEMPT {attempt.attempt_number}] failed: "
                f"{attempt.error_code}; retry scheduled: "
                f"{'yes' if attempt.retry_scheduled else 'no'}; "
                f"backoff: {attempt.backoff_seconds} s",
                file=stream,
            )

    if output_path is not None:
        print(f"Saved report: {output_path}", file=stream)


def _render_crawl_result(
    result: CrawlScanResult,
    *,
    stream: TextIO,
    output_path: Path | None = None,
) -> None:
    completion = result.coverage.completion_percent
    completion_text = (
        "not applicable"
        if completion is None
        else f"{completion}%"
    )

    print(f"Scan ID: {result.scan_id}", file=stream)
    print(f"Status: {result.status.value}", file=stream)
    print(f"Target: {result.target}", file=stream)
    print(f"Engine: {result.engine} {result.engine_version}", file=stream)
    print("Mode: same-origin crawl", file=stream)
    print(
        "Termination: "
        f"{result.termination.reason.value}",
        file=stream,
    )
    print(
        "Pages: "
        f"{result.coverage.pages_attempted} attempted, "
        f"{result.coverage.pages_succeeded} succeeded, "
        f"{result.coverage.pages_failed} failed, "
        f"{result.coverage.pages_pending} pending",
        file=stream,
    )
    print(
        "Requests: "
        f"{result.coverage.requests_attempted} attempted, "
        f"{result.coverage.requests_succeeded} succeeded",
        file=stream,
    )
    print(f"Coverage: {completion_text}", file=stream)
    print(f"Findings: {len(result.findings)}", file=stream)
    print(f"Errors: {len(result.errors)}", file=stream)
    print(
        "Connected addresses: "
        f"{_display_values(result.connected_addresses)}",
        file=stream,
    )
    print(
        f"HTTP statuses: {_display_values(result.http_statuses)}",
        file=stream,
    )

    for page in result.pages:
        page_coverage = page.coverage.completion_percent
        page_coverage_text = (
            "not applicable"
            if page_coverage is None
            else f"{page_coverage}%"
        )
        print(
            f"- [PAGE depth={page.depth}] {page.status.value}: "
            f"{page.url}; coverage {page_coverage_text}; "
            f"findings {len(page.findings)}; errors {len(page.errors)}",
            file=stream,
        )
        for finding in page.findings:
            print(
                f"  - [{finding.severity.value.upper()}] "
                f"{finding.title} ({finding.identity.rule_id})",
                file=stream,
            )
        for error in page.errors:
            print(
                f"  - [ERROR] {error.stage}/{error.code}: "
                f"{error.message}",
                file=stream,
            )

    termination_error = result.termination.error
    if termination_error is not None:
        print(
            f"- [ERROR] {termination_error.stage}/"
            f"{termination_error.code}: "
            f"{termination_error.message}",
            file=stream,
        )

    for skipped in result.skipped_links:
        print(
            f"- [CRAWL SKIP] {skipped.reason}: {skipped.count}",
            file=stream,
        )

    if output_path is not None:
        print(f"Saved report: {output_path}", file=stream)



def _render_report(
    result: WebGuardReport,
    *,
    stream: TextIO,
    output_path: Path | None = None,
) -> None:
    if isinstance(result, CrawlScanResult):
        _render_crawl_result(
            result,
            stream=stream,
            output_path=output_path,
        )
    else:
        _render_scan_result(
            result,
            stream=stream,
            output_path=output_path,
        )


@contextmanager
def _graceful_crawl_cancellation(
    token: CrawlCancellationToken,
):
    """Convert SIGINT into a bounded cancellation request."""

    if (
        current_thread() is not main_thread()
        or not hasattr(signal, "SIGINT")
    ):
        yield
        return

    previous_handler = signal.getsignal(signal.SIGINT)

    def request_cancellation(_signum, _frame) -> None:
        token.cancel()

    signal.signal(signal.SIGINT, request_cancellation)

    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous_handler)


def _scan_command(args: argparse.Namespace) -> int:
    if _checkpoint_options_configured(args) and not args.crawl:
        raise CliControlledError(
            "checkpoint_option_requires_crawl",
            "Checkpoint and resume options require --crawl.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    if _crawl_limit_options_configured(args) and not args.crawl:
        raise CliControlledError(
            "crawl_option_requires_crawl",
            "Crawl limit options require --crawl.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    if (
        args.checkpoint_key_file is not None
        and args.checkpoint is None
        and args.resume_from is None
    ):
        raise CliControlledError(
            "checkpoint_key_without_checkpoint",
            "--checkpoint-key-file requires --checkpoint or --resume-from.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    if (
        (args.checkpoint is not None or args.resume_from is not None)
        and args.checkpoint_key_file is None
    ):
        raise CliControlledError(
            "checkpoint_key_required",
            "Signed checkpoints require --checkpoint-key-file.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    if (
        args.checkpoint_overwrite
        and args.checkpoint is None
        and args.resume_from is None
    ):
        raise CliControlledError(
            "checkpoint_overwrite_without_checkpoint",
            "--checkpoint-overwrite requires --checkpoint or --resume-from.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    if args.preflight_only and (
        args.output is not None
        or args.overwrite
        or args.audit_output is not None
        or _checkpoint_options_configured(args)
    ):
        raise CliControlledError(
            "preflight_only_output_option_invalid",
            "--preflight-only cannot write reports, audit files, or checkpoints.",
            exit_code=EXIT_PREFLIGHT_FAILED,
        )

    # Validate generic CLI policy values before authorization requirements so
    # malformed options fail deterministically without reading external files.
    validation_policy = _build_validation_policy(args)
    fetch_policy = _build_fetch_policy(args)
    retry_policy = _build_retry_policy(args)
    _build_crawl_policy(args)

    checkpoint_key: bytes | None = None
    resume_checkpoint: CrawlCheckpoint | None = None

    if args.checkpoint_key_file is not None:
        checkpoint_key = _load_checkpoint_key(
            args.checkpoint_key_file
        )

    if args.resume_from is not None:
        assert checkpoint_key is not None
        resume_checkpoint = _load_resume_checkpoint(
            args.resume_from,
            checkpoint_key,
        )
        scan_id = resume_checkpoint.scan_id
    else:
        scan_id = str(uuid4())

    output_path: Path | None = None
    checkpoint_path: Path | None = None

    if not args.preflight_only:
        output_path = _normalise_output_path(
            args.output,
            scan_id=scan_id,
        )
        _check_output_path(output_path, overwrite=args.overwrite)

        if args.checkpoint is not None:
            checkpoint_path = args.checkpoint.expanduser()
        elif args.resume_from is not None:
            checkpoint_path = args.resume_from.expanduser()

        if checkpoint_path is not None:
            if _paths_resolve_equal(checkpoint_path, output_path):
                raise CliControlledError(
                    "checkpoint_report_path_conflict",
                    "Checkpoint and report paths must be different.",
                    exit_code=EXIT_OUTPUT_FAILED,
                )

            same_as_resume = (
                args.resume_from is not None
                and checkpoint_path == args.resume_from.expanduser()
            )
            _check_checkpoint_destination(
                checkpoint_path,
                overwrite=(
                    same_as_resume
                    or args.checkpoint_overwrite
                ),
            )

    authorization: OwnedTargetAuthorization | None = None

    if args.lab:
        if _owned_authorization_options_configured(args):
            raise CliControlledError(
                "owned_target_option_requires_commercial_mode",
                "Owned-target authorization options cannot be used with --lab.",
                exit_code=EXIT_PREFLIGHT_FAILED,
            )
    else:
        if args.authorization_file is None:
            raise CliControlledError(
                "owned_target_authorization_required",
                "External commercial scans require --authorization-file.",
                exit_code=EXIT_PREFLIGHT_FAILED,
            )
        if args.confirm_authorization is None:
            raise CliControlledError(
                "owned_target_confirmation_required",
                "External commercial scans require --confirm-authorization.",
                exit_code=EXIT_PREFLIGHT_FAILED,
            )
        authorization = _load_owned_authorization(
            args.authorization_file
        )

    if (
        resume_checkpoint is not None
        and not _crawl_limit_options_configured(args)
    ):
        crawl_policy = _crawl_policy_from_checkpoint(
            resume_checkpoint.policy
        )
    else:
        crawl_policy = _build_crawl_policy(
            args,
            owned_limits=(
                None if authorization is None else authorization.limits
            ),
        )

    audit_path: Path | None = None
    if authorization is not None and not args.preflight_only:
        assert output_path is not None
        audit_path = _normalise_audit_path(
            args.audit_output,
            output_path=output_path,
        )
        if _paths_resolve_equal(audit_path, output_path):
            raise CliControlledError(
                "owned_target_audit_report_path_conflict",
                "Owned-target audit and report paths must be different.",
                exit_code=EXIT_OUTPUT_FAILED,
            )
        if _paths_resolve_equal(
            audit_path,
            args.authorization_file.expanduser(),
        ):
            raise CliControlledError(
                "owned_target_audit_authorization_path_conflict",
                "Owned-target audit cannot overwrite the authorization file.",
                exit_code=EXIT_OUTPUT_FAILED,
            )
        if (
            checkpoint_path is not None
            and _paths_resolve_equal(audit_path, checkpoint_path)
        ):
            raise CliControlledError(
                "owned_target_audit_checkpoint_path_conflict",
                "Owned-target audit and checkpoint paths must be different.",
                exit_code=EXIT_OUTPUT_FAILED,
            )
        _check_output_path(audit_path, overwrite=args.overwrite)

    if authorization is not None:
        # Reject a malformed, expired, confirmation-mismatched, or
        # out-of-scope authorization using only the canonicalised URL
        # string, before validate_target_url's DNS resolution below ever
        # runs. This is an additional, earlier gate, not a replacement for
        # the full re-check validate_owned_target_preflight still performs
        # against the actual resolved target further down -- destination
        # validation (DNS resolution, private/reserved-address rejection)
        # still runs in full and still gates every connection exactly as
        # before.
        try:
            early_canonical_target = canonicalize_target_url(
                args.target,
                validation_policy,
            )
        except TargetValidationError as exc:
            raise CliControlledError(
                getattr(exc, "code", "target_validation_failed"),
                str(exc),
                exit_code=EXIT_PREFLIGHT_FAILED,
            ) from exc
        try:
            validate_owned_target_authorization_static(
                authorization,
                early_canonical_target,
                confirmation=args.confirm_authorization,
                now=_utc_now(),
            )
        except OwnedTargetPreflightError as exc:
            raise CliControlledError(
                exc.code,
                exc.message,
                exit_code=EXIT_PREFLIGHT_FAILED,
            ) from exc

    try:
        target = validate_target_url(
            args.target,
            validation_policy,
        )
    except TargetValidationError as exc:
        raise CliControlledError(
            getattr(exc, "code", "target_validation_failed"),
            str(exc),
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc

    owned_preflight: OwnedTargetPreflight | None = None
    if authorization is not None:
        try:
            owned_preflight = validate_owned_target_preflight(
                authorization,
                target,
                confirmation=args.confirm_authorization,
                scan_id=scan_id,
                fetch_policy=fetch_policy,
                retry_policy=retry_policy,
                crawl_policy=crawl_policy,
                now=_utc_now(),
            )
        except OwnedTargetPreflightError as exc:
            raise CliControlledError(
                exc.code,
                exc.message,
                exit_code=EXIT_PREFLIGHT_FAILED,
            ) from exc

        _render_owned_preflight(
            owned_preflight,
            stream=sys.stdout,
            audit_path=audit_path,
        )

        if args.preflight_only:
            print("No HTTP request was sent.", file=sys.stdout)
            return EXIT_SUCCESS

        assert audit_path is not None
        _write_owned_audit(
            owned_preflight,
            audit_path,
            overwrite=args.overwrite,
        )

    assert output_path is not None

    if crawl_policy is None:
        result: WebGuardReport = run_passive_header_scan(
            target,
            fetch_policy=fetch_policy,
            retry_policy=retry_policy,
            scan_id=scan_id,
        )
    else:
        cancellation_token = CrawlCancellationToken()

        def persist_checkpoint(
            checkpoint: CrawlCheckpoint,
        ) -> None:
            if checkpoint_path is None:
                return
            assert checkpoint_key is not None
            try:
                write_crawl_checkpoint_file(
                    checkpoint,
                    checkpoint_path,
                    checkpoint_key,
                    overwrite=True,
                )
            except CrawlCheckpointError as exc:
                raise CliControlledError(
                    exc.code,
                    exc.message,
                    exit_code=EXIT_OUTPUT_FAILED,
                ) from exc

        try:
            with _graceful_crawl_cancellation(
                cancellation_token
            ):
                result = run_passive_crawl_scan(
                    target,
                    crawl_policy=crawl_policy,
                    fetch_policy=fetch_policy,
                    retry_policy=retry_policy,
                    scan_id=(
                        None
                        if resume_checkpoint is not None
                        else scan_id
                    ),
                    cancellation_token=cancellation_token,
                    resume_checkpoint=resume_checkpoint,
                    checkpoint_callback=(
                        persist_checkpoint
                        if checkpoint_path is not None
                        else None
                    ),
                )
        except CrawlCheckpointError as exc:
            raise CliControlledError(
                exc.code,
                exc.message,
                exit_code=EXIT_PREFLIGHT_FAILED,
            ) from exc

    _write_report(
        result,
        output_path,
        overwrite=args.overwrite,
    )
    _render_report(
        result,
        stream=sys.stdout,
        output_path=output_path,
    )

    if audit_path is not None:
        print(f"Saved authorization audit: {audit_path}", file=sys.stdout)

    if checkpoint_path is not None:
        print(
            f"Saved checkpoint: {checkpoint_path}",
            file=sys.stdout,
        )

    if result.status is ScanStatus.COMPLETED:
        return EXIT_SUCCESS

    return EXIT_SCAN_FAILED

def _authorization_limits_from_args(
    args: argparse.Namespace,
) -> OwnedTargetLimits:
    try:
        return OwnedTargetLimits(
            maximum_pages=args.authorization_maximum_pages,
            maximum_depth=args.authorization_maximum_depth,
            maximum_links_per_page=(
                args.authorization_maximum_links_per_page
            ),
            minimum_delay_seconds=(
                args.authorization_minimum_delay_seconds
            ),
            maximum_execution_seconds=(
                args.authorization_maximum_execution_seconds
            ),
            maximum_request_attempts=(
                args.authorization_maximum_request_attempts
            ),
            maximum_attempts_per_request=(
                args.authorization_maximum_attempts_per_request
            ),
            timeout_seconds=args.authorization_timeout_seconds,
            maximum_body_bytes=args.authorization_maximum_body_bytes,
            maximum_header_bytes=(
                args.authorization_maximum_header_bytes
            ),
            maximum_header_count=(
                args.authorization_maximum_header_count
            ),
        )
    except OwnedTargetContractError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc


def _authorization_create_command(args: argparse.Namespace) -> int:
    try:
        canonical_target = canonicalize_owned_target_url(args.target)
        canonical_host = urlsplit(canonical_target).hostname
        assert canonical_host is not None
        configured_hosts = tuple(
            canonicalize_owned_target_hostname(value)
            for value in args.authorization_allowed_hosts
        )
        allowed_hosts = tuple(
            sorted({canonical_host, *configured_hosts})
        )
        validity_days = _positive_bounded_integer(
            args.authorization_validity_days,
            name="authorization_validity_days",
            maximum=MAXIMUM_OWNED_AUTHORIZATION_VALIDITY_DAYS,
        )
        issued_at = _utc_now()
        authorization = OwnedTargetAuthorization(
            authorization_id=(
                str(uuid4())
                if args.authorization_id is None
                else args.authorization_id
            ),
            organization=args.organization,
            authorized_by=args.authorized_by,
            target=canonical_target,
            allowed_hosts=allowed_hosts,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(days=validity_days),
            purpose=args.purpose,
            limits=_authorization_limits_from_args(args),
        )
    except OwnedTargetContractError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_PREFLIGHT_FAILED,
        ) from exc

    try:
        path = write_owned_target_authorization_file(
            authorization,
            args.output,
            overwrite=args.overwrite,
        )
    except OwnedTargetContractError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_OUTPUT_FAILED,
        ) from exc

    print(f"Created authorization: {path}")
    print(f"Authorization ID: {authorization.authorization_id}")
    print(f"Canonical target: {authorization.target}")
    print(
        "Authorized hosts: "
        + ", ".join(authorization.allowed_hosts)
    )
    print(f"Expires: {authorization.expires_at.isoformat()}")
    print(f"SHA-256: {authorization.fingerprint}")
    return EXIT_SUCCESS


def _authorization_validate_command(args: argparse.Namespace) -> int:
    authorization = _load_owned_authorization(args.authorization)
    print(f"Valid authorization: {args.authorization}")
    print(f"Authorization ID: {authorization.authorization_id}")
    print(f"Canonical target: {authorization.target}")
    print(f"Expires: {authorization.expires_at.isoformat()}")
    print(f"SHA-256: {authorization.fingerprint}")
    return EXIT_SUCCESS


def _authorization_inspect_command(args: argparse.Namespace) -> int:
    authorization = _load_owned_authorization(args.authorization)
    if args.json_output:
        print(authorization.to_json())
        return EXIT_SUCCESS

    limits = authorization.limits
    print(f"Authorization: {args.authorization}")
    print(f"Authorization ID: {authorization.authorization_id}")
    print(f"Organization: {authorization.organization}")
    print(f"Authorized by: {authorization.authorized_by}")
    print(f"Canonical target: {authorization.target}")
    print(
        "Authorized hosts: "
        + ", ".join(authorization.allowed_hosts)
    )
    print(f"Issued: {authorization.issued_at.isoformat()}")
    print(f"Expires: {authorization.expires_at.isoformat()}")
    print(f"Purpose: {authorization.purpose}")
    print("Passive only: yes")
    print(
        "Limits: "
        f"pages {limits.maximum_pages}, depth {limits.maximum_depth}, "
        f"links/page {limits.maximum_links_per_page}, "
        f"delay {limits.minimum_delay_seconds:g}s, "
        f"time {limits.maximum_execution_seconds:g}s, "
        f"request budget {limits.maximum_request_attempts}, "
        f"attempts/request {limits.maximum_attempts_per_request}"
    )
    print(f"SHA-256: {authorization.fingerprint}")
    return EXIT_SUCCESS


def _load_report(path: Path) -> WebGuardReport:
    try:
        return load_webguard_report_file(path)
    except ScanReportLoadError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_REPORT_INVALID,
        ) from exc


def _report_validate_command(args: argparse.Namespace) -> int:
    result = _load_report(args.report)

    print(f"Valid report: {args.report}")
    print(
        "Report type: "
        + (
            "crawl_scan"
            if isinstance(result, CrawlScanResult)
            else "single_scan"
        )
    )
    print(f"Normalized schema: {result.schema_version}")
    print(f"Scan ID: {result.scan_id}")
    print(f"Status: {result.status.value}")

    return EXIT_SUCCESS


def _report_inspect_command(args: argparse.Namespace) -> int:
    result = _load_report(args.report)

    if args.json_output:
        print(result.to_json())
    else:
        print(f"Report: {args.report}")
        _render_report(result, stream=sys.stdout)

    return EXIT_SUCCESS


def _report_render_command(args: argparse.Namespace) -> int:
    result = _load_report(args.report)
    comparison = None
    if args.baseline is not None:
        baseline = _load_report(args.baseline)
        try:
            comparison = build_report_comparison(
                baseline,
                result,
                generated_at=_utc_now(),
            )
        except ProfessionalReportError as exc:
            raise CliControlledError(
                exc.code,
                exc.message,
                exit_code=EXIT_REPORT_INVALID,
            ) from exc

    try:
        profile = ProfessionalReportProfile(
            organization=args.organization,
            report_title=args.title,
            prepared_by=args.prepared_by,
            classification=args.classification,
            generated_at=_utc_now(),
        )
        rendered = render_professional_html(
            result,
            profile,
            comparison=comparison,
        )
    except ProfessionalReportError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_REPORT_INVALID,
        ) from exc

    output = args.output.expanduser()
    _write_text_output(rendered, output, overwrite=args.overwrite)
    print(f"Professional HTML report: {output}")
    print(f"Scan ID: {result.scan_id}")
    print(f"Findings: {len(result.findings)}")
    if comparison is not None:
        print(
            "Remediation comparison: "
            f"{comparison.new_count} new, "
            f"{comparison.remaining_count} remaining, "
            f"{comparison.fixed_count} fixed"
        )
    return EXIT_SUCCESS


def _report_compare_command(args: argparse.Namespace) -> int:
    baseline = _load_report(args.baseline)
    current = _load_report(args.current)
    try:
        comparison = build_report_comparison(
            baseline,
            current,
            generated_at=_utc_now(),
        )
    except ProfessionalReportError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_REPORT_INVALID,
        ) from exc

    output = args.output.expanduser()
    _write_text_output(
        comparison.to_json(),
        output,
        overwrite=args.overwrite,
    )
    print(f"Comparison report: {output}")
    print(f"Baseline scan: {comparison.baseline_scan_id}")
    print(f"Current scan: {comparison.current_scan_id}")
    print(f"New findings: {comparison.new_count}")
    print(f"Remaining findings: {comparison.remaining_count}")
    print(f"Fixed findings: {comparison.fixed_count}")
    print(f"Presentation changes: {comparison.changed_count}")
    return EXIT_SUCCESS


def _report_comparison_validate_command(args: argparse.Namespace) -> int:
    try:
        comparison = load_report_comparison_file(args.comparison)
    except ReportComparisonError as exc:
        raise CliControlledError(
            exc.code,
            exc.message,
            exit_code=EXIT_REPORT_INVALID,
        ) from exc
    print(f"Valid comparison: {args.comparison}")
    print(f"Normalized schema: {comparison.schema_version}")
    print(f"Baseline scan: {comparison.baseline_scan_id}")
    print(f"Current scan: {comparison.current_scan_id}")
    print(
        "Summary: "
        f"{comparison.new_count} new, "
        f"{comparison.remaining_count} remaining, "
        f"{comparison.fixed_count} fixed"
    )
    return EXIT_SUCCESS


def _init_command(args: argparse.Namespace) -> int:
    home = args.directory.expanduser()

    created: list[Path] = []
    for subdirectory in ("authorizations", "scan-results", "reports"):
        target = home / subdirectory
        existed = target.exists()
        try:
            target.mkdir(parents=True, exist_ok=True)
            os.chmod(target, 0o700)
        except OSError as exc:
            raise CliControlledError(
                "init_directory_create_failed",
                f"Unable to create {target}.",
                exit_code=EXIT_OUTPUT_FAILED,
            ) from exc
        if not existed:
            created.append(target)

    print(f"WebGuard workspace: {home.resolve()}")
    if created:
        print("Created:")
        for path in created:
            print(f"  - {path}")
    else:
        print("All workspace directories already existed.")

    authorization_file = home / "authorizations" / "example.json"
    report_file = home / "scan-results" / "example.json"

    print()
    print("Next steps:")
    print("  A lab target on loopback or a private network (no authorization document):")
    print(
        "    webguard scan http://127.0.0.1:8000/ --lab --allow-host 127.0.0.1 "
        f"--output {report_file}"
    )
    print("  A real target you are authorized to assess:")
    print(
        "    webguard authorization create https://your-site.example "
        '--organization "Your Org" --authorized-by "you@your-org.example" '
        f'--purpose "Describe the assessment" --output {authorization_file}'
    )
    print(
        "    webguard scan https://your-site.example "
        f"--authorization-file {authorization_file} "
        f"--confirm-authorization <authorization-id> --output {report_file}"
    )
    print("  Then render a report:")
    print(
        f"    webguard report render {report_file} "
        f"--output {home / 'reports' / 'example.html'} "
        '--organization "Your Org"'
    )

    return EXIT_SUCCESS


def _doctor_command(args: argparse.Namespace) -> int:
    checks: list[tuple[str, bool, str]] = []

    python_ok = sys.version_info >= (3, 11)
    checks.append((
        "Python version",
        python_ok,
        f"{platform.python_version()}"
        + ("" if python_ok else " (webguard requires Python >= 3.11)"),
    ))

    for distribution_name in (
        "openhuntx-webguard",
        "openhuntx-webguard-contracts",
    ):
        try:
            version = importlib.metadata.version(distribution_name)
            checks.append((distribution_name, True, version))
        except importlib.metadata.PackageNotFoundError:
            checks.append((
                distribution_name,
                False,
                "not installed via package metadata (editable/dev checkout?)",
            ))

    directory = args.directory.expanduser()

    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / f".webguard-doctor-{uuid4().hex}"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
        checks.append(("Write access", True, str(directory.resolve())))
    except OSError as exc:
        checks.append(("Write access", False, f"{directory}: {exc}"))

    try:
        usage = shutil.disk_usage(directory)
        free_megabytes = usage.free / (1024 * 1024)
        checks.append((
            "Free disk space",
            free_megabytes >= 50,
            f"{free_megabytes:.0f} MiB free at {directory.resolve()}",
        ))
    except OSError as exc:
        checks.append(("Free disk space", False, str(exc)))

    all_ok = all(ok for _, ok, _ in checks)

    for name, ok, detail in checks:
        print(f"[{'OK' if ok else 'FAIL'}] {name}: {detail}")

    print()
    print(
        "Note: target reachability is not checked here. Each `webguard scan` "
        "run verifies its own authorized target during preflight."
    )

    return EXIT_SUCCESS if all_ok else EXIT_DOCTOR_CHECK_FAILED


def _iter_result_files(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    # Authorization audit records live beside the reports they belong to.
    # They are evidence, not scan results: never list them as unreadable
    # results and never let `results clean` delete them.
    return sorted(
        (
            path
            for path in directory.glob("*.json")
            if path.is_file() and not path.name.endswith(DEFAULT_OWNED_AUDIT_SUFFIX)
        ),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def _results_list_command(args: argparse.Namespace) -> int:
    directory = args.directory.expanduser()
    files = _iter_result_files(directory)

    if not files:
        print(f"No stored results found in {directory}.")
        return EXIT_SUCCESS

    rows: list[dict[str, object]] = []
    for path in files:
        try:
            result = load_webguard_report_file(path)
        except ScanReportLoadError as exc:
            rows.append({
                "path": str(path),
                "readable": False,
                "error": exc.message,
            })
            continue
        rows.append({
            "path": str(path),
            "readable": True,
            "scan_id": result.scan_id,
            "status": result.status.value,
            "target": result.target,
            "findings": len(result.findings),
        })

    if args.json_output:
        print(json.dumps(rows, indent=2))
        return EXIT_SUCCESS

    for row in rows:
        if not row["readable"]:
            print(f"- [UNREADABLE] {row['path']}: {row['error']}")
            continue
        print(
            f"- {row['path']} | {row['status']} | {row['target']} | "
            f"{row['findings']} finding(s) | scan {row['scan_id']}"
        )

    return EXIT_SUCCESS


def _results_clean_command(args: argparse.Namespace) -> int:
    directory = args.directory.expanduser()
    files = _iter_result_files(directory)

    if not files:
        print(f"No stored results found in {directory}.")
        return EXIT_SUCCESS

    if args.older_than_days is not None:
        cutoff = _utc_now().timestamp() - (args.older_than_days * 86400)
        files = [path for path in files if path.stat().st_mtime < cutoff]

    if not files:
        print("No results matched the cleanup criteria.")
        return EXIT_SUCCESS

    if not args.yes:
        print(f"Would delete {len(files)} file(s) from {directory}:")
        for path in files:
            print(f"  - {path}")
        print("Re-run with --yes to actually delete these files.")
        return EXIT_SUCCESS

    deleted = 0
    for path in files:
        try:
            path.unlink()
            deleted += 1
        except OSError as exc:
            print(f"webguard: could not delete {path}: {exc}", file=sys.stderr)

    print(f"Deleted {deleted} of {len(files)} file(s) from {directory}.")
    return EXIT_SUCCESS


def build_parser() -> argparse.ArgumentParser:
    """Build the public WebGuard argument parser."""

    parser = argparse.ArgumentParser(
        prog="webguard",
        description=(
            "Run passive OpenHuntX WebGuard scans only against targets "
            "you are authorised to assess."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {ENGINE_VERSION}",
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
    )

    scan = commands.add_parser(
        "scan",
        help="Run an authorised passive HTTP response scan.",
    )
    scan.add_argument("target", help="Authorised HTTP or HTTPS target URL.")
    scan.add_argument(
        "-o",
        "--output",
        type=Path,
        help=(
            "Report path. Defaults to scan-results/<scan-id>.json."
        ),
    )
    scan.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly replace an existing regular report file.",
    )
    scan.add_argument(
        "--lab",
        action="store_true",
        help=(
            "Enable laboratory scope rules. Requires at least one "
            "--allow-host value."
        ),
    )
    scan.add_argument(
        "--allow-host",
        action="append",
        dest="allowed_hosts",
        default=[],
        metavar="HOST",
        help=(
            "Explicitly allow an authorised laboratory hostname. "
            "May be repeated and is valid only with --lab."
        ),
    )
    scan.add_argument(
        "--authorization-file",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Validated owned-target authorization required for every "
            "external commercial scan."
        ),
    )
    scan.add_argument(
        "--confirm-authorization",
        default=None,
        metavar="UUID",
        help=(
            "Exact authorization ID acknowledgement required before any "
            "external scan traffic."
        ),
    )
    scan.add_argument(
        "--audit-output",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Owned-target preflight audit path. Defaults beside the scan "
            "report with an authorization-audit suffix."
        ),
    )
    scan.add_argument(
        "--preflight-only",
        action="store_true",
        help=(
            "Validate authorization, public scope, and effective limits "
            "without sending an HTTP request or writing files."
        ),
    )
    scan.add_argument(
        "--crawl",
        action="store_true",
        help=(
            "Safely crawl and passively analyse bounded same-origin HTML "
            "pages. No forms, JavaScript routes, or redirects are followed."
        ),
    )
    scan.add_argument(
        "--crawl-max-pages",
        dest="crawl_maximum_pages",
        type=int,
        default=None,
        metavar="COUNT",
        help=(
            "Maximum pages in crawl mode (default: 10; "
            f"maximum: {MAXIMUM_CRAWL_PAGES})."
        ),
    )
    scan.add_argument(
        "--crawl-max-depth",
        dest="crawl_maximum_depth",
        type=int,
        default=None,
        metavar="DEPTH",
        help=(
            "Maximum link depth in crawl mode (default: 1; "
            f"maximum: {MAXIMUM_CRAWL_DEPTH})."
        ),
    )
    scan.add_argument(
        "--crawl-max-links",
        dest="crawl_maximum_links_per_page",
        type=int,
        default=None,
        metavar="COUNT",
        help=(
            "Maximum anchor links considered per page (default: 100; "
            f"maximum: {MAXIMUM_LINKS_PER_PAGE})."
        ),
    )
    scan.add_argument(
        "--crawl-delay",
        dest="crawl_minimum_delay_seconds",
        type=float,
        default=None,
        metavar="SECONDS",
        help=(
            "Minimum delay between crawl pages (default: 0.1; "
            f"maximum: {MAXIMUM_CRAWL_DELAY_SECONDS:g})."
        ),
    )
    scan.add_argument(
        "--crawl-time-limit",
        dest="crawl_maximum_execution_seconds",
        type=float,
        default=None,
        metavar="SECONDS",
        help=(
            "Maximum total crawl execution time (default: "
            f"{DEFAULT_CRAWL_EXECUTION_SECONDS:g}; maximum: "
            f"{MAXIMUM_CRAWL_EXECUTION_SECONDS:g})."
        ),
    )
    scan.add_argument(
        "--crawl-request-budget",
        dest="crawl_maximum_request_attempts",
        type=int,
        default=None,
        metavar="COUNT",
        help=(
            "Maximum total HTTP request attempts across the crawl "
            f"(default and maximum: {MAXIMUM_CRAWL_REQUEST_ATTEMPTS})."
        ),
    )
    scan.add_argument(
        "--crawl-query-mode",
        choices=tuple(item.value for item in CrawlQueryMode),
        default=None,
        metavar="MODE",
        help=(
            "Discovered-query handling in crawl mode: drop or reject "
            "(default: drop)."
        ),
    )
    scan.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Atomically write a signed crawl checkpoint after each state "
            "transition. Requires --crawl and --checkpoint-key-file."
        ),
    )
    scan.add_argument(
        "--resume-from",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Authenticate, revalidate, and resume a signed crawl checkpoint. "
            "Requires --crawl and --checkpoint-key-file."
        ),
    )
    scan.add_argument(
        "--checkpoint-key-file",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Private HMAC key file for checkpoint signing and verification. "
            "On POSIX systems it must not grant group or other access."
        ),
    )
    scan.add_argument(
        "--checkpoint-overwrite",
        action="store_true",
        help=(
            "Explicitly replace an existing checkpoint destination. "
            "A resumed checkpoint may update its own file without this flag."
        ),
    )
    scan.add_argument(
        "--timeout",
        dest="timeout_seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help=(
            "Per-request timeout in seconds (default: 10; maximum: 60)."
        ),
    )
    scan.add_argument(
        "--max-body-bytes",
        dest="maximum_body_bytes",
        type=int,
        default=DEFAULT_MAXIMUM_BODY_BYTES,
        metavar="BYTES",
        help=(
            "Maximum response body bytes (default: 1048576; "
            "maximum: 16777216)."
        ),
    )
    scan.add_argument(
        "--max-header-bytes",
        dest="maximum_header_bytes",
        type=int,
        default=DEFAULT_MAXIMUM_HEADER_BYTES,
        metavar="BYTES",
        help=(
            "Maximum response header bytes (default: 65536; "
            "maximum: 1048576)."
        ),
    )
    scan.add_argument(
        "--max-header-count",
        dest="maximum_header_count",
        type=int,
        default=DEFAULT_MAXIMUM_HEADER_COUNT,
        metavar="COUNT",
        help=(
            "Maximum response header count (default: 100; maximum: 1000)."
        ),
    )
    scan.add_argument(
        "--max-attempts",
        dest="maximum_attempts",
        type=int,
        default=1,
        metavar="COUNT",
        help=(
            "Maximum total request attempts. The default of 1 disables "
            "retries; the enforced maximum is 3."
        ),
    )
    scan.add_argument(
        "--initial-backoff",
        dest="initial_backoff_seconds",
        type=float,
        default=0.25,
        metavar="SECONDS",
        help="Initial retry backoff (default: 0.25).",
    )
    scan.add_argument(
        "--backoff-multiplier",
        type=float,
        default=2.0,
        metavar="MULTIPLIER",
        help="Retry backoff multiplier (default: 2).",
    )
    scan.add_argument(
        "--max-backoff",
        dest="maximum_backoff_seconds",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Maximum retry backoff per failure (default: 2).",
    )
    scan.set_defaults(handler=_scan_command)

    init = commands.add_parser(
        "init",
        help="Create a local workspace (authorizations/, scan-results/, reports/).",
    )
    init.add_argument(
        "--directory",
        type=Path,
        default=Path("."),
        help="Workspace root (default: current directory).",
    )
    init.set_defaults(handler=_init_command)

    doctor = commands.add_parser(
        "doctor",
        help="Check the local environment WebGuard needs to run.",
    )
    doctor.add_argument(
        "--directory",
        type=Path,
        default=Path("."),
        help=(
            "Directory to check for write access and free space "
            "(default: current directory)."
        ),
    )
    doctor.set_defaults(handler=_doctor_command)

    authorization = commands.add_parser(
        "authorization",
        help="Create, validate, or inspect owned-target authorizations.",
    )
    authorization_commands = authorization.add_subparsers(
        dest="authorization_command",
        required=True,
    )

    authorization_create = authorization_commands.add_parser(
        "create",
        help="Create a bounded passive owned-target authorization.",
    )
    authorization_create.add_argument(
        "target",
        help="Canonical HTTPS URL owned and authorised by the organization.",
    )
    authorization_create.add_argument(
        "--organization",
        required=True,
        help="Legal or operating organization that owns the target.",
    )
    authorization_create.add_argument(
        "--authorized-by",
        required=True,
        help="Named person approving the owned-target assessment.",
    )
    authorization_create.add_argument(
        "--purpose",
        required=True,
        help="Bounded business purpose for this passive assessment.",
    )
    authorization_create.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Destination for the canonical authorization JSON document.",
    )
    authorization_create.add_argument(
        "--authorization-id",
        default=None,
        metavar="UUID",
        help="Optional preassigned canonical UUID. A UUID is generated otherwise.",
    )
    authorization_create.add_argument(
        "--allow-host",
        action="append",
        dest="authorization_allowed_hosts",
        default=[],
        metavar="HOST",
        help=(
            "Additional explicitly owned hostname recorded in the authorization. "
            "May be repeated; the canonical target host is always included."
        ),
    )
    authorization_create.add_argument(
        "--valid-days",
        dest="authorization_validity_days",
        type=int,
        default=DEFAULT_OWNED_AUTHORIZATION_VALIDITY_DAYS,
        metavar="DAYS",
        help="Authorization validity in days (default: 30; maximum: 366).",
    )
    authorization_create.add_argument(
        "--max-pages",
        dest="authorization_maximum_pages",
        type=int,
        default=OWNED_DEFAULT_CRAWL_PAGES,
    )
    authorization_create.add_argument(
        "--max-depth",
        dest="authorization_maximum_depth",
        type=int,
        default=OWNED_DEFAULT_CRAWL_DEPTH,
    )
    authorization_create.add_argument(
        "--max-links",
        dest="authorization_maximum_links_per_page",
        type=int,
        default=OWNED_DEFAULT_CRAWL_LINKS_PER_PAGE,
    )
    authorization_create.add_argument(
        "--minimum-delay",
        dest="authorization_minimum_delay_seconds",
        type=float,
        default=OWNED_DEFAULT_CRAWL_DELAY_SECONDS,
    )
    authorization_create.add_argument(
        "--max-execution-seconds",
        dest="authorization_maximum_execution_seconds",
        type=float,
        default=OWNED_DEFAULT_CRAWL_EXECUTION_SECONDS,
    )
    authorization_create.add_argument(
        "--max-request-attempts",
        dest="authorization_maximum_request_attempts",
        type=int,
        default=OWNED_DEFAULT_CRAWL_REQUEST_ATTEMPTS,
    )
    authorization_create.add_argument(
        "--max-attempts-per-request",
        dest="authorization_maximum_attempts_per_request",
        type=int,
        default=1,
    )
    authorization_create.add_argument(
        "--timeout",
        dest="authorization_timeout_seconds",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    authorization_create.add_argument(
        "--max-body-bytes",
        dest="authorization_maximum_body_bytes",
        type=int,
        default=DEFAULT_MAXIMUM_BODY_BYTES,
    )
    authorization_create.add_argument(
        "--max-header-bytes",
        dest="authorization_maximum_header_bytes",
        type=int,
        default=DEFAULT_MAXIMUM_HEADER_BYTES,
    )
    authorization_create.add_argument(
        "--max-header-count",
        dest="authorization_maximum_header_count",
        type=int,
        default=DEFAULT_MAXIMUM_HEADER_COUNT,
    )
    authorization_create.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly replace an existing regular authorization file.",
    )
    authorization_create.set_defaults(
        handler=_authorization_create_command
    )

    authorization_validate = authorization_commands.add_parser(
        "validate",
        help="Strictly validate an owned-target authorization document.",
    )
    authorization_validate.add_argument("authorization", type=Path)
    authorization_validate.set_defaults(
        handler=_authorization_validate_command
    )

    authorization_inspect = authorization_commands.add_parser(
        "inspect",
        help="Display a validated owned-target authorization.",
    )
    authorization_inspect.add_argument("authorization", type=Path)
    authorization_inspect.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print canonical authorization JSON.",
    )
    authorization_inspect.set_defaults(
        handler=_authorization_inspect_command
    )

    report = commands.add_parser(
        "report",
        help="Validate, inspect, render, or compare scan reports.",
    )
    report_commands = report.add_subparsers(
        dest="report_command",
        required=True,
    )

    validate = report_commands.add_parser(
        "validate",
        help="Strictly validate and normalize a scan report.",
    )
    validate.add_argument("report", type=Path)
    validate.set_defaults(handler=_report_validate_command)

    inspect = report_commands.add_parser(
        "inspect",
        help="Display a validated scan report.",
    )
    inspect.add_argument("report", type=Path)
    inspect.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print canonical normalized JSON instead of a human summary.",
    )
    inspect.set_defaults(handler=_report_inspect_command)

    render = report_commands.add_parser(
        "render",
        help="Render a self-contained professional HTML report.",
    )
    render.add_argument("report", type=Path)
    render.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Destination HTML file.",
    )
    render.add_argument(
        "--organization",
        required=True,
        help="Customer or asset-owning organization displayed in the report.",
    )
    render.add_argument(
        "--title",
        default=DEFAULT_REPORT_TITLE,
        help="Customer-facing report title.",
    )
    render.add_argument(
        "--prepared-by",
        default="OpenHuntX",
        help="Report preparer displayed on the cover.",
    )
    render.add_argument(
        "--classification",
        default=DEFAULT_REPORT_CLASSIFICATION,
        help="Document classification displayed on the cover.",
    )
    render.add_argument(
        "--baseline",
        type=Path,
        default=None,
        help="Optional earlier compatible report for remediation verification.",
    )
    render.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly replace an existing regular HTML file.",
    )
    render.set_defaults(handler=_report_render_command)

    compare = report_commands.add_parser(
        "compare",
        help="Compare baseline and current findings by stable fingerprint.",
    )
    compare.add_argument("baseline", type=Path)
    compare.add_argument("current", type=Path)
    compare.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Destination canonical comparison JSON file.",
    )
    compare.add_argument(
        "--overwrite",
        action="store_true",
        help="Explicitly replace an existing regular comparison file.",
    )
    compare.set_defaults(handler=_report_compare_command)

    comparison_validate = report_commands.add_parser(
        "validate-comparison",
        help="Strictly validate a saved remediation comparison document.",
    )
    comparison_validate.add_argument("comparison", type=Path)
    comparison_validate.set_defaults(
        handler=_report_comparison_validate_command
    )

    results = commands.add_parser(
        "results",
        help="List or clean up locally stored scan result files.",
    )
    results_commands = results.add_subparsers(
        dest="results_command",
        required=True,
    )

    results_list = results_commands.add_parser(
        "list",
        help="List stored scan result files.",
    )
    results_list.add_argument(
        "--directory",
        type=Path,
        default=DEFAULT_OUTPUT_DIRECTORY,
        help="Directory to scan for result files (default: scan-results).",
    )
    results_list.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print machine-readable JSON instead of a human summary.",
    )
    results_list.set_defaults(handler=_results_list_command)

    results_clean = results_commands.add_parser(
        "clean",
        help="Delete stored scan result files.",
    )
    results_clean.add_argument(
        "--directory",
        type=Path,
        default=DEFAULT_OUTPUT_DIRECTORY,
        help="Directory to clean (default: scan-results).",
    )
    results_clean.add_argument(
        "--older-than-days",
        type=float,
        default=None,
        metavar="DAYS",
        help="Only delete files older than this many days.",
    )
    results_clean.add_argument(
        "--yes",
        action="store_true",
        help="Actually delete files. Without this flag, only a dry run is printed.",
    )
    results_clean.set_defaults(handler=_results_clean_command)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the WebGuard CLI and return a deterministic process status."""

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return int(args.handler(args))
    except CliControlledError as exc:
        print(
            f"webguard: [{exc.code}] {exc.message}",
            file=sys.stderr,
        )
        return exc.exit_code
    except KeyboardInterrupt:
        print("webguard: cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - last-resort fail-closed boundary
        print(
            f"webguard: [unexpected_error] {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return EXIT_UNEXPECTED_ERROR


__all__ = [
    "EXIT_DOCTOR_CHECK_FAILED",
    "EXIT_OUTPUT_FAILED",
    "EXIT_PREFLIGHT_FAILED",
    "EXIT_REPORT_INVALID",
    "EXIT_SCAN_FAILED",
    "EXIT_SUCCESS",
    "EXIT_UNEXPECTED_ERROR",
    "EXIT_USAGE",
    "build_parser",
    "main",
]
