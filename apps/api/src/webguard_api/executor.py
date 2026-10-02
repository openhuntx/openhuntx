"""Safe owned-target scanner execution for queued service jobs."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, replace as dataclasses_replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit
from uuid import uuid4

from webguard_contracts import (
    OwnedTargetContractError,
    ScanJobMode,
    ScanJobRecord,
    ScanStatus,
    WebGuardReport,
    write_owned_target_audit_file,
)
from webguard_scanner import (
    ACTIVE_DETECTOR_REGISTRY,
    ActiveDetectionContext,
    ActiveDetectionError,
    ActiveDetectionPolicy,
    AttackSurfaceBudget,
    AuthenticatedCrawlStatus,
    AuthenticationHealthCriterion,
    AuthorizationResource,
    AuthorizationResourceGraph,
    AuthorizationResourcePair,
    CrawlCancellationToken,
    CrawlPolicy,
    DetectionCandidate,
    ENGINE_VERSION,
    FetchPolicy,
    IdentifierLocation,
    MAXIMUM_DISCOVERED_CANDIDATES,
    OWNED_DEFAULT_CRAWL_DELAY_SECONDS,
    OWNED_DEFAULT_CRAWL_DEPTH,
    OWNED_DEFAULT_CRAWL_EXECUTION_SECONDS,
    OWNED_DEFAULT_CRAWL_LINKS_PER_PAGE,
    OWNED_DEFAULT_CRAWL_PAGES,
    OWNED_DEFAULT_CRAWL_REQUEST_ATTEMPTS,
    ResourceOwnership,
    ResourceSource,
    RequestTemplate,
    RetryPolicy,
    ValidatedTarget,
    ValidationMode,
    ValidationPolicy,
    build_comparison_pairs,
    discover_page_attack_surface,
    discover_site_attack_surface,
    fetch_same_origin_page,
    run_authenticated_resource_discovery_crawl,
    run_idor_authorization_detector,
    run_ssrf_callback_detector,
    to_request_templates,
    validate_owned_target_preflight,
    validate_target_url,
    run_passive_crawl_scan,
    run_passive_header_scan,
)
from webguard_scanner.callback_broker import CallbackBrokerError, CallbackToken

from .artifact_store import ArtifactStore, ArtifactStoreError, LocalArtifactStore
from .authentication_contexts import (
    AuthenticationContextError,
    AuthenticationContextRepository,
)
from .authorization_comparison import (
    AuthorizationComparisonError,
    AuthorizationComparisonPlanRepository,
)
from .callback_service import CallbackRepository, CallbackServiceError
from .authorizations import AuthorizationRepository, AuthorizationRepositoryError
from .coverage_store import (
    CoverageStatus,
    InMemoryCoverageRepository,
    UNAUTHENTICATED_IDENTITY_LABEL,
    split_asset_and_path,
)
from .finding_store import InMemoryFindingRepository
from .permits import TrustScanPermitError, TrustScanSigner, validate_permit_use
from .safety import TrustScanRuntimeSafetyEngine, TrustScanRuntimeSafetyError
from .scan_store import InMemoryScanRepository
from .secret_provider import LocalSecretProvider, SecretProvider, SecretProviderError
from .repository_contracts import JobRepository, TenantScopedCallbackBroker
from .store import JobStoreError


# A fixed, conservative sub-budget for authenticated resource-discovery
# crawls (Slice 9) -- deliberately not operator-configurable this
# slice (see the phase 9 audit doc's "Known limitations"), and
# independent of both the main scan's own CrawlPolicy (if the job
# itself is a crawl) and the IDOR detector's own comparison-request
# budget (ActiveDetectionPolicy.maximum_probe_requests, unchanged from
# Slice 8). Every request issued under it still goes through the same
# before_request/after_request runtime-safety hooks as every other
# request this executor issues, so it still counts toward the overall
# TrustScan runtime safety engine's limits.
_DISCOVERY_CRAWL_POLICY = CrawlPolicy(
    maximum_pages=5,
    maximum_depth=1,
    maximum_request_attempts=20,
)

_ACTIVE_DETECTION_ELIGIBLE_STATUSES = frozenset(
    {ScanStatus.COMPLETED, ScanStatus.COMPLETED_WITH_ERRORS}
)


def _endpoint_of(candidate: DetectionCandidate | RequestTemplate) -> str:
    return candidate.url if isinstance(candidate, DetectionCandidate) else candidate.endpoint


def _discover_and_detect_page(
    target: ValidatedTarget,
    page_url: str,
    detectors: list[tuple[str, Callable]],
    context: ActiveDetectionContext,
    policy: ActiveDetectionPolicy,
    safety: TrustScanRuntimeSafetyEngine,
    cancellation_check: Callable[[], bool],
    restrict_to_page_path: str | None = None,
    extra_candidates: tuple[DetectionCandidate | RequestTemplate, ...] = (),
    allow_post: bool = False,
    allow_json: bool = False,
    authentication_material=None,
) -> list:
    if cancellation_check():
        return []

    response = fetch_same_origin_page(
        target,
        page_url,
        policy=policy,
        before_request=safety.before_request,
        after_request=safety.after_request,
        authentication_material=authentication_material,
    )
    if response is None:
        return []

    surface = discover_page_attack_surface(
        target, page_url, response.body, budget=AttackSurfaceBudget()
    )
    # allow_post/allow_json come from the binding TrustScan permit's own
    # allowed_http_methods claim (see _apply_active_detection) -- this is
    # the "explicit active authorization" that lets a
    # REQUIRES_EXPLICIT_ACTIVE_AUTHORIZATION POST-form/JSON candidate
    # become representable as a RequestTemplate at all. It is still not
    # itself a probe: every runtime safety check (budget, rate,
    # concurrency, cancellation, method authorization at the safe_http
    # layer) applies identically afterwards.
    candidates = to_request_templates(
        surface, allow_post=allow_post, allow_json=allow_json
    )
    if extra_candidates:
        seen = {(_endpoint_of(c), c.parameter) for c in candidates}
        merged = list(candidates)
        for candidate in extra_candidates:
            key = (_endpoint_of(candidate), candidate.parameter)
            if key in seen:
                continue
            seen.add(key)
            merged.append(candidate)
        candidates = tuple(merged)
    if restrict_to_page_path is not None:
        # A crawl page's findings must all belong to that page's own URL
        # (an existing, audited CrawlPageScanResult invariant). A
        # discovered form whose action targets a different page cannot be
        # attributed to this page slot, so only self-submitting forms
        # (search boxes and similar) are testable in crawl mode today.
        candidates = tuple(
            candidate
            for candidate in candidates
            if urlsplit(_endpoint_of(candidate)).path == restrict_to_page_path
        )
    if not candidates:
        return []
    candidates = candidates[: policy.maximum_probe_requests]

    findings = []
    for _check_id, runner in detectors:
        if cancellation_check():
            break
        try:
            result = runner(
                target,
                candidates,
                context,
                policy=policy,
                before_request=safety.before_request,
                after_request=safety.after_request,
                cancellation_check=cancellation_check,
                authentication_material=authentication_material,
            )
        except ActiveDetectionError:
            # A code-level active-detection guard (e.g. a candidate-budget
            # mismatch), not a security-relevant runtime safety decision.
            # The passive result already obtained must not be discarded
            # over this -- skip this detector for this page.
            continue
        findings.extend(result.findings)
    return findings


def _apply_active_detection(
    report: WebGuardReport,
    *,
    target: ValidatedTarget,
    active_checks: tuple[str, ...],
    scan_id: str,
    organization_id: str,
    authorization_id: str,
    permit_id: str,
    permit_fingerprint: str,
    authentication_context_id: str | None,
    authentication_contexts,
    secret_provider: SecretProvider,
    fetch_policy: FetchPolicy,
    safety: TrustScanRuntimeSafetyEngine,
    cancellation_token: CrawlCancellationToken,
) -> WebGuardReport:
    """Run authorized active detectors and merge findings into the report.

    Fails closed by construction: if ``active_checks`` is empty (the
    default for every permit that has not explicitly opted in), this
    returns ``report`` completely unchanged -- no discovery fetch, no
    probe, nothing observably different from passive-only execution.

    If ``authentication_context_id`` is set (Slice 7), the referenced
    context is re-validated here -- organization/target/authorization
    binding and ACTIVE status -- independently of the check already made
    at permit-issuance time (the same defense-in-depth pattern already
    used for permit validation itself: a context could be revoked after
    the permit was issued but before this scan actually runs). Secret
    material is resolved once per scan, held only in this function's
    local scope, and passed to the discovery/detector layer as an
    in-memory ``AuthenticationMaterial`` -- it is never assigned to
    anything returned from this function, logged, or included in
    ``report``.
    """

    if not active_checks:
        return report

    authentication_material = None
    if authentication_context_id is not None:
        try:
            context_record = authentication_contexts.require_bound(
                authentication_context_id,
                organization_id=organization_id,
                target=target.normalised_url,
                authorization_id=authorization_id,
                now=safety.clock(),
            )
            authentication_material = secret_provider.resolve(
                context_record.secret_reference_id or authentication_context_id
            )
        except (AuthenticationContextError, SecretProviderError) as exc:
            raise TrustScanRuntimeSafetyError(exc.code, exc.message) from exc

    detectors = [
        (check_id, ACTIVE_DETECTOR_REGISTRY[check_id])
        for check_id in active_checks
        if check_id in ACTIVE_DETECTOR_REGISTRY
    ]
    if not detectors:
        return report

    context = ActiveDetectionContext(
        scan_id=scan_id,
        authorization_id=authorization_id,
        permit_id=permit_id,
        permit_fingerprint=permit_fingerprint,
    )
    policy = ActiveDetectionPolicy(
        fetch_policy=fetch_policy,
        maximum_probe_requests=MAXIMUM_DISCOVERED_CANDIDATES,
    )
    # The permit's own allowed_http_methods claim is the "explicit active
    # authorization" gating POST/JSON candidate representability (see
    # to_request_templates). This does not itself authorize a probe --
    # safe_http.fetch_once and the runtime safety engine independently
    # re-check the method against this exact same claim before any
    # request is sent.
    allow_post = "POST" in fetch_policy.allowed_methods
    allow_json = allow_post

    def cancellation_check() -> bool:
        return cancellation_token.is_cancelled

    if hasattr(report, "pages"):
        changed = False
        updated_pages = []
        for page in report.pages:
            if (
                cancellation_check()
                or page.status not in _ACTIVE_DETECTION_ELIGIBLE_STATUSES
            ):
                updated_pages.append(page)
                continue
            active_findings = _discover_and_detect_page(
                target,
                page.url,
                detectors,
                context,
                policy,
                safety,
                cancellation_check,
                restrict_to_page_path=urlsplit(page.url).path or "/",
                allow_post=allow_post,
                allow_json=allow_json,
                authentication_material=authentication_material,
            )
            if not active_findings:
                updated_pages.append(page)
                continue
            changed = True
            updated_pages.append(
                dataclasses_replace(
                    page,
                    findings=page.findings + tuple(active_findings),
                )
            )
        if not changed:
            return report
        return dataclasses_replace(report, pages=tuple(updated_pages))

    if (
        report.status not in _ACTIVE_DETECTION_ELIGIBLE_STATUSES
        or cancellation_check()
    ):
        return report

    # Site-level discovery (sitemap.xml, robots.txt, common OpenAPI paths)
    # only runs for single-page scans. Crawl-mode findings must be
    # attributable to one specific crawled page's own URL (see
    # restrict_to_page_path above); site-level candidates aren't tied to
    # any one page, so folding them into crawl mode would either violate
    # that invariant or require inventing an attribution rule this slice
    # does not define. Deferred, not silently dropped -- see the phase 5
    # audit doc.
    site_surface = discover_site_attack_surface(
        target,
        policy=policy,
        before_request=safety.before_request,
        after_request=safety.after_request,
        cancellation_check=cancellation_check,
    )
    site_candidates = to_request_templates(
        site_surface, allow_post=allow_post, allow_json=allow_json
    )

    active_findings = _discover_and_detect_page(
        target,
        target.normalised_url,
        detectors,
        context,
        policy,
        safety,
        cancellation_check,
        extra_candidates=site_candidates,
        allow_post=allow_post,
        allow_json=allow_json,
        authentication_material=authentication_material,
    )
    if not active_findings:
        return report
    return dataclasses_replace(
        report,
        findings=report.findings + tuple(active_findings),
    )


class JobExecutionError(ValueError):
    """Controlled service-side execution failure."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.safety_receipt_ref = safety_receipt_ref
        self.safety_receipt_sha256 = safety_receipt_sha256


@dataclass(frozen=True, slots=True)
class JobExecutionOutcome:
    """Result and safe relative artifact references from one worker run."""

    report: WebGuardReport
    report_ref: str
    audit_ref: str
    safety_receipt_ref: str | None = None
    safety_receipt_sha256: str | None = None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _record_coverage_for_report(
    coverage_repository,
    report,
    *,
    organization_id: str,
    scan_id: str,
    now: datetime,
) -> None:
    """Coverage Truth Map v1 population (coverage_store.py's own
    module docstring has the full scope rationale). Runs against
    whatever ScanCoverage/CrawlScanCoverage the executor already
    computed for this report; no new scanning, no new requests, just
    persisting a signal that already existed and was previously
    discarded once the report left scope.

    identity_label is always UNAUTHENTICATED_IDENTITY_LABEL here: this
    function only ever sees the base report single_scanner/
    crawl_scanner returned, before _apply_active_detection/
    _apply_authorization_comparison/_apply_ssrf_callback_detection
    layer their own findings on top. Those three detectors can run
    under a specific identity's authentication material, but
    NormalizedFinding/FindingIdentity carries no identity field to
    recover which one from the augmented report, so extending coverage
    population to them is left for later work, not guessed at here."""

    pages = getattr(report, "pages", None)
    operations = (
        ((report.target, report.status, report.coverage),)
        if pages is None
        else tuple((page.url, page.status, page.coverage) for page in pages)
    )

    for url, status, coverage in operations:
        asset, path = split_asset_and_path(url)
        unreachable = status is ScanStatus.FAILED
        executed_check_ids = frozenset(coverage.executed_checks)
        skipped_check_ids = {item.check_id for item in coverage.skipped_checks}
        for check_id in coverage.planned_checks:
            if check_id in executed_check_ids:
                check_status = CoverageStatus.COMPLETED
            elif check_id in skipped_check_ids:
                check_status = CoverageStatus.BLOCKED
            else:
                check_status = (
                    CoverageStatus.UNREACHABLE if unreachable else CoverageStatus.COMPLETED
                )
            coverage_repository.record_coverage(
                organization_id=organization_id,
                asset=asset,
                path=path,
                http_method="GET",
                identity_label=UNAUTHENTICATED_IDENTITY_LABEL,
                check_id=check_id,
                status=check_status,
                scanner_version=ENGINE_VERSION,
                now=now,
                scan_id=scan_id,
            )


def _prepare_private_directory(path: Path) -> None:
    # These messages are persisted as job.error_message, a tenant-visible
    # field (service.py's /result and /jobs/{id} responses): the path
    # interpolated below is the operator's own --artifacts directory,
    # expanded from wherever they passed it (executor.py's own
    # ScanJobExecutor.__init__ calls Path(artifact_directory).expanduser(),
    # so a "~/..." value here becomes the literal OS username), never
    # anything the requesting tenant supplied. Generic messages here keep
    # that server-side detail out of a tenant-facing surface while
    # keeping the same stable codes for every other caller to match on.
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise JobExecutionError(
            "artifact_directory_create_failed",
            "Unable to create the private artifact directory.",
        ) from exc
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise JobExecutionError(
            "artifact_directory_inspection_failed",
            "Unable to inspect the artifact directory.",
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise JobExecutionError(
            "artifact_directory_invalid",
            "Artifact directories must be real directories, not links.",
        )
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        raise JobExecutionError(
            "artifact_directory_permissions_failed",
            "Unable to apply owner-only artifact directory permissions.",
        ) from exc


def _write_signed_safety_receipt(receipt, path: Path) -> str:
    document = receipt.to_json() + "\n"
    try:
        exists = os.path.lexists(path)
    except OSError as exc:
        raise JobExecutionError(
            "artifact_path_inspection_failed",
            "Unable to inspect the safety-receipt artifact path.",
        ) from exc
    if exists:
        raise JobExecutionError(
            "artifact_path_exists",
            "A service job artifact path already exists.",
        )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            descriptor = None
            output.write(document)
            output.flush()
            os.fsync(output.fileno())
    except OSError as exc:
        raise JobExecutionError(
            "artifact_write_failed",
            "Unable to write the TrustScan safety receipt.",
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return receipt.fingerprint


_IDENTIFIER_LOCATION_MAP = {
    "path": IdentifierLocation.PATH,
    "query": IdentifierLocation.QUERY,
    "none": IdentifierLocation.NONE,
}
_RESOURCE_OWNERSHIP_MAP = {
    "private_to_owner": ResourceOwnership.PRIVATE_TO_OWNER,
    "shared": ResourceOwnership.SHARED,
    "public": ResourceOwnership.PUBLIC,
    "unknown": ResourceOwnership.UNKNOWN,
}


def _resource_pair_from_spec(spec, *, primary_identity: str, secondary_identity: str):
    identifier_location = _IDENTIFIER_LOCATION_MAP.get(
        spec.identifier_location, IdentifierLocation.NONE
    )
    expected_access = _RESOURCE_OWNERSHIP_MAP.get(
        spec.expected_access, ResourceOwnership.PRIVATE_TO_OWNER
    )
    # Every resource this orchestration path ever constructs is sourced
    # from an operator-supplied comparison-plan resource_scope entry --
    # EXPLICIT_TEST_RESOURCE is the only provenance value used here.
    # There is no code path anywhere in this module that generates,
    # enumerates, or guesses an identifier.
    primary_resource = AuthorizationResource(
        resource_type=spec.resource_type,
        endpoint=spec.primary_endpoint,
        method=spec.method,
        identifier_location=identifier_location,
        identifier_name=spec.identifier_name,
        identifier_value=spec.primary_endpoint.rsplit("/", 1)[-1],
        owning_test_identity=primary_identity,
        source=ResourceSource.EXPLICIT_TEST_RESOURCE,
        expected_access=expected_access,
    )
    secondary_resource = AuthorizationResource(
        resource_type=spec.resource_type,
        endpoint=spec.secondary_endpoint,
        method=spec.method,
        identifier_location=identifier_location,
        identifier_name=spec.identifier_name,
        identifier_value=spec.secondary_endpoint.rsplit("/", 1)[-1],
        owning_test_identity=secondary_identity,
        source=ResourceSource.EXPLICIT_TEST_RESOURCE,
        expected_access=expected_access,
    )
    return AuthorizationResourcePair(
        primary_resource=primary_resource, secondary_resource=secondary_resource
    )


def _apply_authorization_comparison(
    report: WebGuardReport,
    *,
    target: ValidatedTarget,
    active_checks: tuple[str, ...],
    scan_id: str,
    organization_id: str,
    authorization_id: str,
    permit_id: str,
    permit_fingerprint: str,
    comparison_plan_id: str | None,
    authorization_comparison_plans: AuthorizationComparisonPlanRepository,
    authentication_contexts: AuthenticationContextRepository,
    secret_provider: SecretProvider,
    fetch_policy: FetchPolicy,
    safety: TrustScanRuntimeSafetyEngine,
    cancellation_token: CrawlCancellationToken,
) -> WebGuardReport:
    """Run the authorization-differential (IDOR/BOLA) detector and merge
    findings into the report.

    Fails closed by construction: if ``active.authorization.idor`` is not
    in ``active_checks``, or ``comparison_plan_id`` is not set, this
    returns ``report`` completely unchanged. The permit's active_checks
    claim alone is not sufficient either -- see ``service.issue_permit``,
    which additionally requires the plan's own ``permitted_active_check``
    to already be present in ``active_checks`` before the permit can ever
    be issued with both set inconsistently.

    Single-page scans only this slice (see the phase 8 audit doc): a
    crawled page's findings must be attributable to that one page's own
    URL (the same invariant that already defers site-level attack-surface
    discovery in crawl mode), and this detector's resources are explicit,
    scan-wide endpoints, not tied to any one crawled page.
    """

    if "active.authorization.idor" not in active_checks or comparison_plan_id is None:
        return report

    if hasattr(report, "pages"):
        # Crawl mode: deferred, not silently dropped -- see the module
        # docstring above and the phase 8 audit doc's "Known limitations."
        return report

    if report.status not in _ACTIVE_DETECTION_ELIGIBLE_STATUSES:
        return report

    def cancellation_check() -> bool:
        return cancellation_token.is_cancelled

    if cancellation_check():
        return report

    try:
        plan = authorization_comparison_plans.require_bound(
            comparison_plan_id,
            organization_id=organization_id,
            target=target.normalised_url,
            authorization_id=authorization_id,
            now=safety.clock(),
        )
        primary_context_record = authentication_contexts.require_bound(
            plan.primary_context_id,
            organization_id=organization_id,
            target=target.normalised_url,
            authorization_id=authorization_id,
            now=safety.clock(),
        )
        secondary_context_record = authentication_contexts.require_bound(
            plan.secondary_context_id,
            organization_id=organization_id,
            target=target.normalised_url,
            authorization_id=authorization_id,
            now=safety.clock(),
        )
        primary_material = secret_provider.resolve(
            primary_context_record.secret_reference_id or plan.primary_context_id
        )
        secondary_material = secret_provider.resolve(
            secondary_context_record.secret_reference_id or plan.secondary_context_id
        )
        # Identity *labels* (never secret material) come from each
        # context's own metadata record -- the same non-sensitive label
        # an operator chose when registering that identity.
        primary_identity_label = primary_context_record.identity_label
        secondary_identity_label = secondary_context_record.identity_label
    except (AuthorizationComparisonError, AuthenticationContextError, SecretProviderError) as exc:
        raise TrustScanRuntimeSafetyError(exc.code, exc.message) from exc

    resource_pairs = list(
        _resource_pair_from_spec(
            spec,
            primary_identity=primary_identity_label,
            secondary_identity=secondary_identity_label,
        )
        for spec in plan.resource_scope
    )

    if plan.enable_discovery and not cancellation_check():
        graph = AuthorizationResourceGraph()
        for identity_label, material in (
            (primary_identity_label, primary_material),
            (secondary_identity_label, secondary_material),
        ):
            discovery = run_authenticated_resource_discovery_crawl(
                target,
                authentication_material=material,
                owning_identity=identity_label,
                crawl_policy=_DISCOVERY_CRAWL_POLICY,
                fetch_policy=fetch_policy,
                authentication_health_criterion=AuthenticationHealthCriterion(
                    login_page_marker=plan.discovery_login_page_marker or None,
                ),
                before_request=safety.before_request,
                after_request=safety.after_request,
            )
            if discovery.status is AuthenticatedCrawlStatus.SUCCEEDED:
                graph.add_resources(identity_label, discovery.resources)
            # A discovery-phase authentication failure for one identity
            # does not raise: it simply means that identity contributes
            # no discovered resources this run (fail closed on data, not
            # on the whole scan) -- an expired session must never be
            # silently treated as "this identity legitimately has no
            # resources."
        existing_pair_ids = {
            (p.primary_resource.resource_id, p.secondary_resource.resource_id)
            for p in resource_pairs
        }
        for pair in build_comparison_pairs(
            graph,
            primary_identity=primary_identity_label,
            secondary_identity=secondary_identity_label,
        ):
            pair_id = (
                pair.primary_resource.resource_id,
                pair.secondary_resource.resource_id,
            )
            if pair_id in existing_pair_ids:
                continue
            existing_pair_ids.add(pair_id)
            resource_pairs.append(pair)

    resource_pairs = tuple(resource_pairs)
    if not resource_pairs:
        return report

    context = ActiveDetectionContext(
        scan_id=scan_id,
        authorization_id=authorization_id,
        permit_id=permit_id,
        permit_fingerprint=permit_fingerprint,
    )
    policy = ActiveDetectionPolicy(
        fetch_policy=fetch_policy,
        maximum_probe_requests=max(MAXIMUM_DISCOVERED_CANDIDATES, len(resource_pairs) * 4),
    )

    try:
        result = run_idor_authorization_detector(
            target,
            resource_pairs,
            context,
            primary_identity_label=primary_identity_label,
            primary_material=primary_material,
            secondary_identity_label=secondary_identity_label,
            secondary_material=secondary_material,
            policy=policy,
            before_request=safety.before_request,
            after_request=safety.after_request,
            cancellation_check=cancellation_check,
        )
    except ActiveDetectionError:
        return report

    if not result.findings:
        return report
    return dataclasses_replace(
        report, findings=report.findings + tuple(result.findings)
    )


class _ScanScopedCallbackBroker:
    """Thin per-scan adapter satisfying the scanner's `CallbackBroker`
    protocol exactly (`register`/`wait_for_observation`, nothing more)
    -- binds this one scan's organization/target/authorization once,
    via closure, so the detector never needs to know tenancy exists.
    Translates the API-layer `CallbackServiceError` back into the
    scanner-layer `CallbackBrokerError` the detector already knows how
    to catch per-candidate, rather than letting a leaked API-layer
    exception type cross that boundary."""

    def __init__(
        self,
        repository: TenantScopedCallbackBroker,
        *,
        organization_id: str,
        target: str,
        authorization_id: str,
        job_id: str | None = None,
        permit_id: str | None = None,
    ) -> None:
        self._repository = repository
        self._organization_id = organization_id
        self._target = target
        self._authorization_id = authorization_id
        self._job_id = job_id
        self._permit_id = permit_id

    def register(self, *, scan_id: str, candidate_fingerprint: str) -> CallbackToken:
        try:
            return self._repository.register(
                scan_id=scan_id,
                candidate_fingerprint=candidate_fingerprint,
                organization_id=self._organization_id,
                target=self._target,
                authorization_id=self._authorization_id,
                job_id=self._job_id,
                permit_id=self._permit_id,
            )
        except CallbackServiceError as exc:
            raise CallbackBrokerError(exc.code, exc.message) from exc

    def wait_for_observation(self, token, *, policy, cancellation_check=None):
        try:
            return self._repository.wait_for_observation(
                token,
                organization_id=self._organization_id,
                policy=policy,
                cancellation_check=cancellation_check,
            )
        except CallbackServiceError as exc:
            raise CallbackBrokerError(exc.code, exc.message) from exc


def _apply_ssrf_callback_detection(
    report: WebGuardReport,
    *,
    target: ValidatedTarget,
    active_checks: tuple[str, ...],
    scan_id: str,
    organization_id: str,
    authorization_id: str,
    permit_id: str,
    permit_fingerprint: str,
    authentication_context_id: str | None,
    authentication_contexts: AuthenticationContextRepository,
    secret_provider: SecretProvider,
    callback_repository: TenantScopedCallbackBroker,
    fetch_policy: FetchPolicy,
    safety: TrustScanRuntimeSafetyEngine,
    cancellation_token: CrawlCancellationToken,
    job_id: str | None = None,
) -> WebGuardReport:
    """Run the SSRF-callback detector and merge findings into the
    report.

    Fails closed by construction: if ``active.ssrf.callback`` is not in
    ``active_checks``, this returns ``report`` completely unchanged --
    an XSS-only, SQLi-only, or IDOR-only permit never authorizes this
    detector, exactly as requirement 1 requires (there is no shared
    "any active check" gate here beyond the identical
    ``PERMIT_ISSUE_ACTIVE`` RBAC gate every active check already uses
    at issuance time).

    Single-page scans only this slice, mirroring the same, already-
    documented precedent as Slice 8/9's comparison-style detectors: a
    crawled page's findings must be attributable to that one page's own
    URL, and SSRF candidate discovery here is not yet threaded through
    crawl-mode's per-page restriction.
    """

    if "active.ssrf.callback" not in active_checks:
        return report

    if hasattr(report, "pages"):
        return report

    if report.status not in _ACTIVE_DETECTION_ELIGIBLE_STATUSES:
        return report

    def cancellation_check() -> bool:
        return cancellation_token.is_cancelled

    if cancellation_check():
        return report

    authentication_material = None
    if authentication_context_id is not None:
        try:
            context_record = authentication_contexts.require_bound(
                authentication_context_id,
                organization_id=organization_id,
                target=target.normalised_url,
                authorization_id=authorization_id,
                now=safety.clock(),
            )
            authentication_material = secret_provider.resolve(
                context_record.secret_reference_id or authentication_context_id
            )
        except (AuthenticationContextError, SecretProviderError) as exc:
            raise TrustScanRuntimeSafetyError(exc.code, exc.message) from exc

    response = fetch_same_origin_page(
        target,
        target.normalised_url,
        policy=ActiveDetectionPolicy(fetch_policy=fetch_policy),
        before_request=safety.before_request,
        after_request=safety.after_request,
        authentication_material=authentication_material,
    )
    if response is None:
        return report

    surface = discover_page_attack_surface(
        target, target.normalised_url, response.body, budget=AttackSurfaceBudget()
    )
    allow_post = "POST" in fetch_policy.allowed_methods
    allow_json = allow_post
    candidates = to_request_templates(
        surface, allow_post=allow_post, allow_json=allow_json
    )
    if not candidates:
        return report
    candidates = candidates[:MAXIMUM_DISCOVERED_CANDIDATES]

    context = ActiveDetectionContext(
        scan_id=scan_id,
        authorization_id=authorization_id,
        permit_id=permit_id,
        permit_fingerprint=permit_fingerprint,
    )
    policy = ActiveDetectionPolicy(
        fetch_policy=fetch_policy,
        maximum_probe_requests=MAXIMUM_DISCOVERED_CANDIDATES,
    )
    broker = _ScanScopedCallbackBroker(
        callback_repository,
        organization_id=organization_id,
        target=target.normalised_url,
        authorization_id=authorization_id,
        job_id=job_id,
        permit_id=permit_id,
    )

    try:
        result = run_ssrf_callback_detector(
            target,
            candidates,
            context,
            callback_broker=broker,
            policy=policy,
            callback_policy=callback_repository.policy,
            before_request=safety.before_request,
            after_request=safety.after_request,
            authentication_material=authentication_material,
            cancellation_check=cancellation_check,
        )
    except ActiveDetectionError:
        return report

    if not result.findings:
        return report
    return dataclasses_replace(
        report, findings=report.findings + tuple(result.findings)
    )


class ScanJobExecutor:
    """Execute one validated, server-authorized passive scanner job."""

    def __init__(
        self,
        *,
        authorizations: AuthorizationRepository,
        store: JobRepository,
        trustscan_signer: TrustScanSigner,
        artifact_directory: Path,
        clock: Callable[[], datetime] = _utc_now,
        single_scanner: Callable[..., WebGuardReport] = run_passive_header_scan,
        crawl_scanner: Callable[..., WebGuardReport] = run_passive_crawl_scan,
        organization_resolver: Callable[[str], str | None] | None = None,
        authorization_assignment_checker: (
            Callable[[str, str], bool] | None
        ) = None,
        authentication_contexts: AuthenticationContextRepository | None = None,
        authorization_comparison_plans: AuthorizationComparisonPlanRepository | None = None,
        callback_repository: TenantScopedCallbackBroker | None = None,
        scan_repository=None,
        finding_repository=None,
        coverage_repository=None,
        secret_provider: SecretProvider | None = None,
        artifact_store: ArtifactStore | None = None,
    ) -> None:
        self.authorizations = authorizations
        self.store = store
        self.trustscan_signer = trustscan_signer
        self.artifact_directory = Path(artifact_directory).expanduser()
        self.clock = clock
        self.single_scanner = single_scanner
        self.crawl_scanner = crawl_scanner
        self.organization_resolver = organization_resolver
        self.authorization_assignment_checker = (
            authorization_assignment_checker
        )
        # See WebGuardJobService's identical parameter for the rationale:
        # optional and defaulted so every pre-Slice-7 constructor call
        # site is unaffected; a caller that needs contexts registered via
        # the service to be usable by this executor must pass the same
        # repository instance to both.
        self.authentication_contexts = (
            authentication_contexts
            if authentication_contexts is not None
            else AuthenticationContextRepository()
        )
        # Same rationale, same pattern, Slice 8.
        self.authorization_comparison_plans = (
            authorization_comparison_plans
            if authorization_comparison_plans is not None
            else AuthorizationComparisonPlanRepository()
        )
        # Same rationale, Slice 10. A default, receiver-less repository
        # is a safe fallback: without a real callback receiver actually
        # running and pointed at it, every SSRF probe simply times out
        # and correctly reports NOT_VULNERABLE rather than crashing --
        # a caller that wants genuine SSRF confirmation must construct
        # a `CallbackHttpReceiver` against this same repository
        # instance and pass it here.
        self.callback_repository = (
            callback_repository
            if callback_repository is not None
            else CallbackRepository(base_url="http://127.0.0.1:0/")
        )
        # Slice 13: durable scan-record and finding persistence.
        # Optional and defaulted to an in-memory backend so every
        # pre-Slice-13 constructor call site is unaffected -- local/
        # unit/lab behavior is identical to before (findings are
        # tracked in-memory, same as authentication contexts/
        # comparison plans/callback registrations already were).
        # Production wiring passes `PostgresScanRepository`/
        # `PostgresFindingRepository` explicitly.
        self.scan_repository = (
            scan_repository if scan_repository is not None else InMemoryScanRepository()
        )
        self.finding_repository = (
            finding_repository if finding_repository is not None else InMemoryFindingRepository()
        )
        # Coverage Truth Map v1 (product vision pillar 5). Phase 4 (an
        # API/report surface) added InMemoryCoverageRepository, so this
        # now follows the identical optional/defaulted pattern
        # scan_repository/finding_repository already use, rather than
        # leaving coverage un-populated in local/lab mode: a caller
        # that never explicitly disabled coverage tracking now gets it
        # for free, the same way it already gets scan/finding tracking
        # for free. Production wiring still passes
        # PostgresCoverageRepository explicitly.
        self.coverage_repository = (
            coverage_repository if coverage_repository is not None else InMemoryCoverageRepository()
        )
        # Slice 14 requirement 1: secret resolution goes through one
        # provider-neutral interface, mirroring TrustScanSigner/
        # SigningProvider (signing.py). Defaulted to a local adapter
        # over whatever `authentication_contexts` repository this
        # executor holds -- unchanged local/dev/test/lab behavior when
        # that repository is the in-memory one (it has `get_secret`);
        # fails closed, not silently, if it is the PostgreSQL metadata-
        # only repository and no real provider was explicitly injected.
        self.secret_provider = (
            secret_provider
            if secret_provider is not None
            else LocalSecretProvider(self.authentication_contexts)
        )
        # Slice 17 requirement 7: the completed report's bytes are now
        # written through the same `ArtifactStore` abstraction
        # `service.py` already reads them back through, completing
        # Slice 14's own stated intent (`artifact_store.py`'s module
        # docstring named this executor's hand-rolled `_write_report`
        # as the exact behavior `LocalArtifactStore` was extracted
        # from, but never actually wired the two together until now).
        # Defaulted to a fresh `LocalArtifactStore` over this
        # executor's own `artifact_directory` -- functionally
        # equivalent to the pre-Slice-17 hand-rolled write (same
        # 0o600/0o700 permissions, same owner-only O_NOFOLLOW-guarded
        # write), so every pre-Slice-17 local/dev/test/lab call site
        # that does not pass this explicitly is unaffected. Production
        # wiring passes the same `ObjectStorageArtifactStore` instance
        # `WebGuardJobService` reads from, so a report a worker writes
        # is immediately, durably readable via the API.
        self.artifact_store = (
            artifact_store if artifact_store is not None else LocalArtifactStore(self.artifact_directory)
        )

    def _policies(self, authorization, permit, mode: ScanJobMode):
        limits = authorization.limits
        claims = permit.permit.claims
        fetch_policy = FetchPolicy(
            timeout_seconds=min(10.0, limits.timeout_seconds),
            maximum_body_bytes=min(1_048_576, limits.maximum_body_bytes),
            maximum_header_bytes=min(65_536, limits.maximum_header_bytes),
            maximum_header_count=min(100, limits.maximum_header_count),
            allowed_methods=frozenset(claims.allowed_http_methods),
        )
        retry_policy = RetryPolicy(maximum_attempts=1)
        if mode is ScanJobMode.SINGLE_PAGE:
            return fetch_policy, retry_policy, None
        crawl_policy = CrawlPolicy(
            maximum_pages=min(OWNED_DEFAULT_CRAWL_PAGES, limits.maximum_pages),
            maximum_depth=min(OWNED_DEFAULT_CRAWL_DEPTH, limits.maximum_depth),
            maximum_links_per_page=min(
                OWNED_DEFAULT_CRAWL_LINKS_PER_PAGE,
                limits.maximum_links_per_page,
            ),
            minimum_delay_seconds=max(
                OWNED_DEFAULT_CRAWL_DELAY_SECONDS,
                limits.minimum_delay_seconds,
                1.0 / claims.maximum_requests_per_second,
            ),
            maximum_execution_seconds=min(
                OWNED_DEFAULT_CRAWL_EXECUTION_SECONDS,
                limits.maximum_execution_seconds,
            ),
            maximum_request_attempts=min(
                OWNED_DEFAULT_CRAWL_REQUEST_ATTEMPTS,
                limits.maximum_request_attempts,
                claims.maximum_request_attempts,
            ),
        )
        return fetch_policy, retry_policy, crawl_policy

    def execute(
        self,
        record: ScanJobRecord,
        *,
        cancellation_token: CrawlCancellationToken | None = None,
    ) -> JobExecutionOutcome:
        if record.state.value != "running":
            raise JobExecutionError(
                "job_not_running",
                "Only a running job can be executed.",
            )
        if cancellation_token is not None and cancellation_token.is_cancelled:
            raise JobExecutionError(
                "job_cancelled_before_execution",
                "The job was cancelled before scanner execution.",
            )
        try:
            authorization = self.authorizations.get(record.request.authorization_id)
        except AuthorizationRepositoryError as exc:
            raise JobExecutionError(exc.code, exc.message) from exc
        if authorization.fingerprint != record.request.authorization_sha256:
            raise JobExecutionError(
                "authorization_changed_after_submission",
                "The server-side authorization changed after the job was submitted.",
            )
        if authorization.target != record.request.target:
            raise JobExecutionError(
                "authorization_target_mismatch",
                "The job target no longer matches the server-side authorization.",
            )
        scope = self.store.get_scope(record.job_id)
        if scope is None:
            raise JobExecutionError(
                "trustscan_job_scope_missing",
                "The service job does not contain organization scope metadata.",
            )
        if self.authorization_assignment_checker is not None:
            try:
                assignment_current = (
                    self.authorization_assignment_checker(
                        scope[0],
                        record.request.authorization_id,
                    )
                )
            except Exception as exc:
                raise JobExecutionError(
                    "authorization_assignment_check_failed",
                    (
                        "Unable to verify the organization "
                        "authorization assignment."
                    ),
                ) from exc

            if not assignment_current:
                raise JobExecutionError(
                    "authorization_not_assigned",
                    (
                        "The authorization is no longer assigned "
                        "to this organization."
                    ),
                )

        binding = self.store.get_job_permit_binding(record.job_id)
        if binding is None:
            raise JobExecutionError(
                "trustscan_permit_missing",
                "The service job is not bound to a TrustScan permit.",
            )
        try:
            permit = self.store.get_scan_permit_scoped(binding[0], scope[0])
        except JobStoreError as exc:
            raise JobExecutionError(exc.code, exc.message) from exc
        if permit.permit.fingerprint != binding[1]:
            raise JobExecutionError(
                "trustscan_permit_binding_changed",
                "The job TrustScan permit fingerprint does not match the persisted permit.",
            )
        try:
            validate_permit_use(
                permit,
                signer=self.trustscan_signer,
                organization_id=scope[0],
                authorization=authorization,
                target=record.request.target,
                mode=record.request.mode,
                now=self.clock(),
            )
        except TrustScanPermitError as exc:
            raise JobExecutionError(exc.code, exc.message) from exc

        try:
            target = validate_target_url(
                record.request.target,
                ValidationPolicy(mode=ValidationMode.COMMERCIAL),
            )
        except ValueError as exc:
            # scope_validator.py's own TargetValidationError messages
            # interpolate the specific address that failed classification
            # (e.g. "Commercial scans cannot target '10.1.2.3'."), which
            # is whatever the scanning host's own DNS resolver actually
            # returned for the tenant's authorized hostname, not anything
            # the tenant supplied directly. A tenant who controls that
            # hostname's DNS could read this job.error_message (a
            # tenant-visible field) as a one-address-per-job internal-
            # network oracle. The stable code above is enough for a
            # caller to act on; the resolved address itself is not
            # persisted here.
            raise JobExecutionError(
                getattr(exc, "code", "target_validation_failed"),
                "The target could not be validated for this scan.",
            ) from exc

        fetch_policy, retry_policy, crawl_policy = self._policies(
            authorization,
            permit,
            record.request.mode,
        )
        scan_id = str(uuid4())
        try:
            preflight = validate_owned_target_preflight(
                authorization,
                target,
                confirmation=authorization.authorization_id,
                scan_id=scan_id,
                fetch_policy=fetch_policy,
                retry_policy=retry_policy,
                crawl_policy=crawl_policy,
                now=self.clock(),
            )
        except ValueError as exc:
            raise JobExecutionError(
                getattr(exc, "code", "owned_target_preflight_failed"),
                str(exc),
            ) from exc

        if cancellation_token is not None and cancellation_token.is_cancelled:
            raise JobExecutionError(
                "job_cancelled_before_execution",
                "The job was cancelled before scanner execution.",
            )

        organization_id = (
            None
            if self.organization_resolver is None
            else self.organization_resolver(record.job_id)
        )
        # Slice 13 requirement 2: the durable scan record starts here,
        # the moment execution genuinely begins -- before any actual
        # scanner request is made -- so a scan that fails immediately
        # after this point still has a persisted RUNNING record rather
        # than appearing to have never started.
        if organization_id is not None:
            self.scan_repository.create_scan(
                organization_id=scope[0],
                job_id=record.job_id,
                target=record.request.target,
                authorization_id=record.request.authorization_id,
                mode=record.request.mode.value,
                scanner_version=ENGINE_VERSION,
                now=self.clock(),
                permit_id=permit.permit.claims.permit_id,
                permit_fingerprint=permit.permit.fingerprint,
                requested_checks=tuple(permit.permit.claims.active_checks),
                scan_id=scan_id,
            )
        # scan_id (above) is freshly generated on every call to execute(),
        # including a retry after lease recovery, unlike record.job_id,
        # which is fixed for the job's whole lifetime. Nesting under it
        # gives each execution attempt its own artifact directory: without
        # it, a job requeued after a crash, a restart, or lost lease
        # always failed on retry, because write_owned_target_audit_file
        # below runs with overwrite=False (deliberately, to never silently
        # replace an existing audit record) against the same fixed path
        # the first, interrupted attempt had already written.
        relative_directory = (
            Path("jobs") / record.job_id / scan_id
            if organization_id is None
            else Path("organizations") / organization_id / "jobs" / record.job_id / scan_id
        )
        report_ref = (relative_directory / "report.json").as_posix()
        audit_ref = (relative_directory / "authorization-audit.json").as_posix()
        safety_receipt_ref = (relative_directory / "trustscan-safety-receipt.json").as_posix()
        _prepare_private_directory(self.artifact_directory)
        job_directory = self.artifact_directory / relative_directory
        _prepare_private_directory(job_directory)
        audit_path = self.artifact_directory / audit_ref
        safety_receipt_path = self.artifact_directory / safety_receipt_ref

        try:
            write_owned_target_audit_file(
                preflight.audit_record,
                audit_path,
                overwrite=False,
            )
        except OwnedTargetContractError as exc:
            raise JobExecutionError(exc.code, exc.message) from exc

        def revalidate_runtime_permission() -> None:
            try:
                current_authorization = self.authorizations.get(
                    record.request.authorization_id
                )
            except AuthorizationRepositoryError as exc:
                raise TrustScanPermitError(exc.code, exc.message) from exc
            if current_authorization.fingerprint != authorization.fingerprint:
                raise TrustScanPermitError(
                    "authorization_changed_during_execution",
                    "The server-side authorization changed during scanner execution.",
                )
            if self.authorization_assignment_checker is not None:
                try:
                    assignment_current = (
                        self.authorization_assignment_checker(
                            scope[0],
                            record.request.authorization_id,
                        )
                    )
                except Exception as exc:
                    raise TrustScanPermitError(
                        "authorization_assignment_check_failed",
                        (
                            "Unable to verify the organization "
                            "authorization assignment."
                        ),
                    ) from exc

                if not assignment_current:
                    raise TrustScanPermitError(
                        "authorization_not_assigned",
                        (
                            "The authorization is no longer assigned "
                            "to this organization."
                        ),
                    )

            current_binding = self.store.get_job_permit_binding(record.job_id)
            if current_binding is None or current_binding != binding:
                raise TrustScanPermitError(
                    "trustscan_permit_binding_changed",
                    "The job TrustScan permit binding changed during execution.",
                )
            try:
                current_permit = self.store.get_scan_permit_scoped(
                    binding[0], scope[0]
                )
            except JobStoreError as exc:
                raise TrustScanPermitError(exc.code, exc.message) from exc
            if current_permit.permit.fingerprint != binding[1]:
                raise TrustScanPermitError(
                    "trustscan_permit_binding_changed",
                    "The persisted TrustScan permit changed during execution.",
                )
            validate_permit_use(
                current_permit,
                signer=self.trustscan_signer,
                organization_id=scope[0],
                authorization=current_authorization,
                target=record.request.target,
                mode=record.request.mode,
                now=self.clock(),
            )

        safety = TrustScanRuntimeSafetyEngine(
            permit=permit,
            signer=self.trustscan_signer,
            organization_id=scope[0],
            job_id=record.job_id,
            scan_id=scan_id,
            target=record.request.target,
            revalidate=revalidate_runtime_permission,
            clock=self.clock,
        )

        token = cancellation_token or CrawlCancellationToken()
        try:
            if crawl_policy is None:
                report = self.single_scanner(
                    target,
                    fetch_policy=fetch_policy,
                    retry_policy=retry_policy,
                    scan_id=scan_id,
                    before_request=safety.before_request,
                    after_request=safety.after_request,
                )
            else:
                report = self.crawl_scanner(
                    target,
                    crawl_policy=crawl_policy,
                    fetch_policy=fetch_policy,
                    retry_policy=retry_policy,
                    scan_id=scan_id,
                    cancellation_token=token,
                    before_request=safety.before_request,
                    after_request=safety.after_request,
                )
            report = _apply_active_detection(
                report,
                target=target,
                active_checks=permit.permit.claims.active_checks,
                scan_id=scan_id,
                organization_id=scope[0],
                authorization_id=record.request.authorization_id,
                permit_id=permit.permit.claims.permit_id,
                permit_fingerprint=permit.permit.fingerprint,
                authentication_context_id=permit.permit.claims.authentication_context_id,
                authentication_contexts=self.authentication_contexts,
                secret_provider=self.secret_provider,
                fetch_policy=fetch_policy,
                safety=safety,
                cancellation_token=token,
            )
            report = _apply_authorization_comparison(
                report,
                target=target,
                active_checks=permit.permit.claims.active_checks,
                scan_id=scan_id,
                organization_id=scope[0],
                authorization_id=record.request.authorization_id,
                permit_id=permit.permit.claims.permit_id,
                permit_fingerprint=permit.permit.fingerprint,
                comparison_plan_id=permit.permit.claims.authorization_comparison_plan_id,
                authorization_comparison_plans=self.authorization_comparison_plans,
                authentication_contexts=self.authentication_contexts,
                secret_provider=self.secret_provider,
                fetch_policy=fetch_policy,
                safety=safety,
                cancellation_token=token,
            )
            report = _apply_ssrf_callback_detection(
                report,
                target=target,
                active_checks=permit.permit.claims.active_checks,
                scan_id=scan_id,
                organization_id=scope[0],
                authorization_id=record.request.authorization_id,
                permit_id=permit.permit.claims.permit_id,
                permit_fingerprint=permit.permit.fingerprint,
                authentication_context_id=permit.permit.claims.authentication_context_id,
                authentication_contexts=self.authentication_contexts,
                secret_provider=self.secret_provider,
                callback_repository=self.callback_repository,
                fetch_policy=fetch_policy,
                safety=safety,
                cancellation_token=token,
                job_id=record.job_id,
            )
        except TrustScanRuntimeSafetyError as exc:
            receipt = safety.signed_receipt(termination_reason="safety_blocked")
            digest = _write_signed_safety_receipt(receipt, safety_receipt_path)
            raise JobExecutionError(
                exc.code,
                exc.message,
                safety_receipt_ref=safety_receipt_ref,
                safety_receipt_sha256=digest,
            ) from exc
        except Exception as exc:
            # An unexpected scanner bug can happen after before_request
            # already permitted real network traffic against the
            # authorised target. Without this, that traffic would leave
            # no signed safety receipt at all -- discards the original
            # exception's type and message, matching every other
            # controlled boundary in this module: only a stable code and
            # a generic message ever reach the job record.
            receipt = safety.signed_receipt(termination_reason="scanner_error")
            digest = _write_signed_safety_receipt(receipt, safety_receipt_path)
            raise JobExecutionError(
                "scan_execution_failed",
                "The scan could not be completed due to an unexpected error.",
                safety_receipt_ref=safety_receipt_ref,
                safety_receipt_sha256=digest,
            ) from exc

        receipt = safety.signed_receipt(termination_reason=report.status.value)
        try:
            self.artifact_store.put(report_ref, (report.to_json() + "\n").encode("utf-8"))
        except ArtifactStoreError as exc:
            raise JobExecutionError(exc.code, exc.message) from exc
        digest = _write_signed_safety_receipt(receipt, safety_receipt_path)

        if organization_id is not None:
            for finding in report.findings:
                cwe_id = next(
                    (i.value for i in finding.identifiers if i.namespace == "CWE"), None
                )
                owasp_category = next(
                    (i.value for i in finding.identifiers if i.namespace == "OWASP"), None
                )
                self.finding_repository.record_finding(
                    organization_id=scope[0],
                    scan_id=scan_id,
                    fingerprint=finding.identity.fingerprint,
                    check_id=finding.identity.rule_id,
                    scanner_version=ENGINE_VERSION,
                    title=finding.title,
                    severity=finding.severity.value,
                    confidence=finding.confidence.value,
                    asset=finding.identity.asset,
                    endpoint=finding.identity.path,
                    http_method=finding.identity.method,
                    now=self.clock(),
                    parameter=finding.identity.parameter,
                    cwe_id=cwe_id,
                    owasp_category=owasp_category,
                    evidence="; ".join(item.summary for item in finding.evidence) or None,
                    remediation=finding.remediation,
                    references=finding.references,
                )
            if self.coverage_repository is not None:
                _record_coverage_for_report(
                    self.coverage_repository,
                    report,
                    organization_id=scope[0],
                    scan_id=scan_id,
                    now=self.clock(),
                )
            self.scan_repository.complete_scan(
                scan_id,
                organization_id=scope[0],
                status=report.status.value,
                report_ref=report_ref,
                finding_count=len(report.findings),
                now=self.clock(),
            )

        return JobExecutionOutcome(
            report=report,
            report_ref=report_ref,
            audit_ref=audit_ref,
            safety_receipt_ref=safety_receipt_ref,
            safety_receipt_sha256=digest,
        )


__all__ = [
    "JobExecutionError",
    "JobExecutionOutcome",
    "ScanJobExecutor",
]
