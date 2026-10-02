"""Database-backed recurring scan-schedule coordinator."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .authorizations import AuthorizationRepository, AuthorizationRepositoryError
from .db_errors import DatabaseError
from .identity import IdentityStore, IdentityStoreError
from .permits import TrustScanPermitError, TrustScanSigner, validate_permit_use
from .store import JobStoreError, ScanJobStore
from .structured_logging import exception_fields, log_event

# P1-B2 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
# progress-staleness bound for health/readiness -- see
# ScanScheduleCoordinator.progress_stale_after_seconds's own docstring.
DEFAULT_PROGRESS_STALE_MULTIPLIER = 6.0
DEFAULT_PROGRESS_STALE_FLOOR_SECONDS = 3.0
# P1-B2 pre-commit correction: identical reasoning and value to
# worker.py's own constant of the same name -- a real-outage
# re-measurement caught that _run_forever()'s first DB call
# (list_due_schedules()) can legitimately block for up to the pool's
# ordinary ~5s checkout timeout before the except DatabaseError:
# branch is reached to touch progress at all, exceeding the
# healthy-path-only floor above. Duplicated rather than imported to
# keep this module storage-agnostic (SQLite-backed tests never
# exercise this path).
DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS = 7.0


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class ScheduleRunSummary:
    """One scheduler pass summary."""

    inspected: int = 0
    enqueued: int = 0
    blocked: int = 0
    raced: int = 0


class ScanScheduleCoordinator:
    """Materialise due recurring schedules into tenant-scoped scan jobs."""

    def __init__(
        self,
        *,
        store: ScanJobStore,
        authorizations: AuthorizationRepository,
        identity: IdentityStore,
        trustscan_signer: TrustScanSigner,
        poll_seconds: float = 1.0,
        batch_size: int = 100,
        clock: Callable[[], datetime] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.authorizations = authorizations
        self.identity = identity
        self.trustscan_signer = trustscan_signer
        self.poll_seconds = float(poll_seconds)
        self.batch_size = batch_size
        self.clock = clock
        self.monotonic = monotonic
        # Phase 6 C-7: see worker.py's identical attributes for why
        # these are kept alongside the P1-B1/B2 state below.
        self.last_loop_error_type: str | None = None
        self.last_loop_error_at: datetime | None = None
        if not 0.1 <= self.poll_seconds <= 60.0:
            raise ValueError("poll_seconds must be from 0.1 to 60 seconds.")
        if isinstance(self.batch_size, bool) or not isinstance(self.batch_size, int):
            raise ValueError("batch_size must be an integer.")
        if not 1 <= self.batch_size <= 1000:
            raise ValueError("batch_size must be from 1 to 1000.")
        # P1-B1: edge-trigger state for database_outage_detected/
        # _recovered -- touched only from run_forever()'s own thread.
        self._in_database_outage = False
        # P1-B2: touched at the top of every _run_forever() iteration
        # (processed, idle, or outage-backoff alike) -- see
        # progress_healthy().
        self._last_progress_monotonic = self.monotonic()

    def _touch_progress(self) -> None:
        self._last_progress_monotonic = self.monotonic()

    @property
    def progress_stale_after_seconds(self) -> float:
        return max(
            self.poll_seconds * DEFAULT_PROGRESS_STALE_MULTIPLIER,
            DEFAULT_PROGRESS_STALE_FLOOR_SECONDS,
            DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS,
        )

    def progress_healthy(self, *, stale_after_seconds: float | None = None) -> bool:
        """Pure, local, non-raising -- see ScanJobWorker.progress_healthy's
        own docstring for the same reasoning applied here: no
        dependency knowledge belongs in this method, only "is the loop
        itself still turning." Composed with a separate dependency
        check at the CLI/health-server wiring layer."""

        threshold = self.progress_stale_after_seconds if stale_after_seconds is None else stale_after_seconds
        return (self.monotonic() - self._last_progress_monotonic) <= threshold

    def _block(self, schedule, *, code: str, now: datetime) -> bool:
        blocked = (
            self.store.block_due_schedule(
                schedule.schedule_id,
                expected_revision=schedule.revision,
                error_code=code,
                now=now,
            )
            is not None
        )
        if blocked:
            log_event(service="scheduler",
                event="schedule_materialization_failed", level="warning",
                schedule_id=schedule.schedule_id, error_code=code,
            )
        return blocked

    def run_once(self) -> ScheduleRunSummary:
        now = self.clock()
        schedules = self.store.list_due_schedules(now=now, limit=self.batch_size)
        enqueued = blocked = raced = 0
        for schedule in schedules:
            # P1-B2 pre-commit correction: a single run_once() call
            # processing a large, legitimately slow batch (many due
            # schedules, each materialization attempt taking real
            # time) must not look progress-stale just because
            # _run_forever()'s own touch only happens after the whole
            # call returns -- this is the scheduler's equivalent of
            # worker.py's monitor_job() touching progress every
            # heartbeat cycle during one long job. Touched once per
            # schedule actually reached, regardless of which branch
            # below handles it -- never for a call that never returns
            # (list_due_schedules() above, or a single schedule's own
            # DB calls hanging) -- that must keep reading as stale.
            self._touch_progress()
            # Phase 6 C-6: identity.py's SQLite-backed authorization_is_
            # assigned wraps its own sqlite3.Error into IdentityStoreError
            # (structurally unrelated to DatabaseError, the Postgres-
            # backed identity store's own failure type) -- caught here so
            # one schedule's store failure blocks only that schedule,
            # never the whole batch.
            try:
                assigned = self.identity.authorization_is_assigned(
                    schedule.organization_id,
                    schedule.authorization_id,
                )
            except IdentityStoreError as exc:
                blocked += int(self._block(schedule, code=exc.code, now=now))
                continue
            if not assigned:
                blocked += int(
                    self._block(
                        schedule,
                        code="authorization_not_assigned",
                        now=now,
                    )
                )
                continue
            try:
                authorization = self.authorizations.get(schedule.authorization_id)
            except AuthorizationRepositoryError as exc:
                blocked += int(self._block(schedule, code=exc.code, now=now))
                continue
            if authorization.target != schedule.target:
                blocked += int(
                    self._block(
                        schedule,
                        code="authorization_target_mismatch",
                        now=now,
                    )
                )
                continue
            if not authorization.issued_at <= now < authorization.expires_at:
                blocked += int(
                    self._block(
                        schedule,
                        code="authorization_not_current",
                        now=now,
                    )
                )
                continue
            binding = self.store.get_schedule_permit_binding(schedule.schedule_id)
            if binding is None:
                blocked += int(
                    self._block(
                        schedule,
                        code="trustscan_permit_missing",
                        now=now,
                    )
                )
                continue
            try:
                permit = self.store.get_scan_permit_scoped(
                    binding[0], schedule.organization_id
                )
            except JobStoreError as exc:
                blocked += int(self._block(schedule, code=exc.code, now=now))
                continue
            if permit.permit.fingerprint != binding[1]:
                blocked += int(
                    self._block(
                        schedule,
                        code="trustscan_permit_binding_changed",
                        now=now,
                    )
                )
                continue
            try:
                validate_permit_use(
                    permit,
                    signer=self.trustscan_signer,
                    organization_id=schedule.organization_id,
                    authorization=authorization,
                    target=schedule.target,
                    mode=schedule.mode,
                    now=now,
                )
            except TrustScanPermitError as exc:
                blocked += int(self._block(schedule, code=exc.code, now=now))
                continue
            try:
                result = self.store.enqueue_due_schedule(
                    schedule.schedule_id,
                    expected_revision=schedule.revision,
                    authorization_sha256=authorization.fingerprint,
                    permit_id=permit.permit.claims.permit_id,
                    permit_sha256=permit.permit.fingerprint,
                    now=now,
                )
            except JobStoreError:
                raise
            if result is None:
                raced += 1
            else:
                enqueued += 1
                _, job_record = result
                log_event(service="scheduler",
                    event="schedule_materialized", level="info",
                    schedule_id=schedule.schedule_id, job_id=job_record.job_id,
                )
        return ScheduleRunSummary(
            inspected=len(schedules),
            enqueued=enqueued,
            blocked=blocked,
            raced=raced,
        )

    def run_forever(self, stop_event: threading.Event) -> None:
        log_event(service="scheduler", event="scheduler_started", level="info")
        try:
            self._run_forever(stop_event)
        finally:
            log_event(service="scheduler", event="scheduler_stopped", level="info")

    def _run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.run_once()
            except DatabaseError:
                # P1-11 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
                # analogous in shape to worker.py's P1-10 run_forever()
                # boundary, but justified independently -- scheduler
                # semantics differ enough that the same shape had to be
                # proven safe here on its own terms, not assumed from
                # the worker precedent.
                #
                # run_once() can raise DatabaseError from list_due_schedules()
                # (a plain read, nothing to lose) or from enqueue_due_schedule()
                # partway through a batch (a write). enqueue_due_schedule()
                # was empirically proven atomic under a mid-method connection
                # failure -- a fault injected between its scan_jobs INSERT
                # and its scan_schedules UPDATE, and one injected after the
                # UPDATE but before the connection block's implicit commit,
                # both left neither a job row nor a revision/next_run_at
                # advance behind (see the P1-11 investigation report). So
                # there is no partial per-schedule state a retry could
                # observe or duplicate: every schedule this batch either
                # fully materialized (job created + revision advanced,
                # durably) before the failure, or is untouched and will be
                # picked up again -- as the same still-due row -- on a
                # later run_once() call. Unlike worker.py's terminal-state
                # writes, there is nothing here that must eventually
                # persist regardless of retries, so no nested bounded-
                # retry-with-backoff helper is needed for the write itself;
                # the outer poll loop already re-drives the whole batch.
                #
                # Only DatabaseError is caught here, deliberately: a
                # semantic JobStoreError (schedule_enqueue_conflict, a
                # trustscan binding change, etc.) must keep propagating
                # unchanged, and an unexpected programming error must keep
                # its existing visibility rather than being silently
                # absorbed by an infrastructure-outage handler. The
                # revision CAS and idempotency-key protections are
                # untouched by this change, so a retried batch cannot
                # duplicate an occurrence beyond what those already allow.
                if not self._in_database_outage:
                    # P1-B1: edge-triggered -- one event per outage
                    # episode, not one per poll cycle.
                    self._in_database_outage = True
                    log_event(service="scheduler", event="database_outage_detected", level="error")
                # P1-B2: touched even on the outage-backoff path -- see
                # the identical worker.py reasoning: backing off and
                # retrying on schedule IS legitimate progress.
                self._touch_progress()
                if stop_event.wait(self.poll_seconds):
                    return
                continue
            except JobStoreError as exc:
                # Phase 6 C-7: structurally unrelated to DatabaseError
                # (ValueError, not RuntimeError), so the P1-11 handler
                # above never catches this. Unlike a transient Postgres
                # outage, a schedule_enqueue_conflict or similar semantic
                # JobStoreError deliberately keeps its own visibility
                # here rather than being folded into outage bookkeeping
                # -- but letting it kill this loop entirely would stop
                # recurring-schedule materialization for every tenant
                # until an operator notices and restarts the process, a
                # materially larger blast radius than one worker thread
                # dying (see this same file's own worker.py counterpart).
                # Logged and the loop continues rather than propagating.
                self.last_loop_error_type = type(exc).__name__
                self.last_loop_error_at = self.clock()
                log_event(service="scheduler",
                    event="job_store_error", level="error",
                    **exception_fields(exc),
                )
                self._touch_progress()
                if stop_event.wait(self.poll_seconds):
                    return
                continue
            if self._in_database_outage:
                self._in_database_outage = False
                log_event(service="scheduler", event="database_outage_recovered", level="info")
            self._touch_progress()
            stop_event.wait(self.poll_seconds)


__all__ = ["ScanScheduleCoordinator", "ScheduleRunSummary"]
