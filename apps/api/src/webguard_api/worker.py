"""Lease-aware background worker for persistent WebGuard scan jobs.

P1-10 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md): a
transient PostgreSQL outage must never permanently kill this worker.
Three distinct places touch the database outside of the job-claim
happy path, and each needed its own resilience treatment against a
``DatabaseError`` (as opposed to a semantic ``JobStoreError`` like
``job_lease_lost``, which must keep failing immediately -- see
``_STALE_LEASE_CODES``):

1. Terminal-state persistence (``_finish_result``/``_fail``/``_cancel``)
   -- bounded retries (``_TERMINAL_PERSISTENCE_MAXIMUM_ATTEMPTS``,
   short backoff) via ``_persist_terminal_state``. If every retry is
   exhausted, the attempt is abandoned *without* raising and *without*
   pretending the write succeeded -- the job is left exactly where it
   durably already is (``RUNNING``, still leased) for the existing,
   already-proven ``recover_expired_leases()`` mechanism to reclaim
   once Postgres (and/or another worker) is available again. This is
   why ``run_once()`` no longer recursively calls ``_fail()`` after
   determining the store itself is unavailable -- that recursive
   attempt is exactly what previously escalated one outage into a
   dead worker thread.
2. The heartbeat/cancellation-check loop (``monitor_job``) -- a
   ``DatabaseError`` here no longer ends the thread; it skips that one
   cycle with a short backoff and keeps trying on its normal schedule.
   Genuine lease loss (``JobStoreError``) is unchanged: that still
   stops the monitor and cancels the in-flight scan, exactly as
   before. A prolonged outage does not need the monitor to declare the
   lease "uncertain" for correctness -- the durable
   ``lease_expires_at`` this worker already wrote at claim/last-renew
   time is what governs; if it lapses, ``recover_expired_leases()``
   reclaims the job to someone else, and this worker's own eventual
   terminal-persistence attempt is then correctly rejected by the
   existing revision/lease-token CAS (unchanged, see ``store.py``).
3. ``run_forever()``'s own loop boundary -- a ``DatabaseError`` from
   ``recover_expired_leases()``/``claim_next_leased()`` themselves
   (i.e. before any job is even claimed) no longer escapes the loop.
   It backs off (reusing ``poll_seconds``, responsive to
   ``stop_event`` so shutdown is never delayed) and the next iteration
   retries naturally -- no separate retry-of-retries logic needed
   here, since neither call holds any in-progress work that a retry
   could lose.

Nothing about lease ownership, lease-token/revision CAS, or
``FOR UPDATE SKIP LOCKED`` claim semantics changes -- see ``store.py``/
``postgres_jobs.py``, both untouched by this fix.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from webguard_scanner import CrawlCancellationToken

from .config import (
    DEFAULT_WORKER_HEARTBEAT_SECONDS,
    DEFAULT_WORKER_LEASE_SECONDS,
    DEFAULT_WORKER_MAXIMUM_ATTEMPTS,
)
from .db_errors import DatabaseError
from .executor import JobExecutionError, ScanJobExecutor
from .repository_contracts import JobRepository
from .structured_logging import exception_fields, log_event
from .store import (
    JobStoreError,
    LeaseRecoverySummary,
    LeasedScanJob,
)

_STALE_LEASE_CODES = {
    "job_lease_expired",
    "job_lease_lost",
    "job_lease_required",
}

# Terminal-persistence retry budget: small and bounded -- the point is
# "absorb a brief blip," not "consume the whole lease window retrying
# one write." This is NOT a guarantee that a retry sequence always
# finishes before the lease it's trying to close out could expire:
# terminal persistence can begin late in an already-running lease
# interval (e.g. right before a heartbeat was due), and each attempt
# can itself take up to WebGuardPostgresPool's own 5s connection-
# checkout timeout before raising, so under a long enough outage the
# lease genuinely can lapse mid-retry. That is safe by construction,
# not by timing: retries never weaken the lease-token/revision CAS
# (_terminal_update() is unchanged). If the lease lapses and another
# worker reclaims the job before this retry sequence finishes, this
# worker's eventual write is rejected exactly as any other stale
# attempt already is (job_lease_lost, or job_state_transition_invalid
# if the job has already reached a terminal state by then) -- so
# correctness holds even when retry duration overlaps lease expiry.
# The cost of that overlap is a possible duplicate execution (see
# DUPLICATE-EXECUTION RISK in docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md),
# never a corrupted or double-persisted result: the CAS still
# guarantees at most one terminal write survives.
DEFAULT_TERMINAL_PERSISTENCE_MAXIMUM_ATTEMPTS = 3
DEFAULT_TERMINAL_PERSISTENCE_RETRY_BACKOFF_SECONDS = 1.0

# Heartbeat-renewal retry backoff: how long the monitor thread waits
# before its next attempt after a DatabaseError, distinct from (and
# shorter than) the full heartbeat_seconds interval a *successful*
# renewal schedules -- so a transient blip is retried promptly, not
# just on the next full heartbeat cycle, while still never busy-looping
# (bounded below by this constant, not by the 10ms floor the normal
# wait_seconds calculation would otherwise clamp to once next_heartbeat
# is in the past).
DEFAULT_HEARTBEAT_RETRY_BACKOFF_SECONDS = 1.0

# P1-B2: progress-staleness bound for health/readiness (see
# ScanJobWorker.progress_stale_after_seconds's own docstring for the
# derivation). Overridable per-instance via
# progress_healthy(stale_after_seconds=...); the CLI's health-server
# wiring additionally allows an operator override via
# WEBGUARD_WORKER_HEALTH_STALE_SECONDS (see cli.py).
DEFAULT_PROGRESS_STALE_MULTIPLIER = 6.0
DEFAULT_PROGRESS_STALE_FLOOR_SECONDS = 3.0
# P1-B2 pre-commit correction: a real-outage re-measurement caught a
# genuine bug in the derivation above -- during a REAL Postgres outage
# (not the fake/instant DatabaseError injection the original unit
# evidence used), run_forever()'s own DatabaseError branch is only
# reached AFTER run_once()'s own first DB call (recover_expired_leases())
# actually times out, which -- per this batch's explicit instruction
# not to change worker job DB operations -- is still bound by the
# *ordinary* WebGuardPostgresPool connection-checkout timeout (5.0s,
# postgres_pool.DEFAULT_CONNECTION_TIMEOUT_SECONDS), not poll_seconds.
# The true worst-case gap between two legitimate progress touches
# during a real outage is therefore one blocked ordinary DB call plus
# one poll_seconds backoff wait, not poll_seconds alone -- the
# multiplier-only formula above was measured against a fake outage
# that skipped this blocking call entirely, so it understated the real
# gap. This constant duplicates (does not import, to keep this module
# storage-agnostic -- SQLite-backed tests never see this path at all)
# postgres_pool.py's own 5.0s default; a generous margin above it
# keeps a real, correctly-surviving outage from ever spuriously
# reporting stale/wedged.
DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS = 7.0


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _default_worker_id() -> str:
    hostname = socket.gethostname().strip() or "localhost"
    safe_hostname = "".join(
        character if 33 <= ord(character) <= 126 else "-"
        for character in hostname
    )[:64]
    return f"{safe_hostname}:{os.getpid()}:{uuid4().hex[:12]}"


class ScanJobWorker:
    """Claim, heartbeat, execute, and safely recover leased scan jobs."""

    def __init__(
        self,
        *,
        store: JobRepository,
        executor: ScanJobExecutor,
        poll_seconds: float = 0.25,
        worker_id: str | None = None,
        lease_seconds: float = DEFAULT_WORKER_LEASE_SECONDS,
        heartbeat_seconds: float = DEFAULT_WORKER_HEARTBEAT_SECONDS,
        maximum_attempts: int = DEFAULT_WORKER_MAXIMUM_ATTEMPTS,
        clock: Callable[[], datetime] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        terminal_persistence_maximum_attempts: int = DEFAULT_TERMINAL_PERSISTENCE_MAXIMUM_ATTEMPTS,
        terminal_persistence_retry_backoff_seconds: float = DEFAULT_TERMINAL_PERSISTENCE_RETRY_BACKOFF_SECONDS,
        heartbeat_retry_backoff_seconds: float = DEFAULT_HEARTBEAT_RETRY_BACKOFF_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.store = store
        self.executor = executor
        self.poll_seconds = float(poll_seconds)
        self.worker_id = _default_worker_id() if worker_id is None else worker_id
        self.lease_seconds = float(lease_seconds)
        self.heartbeat_seconds = float(heartbeat_seconds)
        self.maximum_attempts = maximum_attempts
        self.clock = clock
        self.monotonic = monotonic
        self.terminal_persistence_maximum_attempts = int(terminal_persistence_maximum_attempts)
        self.terminal_persistence_retry_backoff_seconds = float(terminal_persistence_retry_backoff_seconds)
        self.heartbeat_retry_backoff_seconds = float(heartbeat_retry_backoff_seconds)
        self._sleep = sleep
        self.last_recovery_summary = LeaseRecoverySummary()
        # Phase 6 C-7: last_loop_error_type/_at are a simple, always-on
        # record of the last exception run_forever()'s own boundary had
        # to absorb to keep the loop alive -- set for *any* such
        # exception, not just DatabaseError, unlike the edge-triggered
        # P1-B1 outage state below, which is Postgres-outage-specific.
        self.last_loop_error_type: str | None = None
        self.last_loop_error_at: datetime | None = None
        # P1-B1: edge-trigger state for database_outage_detected/
        # _recovered -- read and written only from run_forever()'s own
        # thread (the loop-boundary DatabaseError catch, and the
        # success path right after it), so no lock is needed. This is
        # deliberately scoped to that one boundary for this batch, not
        # also wired into monitor_job()'s own separate heartbeat-
        # DatabaseError handling (a lower-severity, already-resilient
        # path) -- see the P1-B1 report's WORKER EVENTS section.
        self._in_database_outage = False
        # P1-B2 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        # a single monotonic timestamp, touched from every code path
        # that proves this worker's own loop is still actually doing
        # something -- run_forever()'s own iterations (idle poll,
        # processed-a-job, and outage-backoff, all three) AND
        # monitor_job()'s per-cycle lease-heartbeat loop, which keeps
        # running for the entire duration of a long executor.execute()
        # call. That second source is what keeps a genuinely long scan
        # from ever looking stalled just because run_forever() hasn't
        # returned from run_once() yet -- see progress_healthy().
        self._last_progress_monotonic = self.monotonic()
        self._validate_configuration()

    def _touch_progress(self) -> None:
        self._last_progress_monotonic = self.monotonic()

    @property
    def progress_stale_after_seconds(self) -> float:
        """The bound `progress_healthy()` compares against. Not an
        arbitrary guess: every progress-touching code path (the
        idle/outage-backoff `stop_event.wait(self.poll_seconds)` calls
        in `run_forever()`, and `monitor_job()`'s own
        `min(self.poll_seconds, time-to-next-heartbeat)` wait) is
        bounded above by `self.poll_seconds` under healthy operation --
        `DEFAULT_PROGRESS_STALE_MULTIPLIER`/`_FLOOR_SECONDS` are sized
        from that relationship plus a jitter margin measured
        empirically in
        `tests/unit/test_worker_health.py::ProgressStalenessEvidenceTests`.
        But during a REAL outage, `run_once()`'s own first DB call can
        legitimately block for up to the pool's ordinary ~5s checkout
        timeout before `run_forever()`'s `except DatabaseError:` branch
        is even reached to touch progress at all -- a real-outage
        re-measurement caught this gap exceeding the healthy-path
        bound above, so `DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS`
        is also included as a floor, sized generously above that ~5s
        worst case (see this module's own comment on that constant)."""

        return max(
            self.poll_seconds * DEFAULT_PROGRESS_STALE_MULTIPLIER,
            DEFAULT_PROGRESS_STALE_FLOOR_SECONDS,
            DEFAULT_PROGRESS_STALE_DB_OUTAGE_FLOOR_SECONDS,
        )

    def progress_healthy(self, *, stale_after_seconds: float | None = None) -> bool:
        """Pure, local, non-raising: compares two floats. No knowledge
        of Postgres/job-store dependency health belongs here -- that is
        a separate, explicit check composed at the CLI/health-server
        wiring layer (see cli.py), never conflated with "is the loop
        itself still turning." A worker can be `progress_healthy()`
        while `_in_database_outage` is True (the loop is correctly
        backing off and retrying) -- that combination is exactly what
        makes `/healthz` (liveness) stay green through a database
        outage the worker itself already survives, while `/ready`
        (readiness, which also checks the dependency) correctly goes
        unhealthy."""

        threshold = self.progress_stale_after_seconds if stale_after_seconds is None else stale_after_seconds
        return (self.monotonic() - self._last_progress_monotonic) <= threshold

    def _validate_configuration(self) -> None:
        if not 0.01 <= self.poll_seconds <= 5.0:
            raise ValueError("poll_seconds must be from 0.01 to 5 seconds.")
        # Reuse store validation so worker and persistence rules remain aligned.
        self.store._worker_id(self.worker_id)
        self.store._lease_seconds(self.lease_seconds)
        self.store._maximum_attempts(self.maximum_attempts)
        if not 0.05 <= self.heartbeat_seconds < self.lease_seconds:
            raise ValueError(
                "heartbeat_seconds must be at least 0.05 and less than lease_seconds."
            )
        if self.terminal_persistence_maximum_attempts < 1:
            raise ValueError("terminal_persistence_maximum_attempts must be at least 1.")
        if self.terminal_persistence_retry_backoff_seconds < 0:
            raise ValueError("terminal_persistence_retry_backoff_seconds must not be negative.")
        if self.heartbeat_retry_backoff_seconds < 0:
            raise ValueError("heartbeat_retry_backoff_seconds must not be negative.")

    @staticmethod
    def _is_stale_lease_error(error: JobStoreError) -> bool:
        return error.code in _STALE_LEASE_CODES

    def _persist_terminal_state(self, operation: Callable[[], None]) -> bool:
        """Runs one terminal-persistence write (finish/fail/cancel),
        retrying only genuine infrastructure failures (``DatabaseError``)
        with a short bounded backoff -- never a semantic ``JobStoreError``
        (``job_lease_lost`` and friends propagate immediately, unchanged,
        so the caller's existing stale-lease handling keeps working
        exactly as before). Returns ``True`` if the write succeeded,
        ``False`` if every retry was exhausted while the database
        remained unavailable -- the caller must treat ``False`` as
        "abandon this attempt," never as success or as a reason to
        raise or to try a *different* terminal write instead (that
        recursive pattern -- fail write fails, so try _fail() again --
        is exactly what previously turned one outage into a dead
        worker thread)."""

        for attempt in range(1, self.terminal_persistence_maximum_attempts + 1):
            try:
                operation()
                return True
            except DatabaseError:
                if attempt >= self.terminal_persistence_maximum_attempts:
                    log_event(service="worker",
                        event="terminal_persistence_exhausted", level="error",
                        worker_id=self.worker_id, attempt=attempt,
                        reason_code="terminal_persistence_unavailable",
                    )
                    return False
                log_event(service="worker",
                    event="terminal_persistence_retry", level="warning",
                    worker_id=self.worker_id, attempt=attempt,
                )
                self._sleep(self.terminal_persistence_retry_backoff_seconds)
        return False

    def _finish_result(self, lease: LeasedScanJob, outcome) -> bool:
        return self._persist_terminal_state(
            lambda: self.store.finish_result_leased(
                lease.record.job_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                scan_id=outcome.report.scan_id,
                result_status=outcome.report.status,
                report_ref=outcome.report_ref,
                audit_ref=outcome.audit_ref,
                now=self.clock(),
                safety_receipt_ref=outcome.safety_receipt_ref,
                safety_receipt_sha256=outcome.safety_receipt_sha256,
            )
        )

    def _fail(
        self,
        lease: LeasedScanJob,
        *,
        code: str,
        message: str,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> bool:
        return self._persist_terminal_state(
            lambda: self.store.fail_leased(
                lease.record.job_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                error_code=code,
                error_message=message,
                now=self.clock(),
                safety_receipt_ref=safety_receipt_ref,
                safety_receipt_sha256=safety_receipt_sha256,
            )
        )

    def _cancel(self, lease: LeasedScanJob) -> bool:
        return self._persist_terminal_state(
            lambda: self.store.cancel_running_leased(
                lease.record.job_id,
                worker_id=lease.worker_id,
                lease_token=lease.lease_token,
                now=self.clock(),
            )
        )

    def run_once(self) -> bool:
        self.last_recovery_summary = self.store.recover_expired_leases(
            now=self.clock(),
            maximum_attempts=self.maximum_attempts,
        )
        lease = self.store.claim_next_leased(
            now=self.clock(),
            worker_id=self.worker_id,
            lease_seconds=self.lease_seconds,
        )
        if lease is None:
            return False

        record = lease.record
        log_event(service="worker", event="job_claimed", level="info", worker_id=self.worker_id, job_id=record.job_id)
        token = CrawlCancellationToken()
        monitor_stop = threading.Event()
        lease_lost = threading.Event()
        next_heartbeat = self.monotonic() + self.heartbeat_seconds

        def monitor_job() -> None:
            nonlocal next_heartbeat
            while not monitor_stop.is_set():
                wait_seconds = min(
                    self.poll_seconds,
                    max(0.01, next_heartbeat - self.monotonic()),
                )
                if monitor_stop.wait(wait_seconds):
                    return
                # P1-B2: this cycle running at all -- independent of
                # whether the cancellation-check/heartbeat-renewal
                # inside it succeeds -- is the liveness signal for a
                # long-running job: it proves the monitor thread is
                # still cycling on schedule throughout the entire
                # duration of executor.execute() below, which is
                # exactly what keeps a genuinely long scan from ever
                # looking like a wedged run_forever() loop.
                self._touch_progress()
                try:
                    if self.store.is_cancellation_requested(record.job_id):
                        token.cancel()
                    if self.monotonic() >= next_heartbeat:
                        self.store.renew_lease(
                            record.job_id,
                            worker_id=lease.worker_id,
                            lease_token=lease.lease_token,
                            now=self.clock(),
                            lease_seconds=self.lease_seconds,
                        )
                        next_heartbeat = self.monotonic() + self.heartbeat_seconds
                except JobStoreError:
                    # Genuine, semantic lease loss (another worker
                    # already reclaimed this job, or it's otherwise no
                    # longer this worker's to renew) -- unchanged: stop
                    # monitoring and cancel the in-flight scan.
                    lease_lost.set()
                    token.cancel()
                    return
                except DatabaseError:
                    # Infrastructure hiccup, not lease loss -- P1-10:
                    # this must not end the thread. Skip this cycle,
                    # retry sooner than a full heartbeat interval (but
                    # never immediately -- avoids busy-looping while
                    # Postgres is down), and keep monitoring. The
                    # durable lease_expires_at this worker already
                    # wrote still governs correctness even if renewal
                    # keeps failing: if it lapses, recover_expired_leases()
                    # elsewhere reclaims the job, and this worker's own
                    # eventual terminal-persistence attempt is then
                    # correctly rejected by the unchanged CAS.
                    next_heartbeat = self.monotonic() + self.heartbeat_retry_backoff_seconds

        monitor = threading.Thread(
            target=monitor_job,
            name=f"webguard-lease-{record.job_id[:8]}",
            daemon=True,
        )
        monitor.start()

        def stop_monitor() -> None:
            monitor_stop.set()
            monitor.join(timeout=1.0)

        try:
            if record.cancellation_requested:
                token.cancel()
            outcome = self.executor.execute(
                record,
                cancellation_token=token,
            )
            stop_monitor()
            if lease_lost.is_set():
                return True
            try:
                # A False return means every retry was exhausted while
                # Postgres remained unavailable (see
                # _persist_terminal_state) -- the completed result is
                # deliberately NOT reported as persisted, and nothing
                # else is attempted: the job stays RUNNING, exactly as
                # durably recorded, for existing lease-expiry recovery
                # to reclaim. This is not an error to raise or a
                # reason to fall through to _fail() -- the scan
                # genuinely succeeded; only recording that fact failed.
                if self._finish_result(lease, outcome):
                    log_event(service="worker",
                        event="job_completed", level="info",
                        worker_id=self.worker_id, job_id=record.job_id, scan_id=outcome.report.scan_id,
                    )
            except JobStoreError as exc:
                if not self._is_stale_lease_error(exc):
                    raise
        except JobExecutionError as exc:
            stop_monitor()
            if lease_lost.is_set():
                return True
            try:
                if token.is_cancelled or exc.code == "job_cancelled_before_execution":
                    self._cancel(lease)
                elif self._fail(
                    lease,
                    code=exc.code,
                    message=exc.message,
                    safety_receipt_ref=exc.safety_receipt_ref,
                    safety_receipt_sha256=exc.safety_receipt_sha256,
                ):
                    log_event(service="worker",
                        event="job_failed", level="warning",
                        worker_id=self.worker_id, job_id=record.job_id, error_code=exc.code,
                    )
            except JobStoreError as store_error:
                if not self._is_stale_lease_error(store_error):
                    raise
        except JobStoreError:
            stop_monitor()
            raise
        except Exception as exc:
            stop_monitor()
            if lease_lost.is_set():
                return True
            try:
                # Same rule as above: if this also cannot be persisted
                # because Postgres is unavailable, _fail() itself
                # returns False rather than raising -- there is no
                # second attempt, no recursive "try to record the
                # failure of recording the failure." The job is left
                # RUNNING for lease-expiry recovery, and this worker
                # moves on. This is the exact chain (executor raises ->
                # _fail() needs Postgres -> Postgres unavailable ->
                # _fail() itself throws -> worker dies) P1-10 closes.
                if self._fail(
                    lease,
                    code="worker_internal_error",
                    message=(
                        "The scanner worker encountered an unexpected internal error."
                    ),
                ):
                    log_event(service="worker",
                        event="job_failed", level="error",
                        worker_id=self.worker_id, job_id=record.job_id,
                        error_code="worker_internal_error", **exception_fields(exc),
                    )
            except JobStoreError as store_error:
                if not self._is_stale_lease_error(store_error):
                    raise
        finally:
            stop_monitor()
        return True

    def run_forever(self, stop_event: threading.Event) -> None:
        log_event(service="worker", event="worker_started", level="info", worker_id=self.worker_id)
        try:
            while not stop_event.is_set():
                try:
                    processed = self.run_once()
                except DatabaseError:
                    # P1-10: recover_expired_leases()/claim_next_leased()
                    # (run_once()'s own first two calls, before any job is
                    # even claimed) are deliberately left unwrapped inside
                    # run_once() itself -- neither holds any in-progress
                    # work a retry could lose, so there is nothing to gain
                    # from a separate retry-of-retries there. This boundary
                    # is the single place that absorbs a DatabaseError from
                    # either: back off (stop_event-responsive, so shutdown
                    # is never delayed by an outage) and let the next loop
                    # iteration retry naturally. Only DatabaseError is
                    # caught here, deliberately -- an unexpected programming
                    # error must keep its existing visibility, not be
                    # silently absorbed by an infrastructure-outage handler.
                    if not self._in_database_outage:
                        # P1-B1: edge-triggered -- exactly one event per
                        # outage episode, not one per poll cycle.
                        self._in_database_outage = True
                        log_event(service="worker",
                            event="database_outage_detected", level="error", worker_id=self.worker_id,
                        )
                    # P1-B2: touched even on the outage-backoff path --
                    # the loop backing off and retrying on schedule IS
                    # legitimate progress (this is exactly what keeps
                    # /healthz green through an outage the worker
                    # already survives, while /ready's separate
                    # dependency check correctly still fails).
                    self._touch_progress()
                    if stop_event.wait(self.poll_seconds):
                        return
                    continue
                except JobStoreError as exc:
                    # Phase 6 C-7: structurally unrelated to DatabaseError
                    # (ValueError, not RuntimeError), so the P1-10 handler
                    # above never catches this -- the SQLite-backed store's
                    # own equivalent of an unexpected operational failure
                    # (run_once()'s own bare `except JobStoreError: raise`
                    # re-propagates anything not already resolved into a
                    # blocked/failed outcome, e.g. a corrupted persisted
                    # row). Unlike a Postgres outage, retrying this exact
                    # row will not resolve it on its own, so this is
                    # logged and the loop keeps going rather than tracked
                    # as an edge-triggered outage episode.
                    self.last_loop_error_type = type(exc).__name__
                    self.last_loop_error_at = self.clock()
                    log_event(service="worker",
                        event="job_store_error", level="error",
                        worker_id=self.worker_id, **exception_fields(exc),
                    )
                    self._touch_progress()
                    if stop_event.wait(self.poll_seconds):
                        return
                    continue
                if self._in_database_outage:
                    self._in_database_outage = False
                    log_event(service="worker",
                        event="database_outage_recovered", level="info", worker_id=self.worker_id,
                    )
                self._touch_progress()
                if not processed:
                    stop_event.wait(self.poll_seconds)
        finally:
            log_event(service="worker", event="worker_stopped", level="info", worker_id=self.worker_id)


__all__ = [
    "DEFAULT_HEARTBEAT_RETRY_BACKOFF_SECONDS",
    "DEFAULT_TERMINAL_PERSISTENCE_MAXIMUM_ATTEMPTS",
    "DEFAULT_TERMINAL_PERSISTENCE_RETRY_BACKOFF_SECONDS",
    "DEFAULT_WORKER_HEARTBEAT_SECONDS",
    "DEFAULT_WORKER_LEASE_SECONDS",
    "DEFAULT_WORKER_MAXIMUM_ATTEMPTS",
    "ScanJobWorker",
]
