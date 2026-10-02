from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import (
    JobExecutionError,
    JobExecutionOutcome,
    JobStoreError,
    ScanJobStore,
    ScanJobWorker,
)
from webguard_contracts import ScanJobMode, ScanJobRequest, ScanJobState, ScanStatus

from tests.unit.service_test_support import AUTH_ID, NOW, TARGET, authorization, completed_report


class FakeExecutor:
    def __init__(self, outcome=None, error=None):
        self.outcome = outcome
        self.error = error
        self.calls = []

    def execute(self, record, *, cancellation_token):
        self.calls.append((record, cancellation_token))
        if self.error is not None:
            raise self.error
        return self.outcome


class ScanJobWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = ScanJobStore(self.root / "jobs.sqlite3")
        auth = authorization()
        self.request = ScanJobRequest(
            idempotency_key="internstack-worker",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_empty_queue_returns_false(self) -> None:
        worker = ScanJobWorker(
            store=self.store,
            executor=FakeExecutor(),
            clock=lambda: NOW,
        )
        self.assertFalse(worker.run_once())

    def test_completed_outcome_updates_store(self) -> None:
        record, _ = self.store.submit(self.request)
        report = completed_report("b6a39765-16c6-42b4-91f0-998bf07f1912")
        executor = FakeExecutor(
            JobExecutionOutcome(
                report=report,
                report_ref=f"jobs/{record.job_id}/report.json",
                audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
            )
        )
        worker = ScanJobWorker(
            store=self.store,
            executor=executor,
            clock=lambda: NOW,
        )
        self.assertTrue(worker.run_once())
        stored = self.store.get(record.job_id)
        self.assertIs(stored.state, ScanJobState.COMPLETED)
        self.assertEqual(stored.scan_id, report.scan_id)
        self.assertEqual(len(executor.calls), 1)

    def test_controlled_execution_failure_updates_store(self) -> None:
        record, _ = self.store.submit(self.request)
        worker = ScanJobWorker(
            store=self.store,
            executor=FakeExecutor(
                error=JobExecutionError(
                    "authorization_not_found",
                    "Authorization not found.",
                )
            ),
            clock=lambda: NOW,
        )
        worker.run_once()
        stored = self.store.get(record.job_id)
        self.assertIs(stored.state, ScanJobState.FAILED)
        self.assertEqual(stored.error_code, "authorization_not_found")

    def test_unexpected_exception_is_redacted(self) -> None:
        record, _ = self.store.submit(self.request)
        worker = ScanJobWorker(
            store=self.store,
            executor=FakeExecutor(error=RuntimeError("secret stack data")),
            clock=lambda: NOW,
        )
        worker.run_once()
        stored = self.store.get(record.job_id)
        self.assertEqual(stored.error_code, "worker_internal_error")
        self.assertNotIn("secret", stored.error_message or "")

    def test_queued_cancelled_job_is_not_claimed(self) -> None:
        record, _ = self.store.submit(self.request)
        self.store.request_cancellation(record.job_id, now=NOW)
        executor = FakeExecutor()
        worker = ScanJobWorker(
            store=self.store,
            executor=executor,
            clock=lambda: NOW,
        )
        self.assertFalse(worker.run_once())
        self.assertEqual(executor.calls, [])

    def test_run_forever_survives_an_exception_run_once_does_not_catch(self) -> None:
        """Phase 6 C-7: run_once()'s own except Exception only wraps the
        scanner-execution section; recover_expired_leases and
        claim_next_leased, called before it on every pass, are not
        wrapped at all. A real database lock (Phase 6 C-6 hardened this
        to raise a controlled JobStoreError rather than a raw sqlite3
        error) propagated out of run_forever and ended the worker thread
        permanently and silently: serve mode has no supervisor to
        restart it, and /healthz never checks whether it is still
        running. run_forever()'s own boundary now catches JobStoreError
        specifically (alongside the unrelated, Postgres-specific
        DatabaseError a separate track's P1-10 fix already covers) --
        not a blanket Exception, matching that same track's own
        reasoning that a genuinely unexpected bug should stay visible.
        This proves the thread survives and keeps polling on exactly
        the exception type it is now supposed to."""
        import threading
        from unittest.mock import patch

        record, _ = self.store.submit(self.request)
        report = completed_report("b6a39765-16c6-42b4-91f0-998bf07f1912")
        executor = FakeExecutor(
            JobExecutionOutcome(
                report=report,
                report_ref=f"jobs/{record.job_id}/report.json",
                audit_ref=f"jobs/{record.job_id}/authorization-audit.json",
            )
        )
        worker = ScanJobWorker(
            store=self.store,
            executor=executor,
            clock=lambda: NOW,
            poll_seconds=0.01,
        )

        call_count = {"n": 0}
        real_recover = self.store.recover_expired_leases

        def flaky_recover(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise JobStoreError(
                    "job_store_lock_contended",
                    "Simulated transient database lock contention.",
                )
            return real_recover(*args, **kwargs)

        stop_event = threading.Event()
        with patch.object(self.store, "recover_expired_leases", side_effect=flaky_recover):
            thread = threading.Thread(target=worker.run_forever, args=(stop_event,), daemon=True)
            thread.start()
            try:
                for _ in range(200):
                    if call_count["n"] >= 3:
                        break
                    stop_event.wait(0.01)
            finally:
                stop_event.set()
                thread.join(timeout=2)

        self.assertFalse(thread.is_alive(), "run_forever must exit once stop_event is set")
        self.assertGreaterEqual(
            call_count["n"], 3,
            "the loop must keep polling on later iterations, not die after the first failure",
        )
        self.assertEqual(worker.last_loop_error_type, "JobStoreError")
        self.assertIsNotNone(worker.last_loop_error_at)
        stored = self.store.get(record.job_id)
        self.assertIs(stored.state, ScanJobState.COMPLETED)


if __name__ == "__main__":
    unittest.main()
