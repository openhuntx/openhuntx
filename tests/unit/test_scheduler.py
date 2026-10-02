from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import (
    AuthorizationRepository,
    IdentityStore,
    JobStoreError,
    ScanJobStore,
    ScanScheduleCoordinator,
)
from webguard_contracts import OrganizationRole, PrincipalType, ScanJobMode, ScanScheduleState

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
    authorization,
    create_trustscan_permit,
    trustscan_signer,
    write_authorization,
)

SCHEDULE_ID = "66666666-6666-4666-8666-666666666666"


class SchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.auth_dir = self.root / "authorizations"
        write_authorization(self.auth_dir)
        self.store = ScanJobStore(self.root / "jobs.sqlite3")
        self.identity = IdentityStore(self.store.path)
        self.identity.create_organization(
            "InternStack", now=NOW, organization_id=ORG_ID
        )
        self.identity.create_principal(
            ORG_ID,
            "Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OWNER_ID,
        )
        self.identity.assign_authorization(
            ORG_ID,
            AUTH_ID,
            assigned_by=OWNER_ID,
            now=NOW,
        )
        self.signer = trustscan_signer(self.store)
        self.permit = create_trustscan_permit(self.store)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def create_schedule(self, **changes):
        values = dict(
            organization_id=ORG_ID,
            created_by=OWNER_ID,
            name="Hourly",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=authorization().fingerprint,
            mode=ScanJobMode.CRAWL,
            interval_seconds=3600,
            starts_at=NOW,
            now=NOW,
            schedule_id=SCHEDULE_ID,
        )
        values.update(changes)
        values.setdefault("permit_id", self.permit.permit.claims.permit_id)
        values.setdefault("permit_sha256", self.permit.permit.fingerprint)
        return self.store.create_schedule(**values)

    def coordinator(self, **changes):
        values = dict(
            store=self.store,
            authorizations=AuthorizationRepository(self.auth_dir),
            identity=self.identity,
            trustscan_signer=self.signer,
            clock=lambda: NOW,
        )
        values.update(changes)
        return ScanScheduleCoordinator(**values)

    def test_due_schedule_enqueues_one_job(self) -> None:
        self.create_schedule()
        summary = self.coordinator().run_once()
        self.assertEqual(summary.enqueued, 1)
        self.assertEqual(summary.blocked, 0)
        schedule = self.store.get_schedule_scoped(SCHEDULE_ID, ORG_ID)
        self.assertIsNotNone(schedule.last_job_id)

    def test_second_pass_does_not_duplicate_job(self) -> None:
        self.create_schedule()
        first = self.coordinator().run_once()
        second = self.coordinator().run_once()
        self.assertEqual(first.enqueued, 1)
        self.assertEqual(second.inspected, 0)

    def test_missing_assignment_blocks_schedule(self) -> None:
        other_auth = "77777777-7777-4777-8777-777777777777"
        self.create_schedule(authorization_id=other_auth)
        summary = self.coordinator().run_once()
        self.assertEqual(summary.blocked, 1)
        schedule = self.store.get_schedule_scoped(SCHEDULE_ID, ORG_ID)
        self.assertIs(schedule.state, ScanScheduleState.PAUSED)
        self.assertEqual(schedule.last_error_code, "authorization_not_assigned")

    def test_missing_authorization_file_blocks_schedule(self) -> None:
        missing = "77777777-7777-4777-8777-777777777777"
        self.identity.assign_authorization(
            ORG_ID, missing, assigned_by=OWNER_ID, now=NOW
        )
        self.create_schedule(authorization_id=missing)
        summary = self.coordinator().run_once()
        self.assertEqual(summary.blocked, 1)
        schedule = self.store.get_schedule_scoped(SCHEDULE_ID, ORG_ID)
        self.assertEqual(schedule.last_error_code, "authorization_not_found")

    def test_target_mismatch_blocks_schedule(self) -> None:
        self.create_schedule(target="https://different.example/")
        summary = self.coordinator().run_once()
        self.assertEqual(summary.blocked, 1)
        schedule = self.store.get_schedule_scoped(SCHEDULE_ID, ORG_ID)
        self.assertEqual(schedule.last_error_code, "authorization_target_mismatch")

    def test_expired_authorization_blocks_schedule(self) -> None:
        (self.auth_dir / "example.com.json").unlink()
        write_authorization(
            self.auth_dir,
            authorization(
                issued_at=NOW - timedelta(days=2),
                expires_at=NOW,
            ),
        )
        self.create_schedule()
        summary = self.coordinator().run_once()
        self.assertEqual(summary.blocked, 1)
        schedule = self.store.get_schedule_scoped(SCHEDULE_ID, ORG_ID)
        self.assertEqual(schedule.last_error_code, "authorization_not_current")

    def test_future_authorization_blocks_schedule(self) -> None:
        (self.auth_dir / "example.com.json").unlink()
        write_authorization(
            self.auth_dir,
            authorization(
                issued_at=NOW + timedelta(hours=1),
                expires_at=NOW + timedelta(days=2),
            ),
        )
        self.create_schedule()
        summary = self.coordinator().run_once()
        self.assertEqual(summary.blocked, 1)

    def test_missing_trustscan_permit_blocks_legacy_schedule(self) -> None:
        self.create_schedule(permit_id=None, permit_sha256=None)
        summary = self.coordinator().run_once()
        self.assertEqual(summary.blocked, 1)
        schedule = self.store.get_schedule_scoped(SCHEDULE_ID, ORG_ID)
        self.assertIs(schedule.state, ScanScheduleState.PAUSED)
        self.assertEqual(schedule.last_error_code, "trustscan_permit_missing")

    def test_revoked_trustscan_permit_blocks_schedule(self) -> None:
        self.create_schedule()
        self.store.revoke_scan_permit_scoped(
            self.permit.permit.claims.permit_id,
            ORG_ID,
            revoked_by=OWNER_ID,
            now=NOW,
        )
        summary = self.coordinator().run_once()
        self.assertEqual(summary.blocked, 1)
        schedule = self.store.get_schedule_scoped(SCHEDULE_ID, ORG_ID)
        self.assertEqual(schedule.last_error_code, "trustscan_permit_revoked")

    def test_expired_trustscan_permit_blocks_schedule(self) -> None:
        self.create_schedule()
        summary = self.coordinator(clock=lambda: NOW + timedelta(days=8)).run_once()
        self.assertEqual(summary.blocked, 1)
        schedule = self.store.get_schedule_scoped(SCHEDULE_ID, ORG_ID)
        self.assertEqual(schedule.last_error_code, "trustscan_permit_expired")

    def test_scheduler_configuration_is_bounded(self) -> None:
        with self.assertRaises(ValueError):
            self.coordinator(poll_seconds=0.01)
        with self.assertRaises(ValueError):
            self.coordinator(batch_size=0)
        with self.assertRaises(ValueError):
            self.coordinator(batch_size=True)

    def test_batch_size_limits_one_pass(self) -> None:
        self.create_schedule()
        self.create_schedule(
            schedule_id="88888888-8888-4888-8888-888888888888"
        )
        summary = self.coordinator(batch_size=1).run_once()
        self.assertEqual(summary.inspected, 1)
        self.assertEqual(summary.enqueued, 1)

    def test_identity_failure_blocks_only_the_affected_schedule(self) -> None:
        """Phase 6 C-7: authorization_is_assigned's own call in run_once
        was unwrapped, unlike every other lookup in this same loop, so
        an IdentityStoreError there (after the Phase 6 C-6 fix, this is
        now what a real database lock raises here, instead of an
        uncontrolled sqlite3 error) aborted the whole batch rather than
        blocking just the one affected schedule, exactly like a bad
        authorization file or a bad permit binding already do below it
        in this same function."""
        from unittest.mock import patch

        from webguard_api.identity import IdentityStoreError

        self.create_schedule()
        self.create_schedule(
            schedule_id="88888888-8888-4888-8888-888888888888"
        )
        coordinator = self.coordinator()
        with patch.object(
            self.identity,
            "authorization_is_assigned",
            side_effect=IdentityStoreError(
                "authorization_assignment_read_failed", "simulated lock"
            ),
        ):
            summary = coordinator.run_once()
        self.assertEqual(summary.inspected, 2)
        self.assertEqual(summary.blocked, 2)
        self.assertEqual(summary.enqueued, 0)
        schedule = self.store.get_schedule_scoped(SCHEDULE_ID, ORG_ID)
        self.assertEqual(
            schedule.last_error_code, "authorization_assignment_read_failed"
        )

    def test_run_forever_survives_an_exception_run_once_does_not_catch(self) -> None:
        """Companion to worker.py's identical test: run_forever had no
        exception boundary of its own at all, so any exception from
        run_once() (e.g. list_due_schedules, unwrapped, or the deliberate
        except JobStoreError: raise around enqueue_due_schedule) ended
        this thread permanently and silently in serve mode. _run_forever
        now catches JobStoreError specifically (alongside the unrelated,
        Postgres-specific DatabaseError a separate track's P1-11 fix
        already covers), not a blanket Exception."""
        import threading
        from unittest.mock import patch

        self.create_schedule()
        coordinator = self.coordinator(poll_seconds=0.1)

        call_count = {"n": 0}
        real_list_due = self.store.list_due_schedules

        def flaky_list_due(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise JobStoreError(
                    "job_store_lock_contended",
                    "Simulated transient database lock contention.",
                )
            return real_list_due(*args, **kwargs)

        stop_event = threading.Event()
        with patch.object(self.store, "list_due_schedules", side_effect=flaky_list_due):
            thread = threading.Thread(
                target=coordinator.run_forever, args=(stop_event,), daemon=True
            )
            thread.start()
            try:
                for _ in range(200):
                    if call_count["n"] >= 2:
                        break
                    stop_event.wait(0.01)
            finally:
                stop_event.set()
                thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertGreaterEqual(call_count["n"], 2)
        self.assertEqual(coordinator.last_loop_error_type, "JobStoreError")
        self.assertIsNotNone(coordinator.last_loop_error_at)


if __name__ == "__main__":
    unittest.main()
