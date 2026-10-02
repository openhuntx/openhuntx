from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import IdentityStore, IdentityStoreError, JobStoreError, ScanJobStore
from webguard_contracts import (
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
    ScanScheduleState,
)
from tests.unit.service_test_support import AUTH_ID, NOW, ORG_ID, OWNER_ID, TARGET, authorization

class Phase4PersistedScalarValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def mutate(path: Path, sql: str, params: tuple[object, ...]) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.execute(sql, params)
            connection.commit()
        finally:
            connection.close()

    def test_principal_active_rejects_non_boolean_integer(self) -> None:
        path = self.root / 'identity.sqlite3'
        ScanJobStore(path)
        identity = IdentityStore(path)
        identity.create_organization('Phase 4 Scalar Tenant', now=NOW, organization_id=ORG_ID)
        identity.create_principal(
            ORG_ID, 'Phase 4 Owner', principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER, now=NOW, principal_id=OWNER_ID,
        )
        self.mutate(path, 'UPDATE principals SET active = 2 WHERE principal_id = ?', (OWNER_ID,))
        with self.assertRaises(IdentityStoreError) as caught:
            identity.get_principal(OWNER_ID)
        self.assertEqual(caught.exception.code, 'identity_persisted_state_invalid')

    def _leased_job(self, path: Path, key: str):
        store = ScanJobStore(path)
        auth = authorization()
        request = ScanJobRequest(
            idempotency_key=key, target=TARGET, authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint, mode=ScanJobMode.CRAWL, submitted_at=NOW,
        )
        record, created = store.submit(request)
        self.assertTrue(created)
        lease = store.claim_next_leased(now=NOW, worker_id='phase4-scalar-worker', lease_seconds=1)
        self.assertIsNotNone(lease)
        return store, record

    def test_recovery_rejects_non_boolean_cancellation_value(self) -> None:
        path = self.root / 'cancel.sqlite3'
        store, record = self._leased_job(path, 'phase4-invalid-cancellation')
        self.mutate(path, 'UPDATE scan_jobs SET cancellation_requested = 2 WHERE job_id = ?', (record.job_id,))
        with self.assertRaises(JobStoreError) as caught:
            store.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=3)
        self.assertEqual(caught.exception.code, 'job_store_persisted_state_invalid')
        self.assertIs(store.get(record.job_id).state, ScanJobState.RUNNING)

    def test_recovery_rejects_malformed_revision(self) -> None:
        path = self.root / 'revision.sqlite3'
        store, record = self._leased_job(path, 'phase4-invalid-revision')
        self.mutate(path, 'UPDATE scan_jobs SET revision = ? WHERE job_id = ?', (sqlite3.Binary(b'invalid'), record.job_id))
        with self.assertRaises(JobStoreError) as caught:
            store.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=3)
        self.assertEqual(caught.exception.code, 'job_store_persisted_state_invalid')

    def test_recovery_rejects_malformed_attempt_count(self) -> None:
        path = self.root / 'attempt.sqlite3'
        store, record = self._leased_job(path, 'phase4-invalid-attempt-count')
        self.mutate(path, 'UPDATE scan_jobs SET attempt_count = ? WHERE job_id = ?', (sqlite3.Binary(b'invalid'), record.job_id))
        with self.assertRaises(JobStoreError) as caught:
            store.recover_expired_leases(now=NOW + timedelta(seconds=2), maximum_attempts=3)
        self.assertEqual(caught.exception.code, 'job_store_persisted_state_invalid')

    def test_get_rejects_control_character_in_persisted_error_message(self) -> None:
        """Phase 6 C-5: _record_from_row's ScanJobRecord(...) construction
        was the one field-level validation this row-reconstruction
        function did not wrap (every earlier field in the same function
        already is). A row.error_message containing a control character
        fails ScanJobRecord's own contract validation, but that raised
        ScanJobValidationError, uncontrolled, straight out of store.get()
        rather than the JobStoreError every other corrupt-row case in
        this file already produces."""
        path = self.root / 'error-message.sqlite3'
        store, record = self._leased_job(path, 'phase4-invalid-error-message')
        self.mutate(
            path,
            "UPDATE scan_jobs SET error_message = ? WHERE job_id = ?",
            (b'bad\x01', record.job_id),
        )
        with self.assertRaises(JobStoreError) as caught:
            store.get(record.job_id)
        self.assertEqual(caught.exception.code, 'job_store_persisted_state_invalid')

    def test_get_schedule_rejects_control_character_in_persisted_name(self) -> None:
        """Same gap as above, in _schedule_from_row's ScanScheduleRecord(...)
        construction."""
        path = self.root / 'schedule-name.sqlite3'
        store = ScanJobStore(path)
        record = store.create_schedule(
            organization_id=ORG_ID,
            created_by=OWNER_ID,
            name='Phase 6 schedule',
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=authorization().fingerprint,
            mode=ScanJobMode.CRAWL,
            interval_seconds=3600,
            starts_at=NOW,
            now=NOW,
        )
        self.assertIs(record.state, ScanScheduleState.ACTIVE)
        self.mutate(
            path,
            "UPDATE scan_schedules SET name = ? WHERE schedule_id = ?",
            (b'bad\x01name', record.schedule_id),
        )
        with self.assertRaises(JobStoreError) as caught:
            store.get_schedule_scoped(record.schedule_id, ORG_ID)
        self.assertEqual(caught.exception.code, 'job_store_persisted_state_invalid')

if __name__ == '__main__':
    unittest.main()
