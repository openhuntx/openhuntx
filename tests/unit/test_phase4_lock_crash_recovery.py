from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from webguard_api import (
    IdentityStore,
    JobStoreError,
    ScanJobStore,
)
from webguard_api.identity import IdentityStoreError
from webguard_contracts import (
    AuditOutcome,
    OrganizationRole,
    PrincipalType,
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
    SecurityAuditEvent,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    ORG_ID,
    OWNER_ID,
    TARGET,
)


def request(key: str) -> ScanJobRequest:
    return ScanJobRequest(
        idempotency_key=key,
        target=TARGET,
        authorization_id=AUTH_ID,
        authorization_sha256="a" * 64,
        mode=ScanJobMode.CRAWL,
        submitted_at=NOW,
    )


class ShortBusyStore(ScanJobStore):
    """Use a tiny busy timeout for deterministic lock tests."""

    def _connect(self) -> sqlite3.Connection:
        connection = super()._connect()
        connection.execute(
            "PRAGMA busy_timeout = 25"
        )
        return connection


class ShortBusyIdentityStore(IdentityStore):
    """Use a tiny busy timeout for deterministic lock tests."""

    def _connect(self) -> sqlite3.Connection:
        connection = super()._connect()
        connection.execute(
            "PRAGMA busy_timeout = 25"
        )
        return connection


class Phase4LockCrashRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "jobs.sqlite3"

        self.store = ScanJobStore(self.path)
        self.identity = IdentityStore(self.path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def lock_database(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            isolation_level=None,
        )

        connection.execute(
            "PRAGMA busy_timeout = 25"
        )
        connection.execute(
            "BEGIN IMMEDIATE"
        )

        return connection

    def raw_job_state(
        self,
        job_id: str,
    ) -> str:
        connection = sqlite3.connect(self.path)

        try:
            row = connection.execute(
                """
                SELECT state
                FROM scan_jobs
                WHERE job_id = ?
                """,
                (job_id,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(row)
        return row[0]

    def test_locked_submit_is_controlled_and_creates_no_partial_job(
        self,
    ) -> None:
        store = ShortBusyStore(self.path)
        locked = self.lock_database()

        try:
            with self.assertRaises(JobStoreError):
                store.submit(
                    request("phase4-locked-submit")
                )
        finally:
            locked.rollback()
            locked.close()

        connection = sqlite3.connect(self.path)

        try:
            count = connection.execute(
                """
                SELECT COUNT(*)
                FROM scan_jobs
                WHERE idempotency_key = ?
                """,
                ("phase4-locked-submit",),
            ).fetchone()[0]
        finally:
            connection.close()

        self.assertEqual(
            count,
            0,
            msg=(
                "A failed locked submit must not leave "
                "partial persisted work."
            ),
        )

    def test_locked_claim_is_controlled_and_job_remains_queued(
        self,
    ) -> None:
        record, _ = self.store.submit(
            request("phase4-locked-claim")
        )

        store = ShortBusyStore(self.path)
        locked = self.lock_database()

        try:
            with self.assertRaises(JobStoreError):
                store.claim_next(
                    now=NOW
                )
        finally:
            locked.rollback()
            locked.close()

        self.assertEqual(
            self.raw_job_state(record.job_id),
            ScanJobState.QUEUED.value,
            msg=(
                "A failed claim caused by a DB lock "
                "must not cross the execution boundary."
            ),
        )

    def test_store_recovers_after_database_lock_is_released(
        self,
    ) -> None:
        record, _ = self.store.submit(
            request("phase4-lock-release")
        )

        store = ShortBusyStore(self.path)
        locked = self.lock_database()

        try:
            with self.assertRaises(JobStoreError):
                store.claim_next(
                    now=NOW
                )
        finally:
            locked.rollback()
            locked.close()

        reopened = ScanJobStore(self.path)

        claimed = reopened.claim_next(
            now=NOW + timedelta(seconds=1)
        )

        self.assertIsNotNone(claimed)
        self.assertEqual(
            claimed.job_id,
            record.job_id,
        )
        self.assertIs(
            claimed.state,
            ScanJobState.RUNNING,
        )

    def test_uncommitted_claim_like_update_disappears_after_connection_crash(
        self,
    ) -> None:
        record, _ = self.store.submit(
            request("phase4-uncommitted-update")
        )

        connection = sqlite3.connect(
            self.path,
            isolation_level=None,
        )

        connection.execute(
            "BEGIN IMMEDIATE"
        )

        connection.execute(
            """
            UPDATE scan_jobs
            SET state = ?,
                started_at = ?,
                updated_at = ?,
                revision = revision + 1
            WHERE job_id = ?
            """,
            (
                ScanJobState.RUNNING.value,
                NOW.isoformat().replace(
                    "+00:00",
                    "Z",
                ),
                NOW.isoformat().replace(
                    "+00:00",
                    "Z",
                ),
                record.job_id,
            ),
        )

        # Simulate process death before COMMIT.
        connection.close()

        reopened = ScanJobStore(self.path)
        recovered = reopened.get(
            record.job_id
        )

        self.assertIs(
            recovered.state,
            ScanJobState.QUEUED,
            msg=(
                "An uncommitted execution transition "
                "must disappear after connection loss."
            ),
        )

        self.assertIsNone(
            recovered.started_at
        )

    def test_committed_queued_job_survives_restart_and_claims_once(
        self,
    ) -> None:
        record, _ = self.store.submit(
            request("phase4-durable-queue")
        )

        restarted_a = ScanJobStore(self.path)
        restarted_b = ScanJobStore(self.path)

        claimed = restarted_a.claim_next(
            now=NOW
        )

        self.assertIsNotNone(claimed)
        self.assertEqual(
            claimed.job_id,
            record.job_id,
        )

        self.assertIsNone(
            restarted_b.claim_next(
                now=NOW
            ),
            msg=(
                "Restarted stores must not duplicate "
                "an already claimed job."
            ),
        )

    def test_expired_lease_can_be_recovered_after_store_restart(
        self,
    ) -> None:
        record, _ = self.store.submit(
            request("phase4-restart-lease")
        )

        lease = self.store.claim_next_leased(
            now=NOW,
            worker_id="phase4-worker-a",
            lease_seconds=1,
        )

        self.assertIsNotNone(lease)

        restarted = ScanJobStore(self.path)

        summary = restarted.recover_expired_leases(
            now=NOW + timedelta(seconds=2),
            maximum_attempts=3,
        )

        self.assertEqual(
            summary.requeued,
            1,
        )

        reclaimed = restarted.claim_next_leased(
            now=NOW + timedelta(seconds=3),
            worker_id="phase4-worker-b",
            lease_seconds=30,
        )

        self.assertIsNotNone(reclaimed)
        self.assertEqual(
            reclaimed.record.job_id,
            record.job_id,
        )
        self.assertEqual(
            reclaimed.worker_id,
            "phase4-worker-b",
        )

    def test_locked_identity_write_is_controlled_and_not_persisted(
        self,
    ) -> None:
        identity = ShortBusyIdentityStore(
            self.path
        )
        locked = self.lock_database()

        try:
            with self.assertRaises(
                IdentityStoreError
            ):
                identity.create_organization(
                    "Phase 4 Locked Tenant",
                    now=NOW,
                    organization_id=ORG_ID,
                )
        finally:
            locked.rollback()
            locked.close()

        connection = sqlite3.connect(self.path)

        try:
            row = connection.execute(
                """
                SELECT organization_id
                FROM organizations
                WHERE organization_id = ?
                """,
                (ORG_ID,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNone(
            row,
            msg=(
                "A failed locked identity write must "
                "not persist partial RBAC state."
            ),
        )


    def create_owner_identity(
        self,
        identity: IdentityStore,
    ) -> None:
        identity.create_organization(
            "Phase 4 Identity Tenant",
            now=NOW,
            organization_id=ORG_ID,
        )

        identity.create_principal(
            ORG_ID,
            "Phase 4 Owner",
            principal_type=PrincipalType.USER,
            role=OrganizationRole.OWNER,
            now=NOW,
            principal_id=OWNER_ID,
        )

    def test_locked_principal_create_is_controlled(
        self,
    ) -> None:
        identity = ShortBusyIdentityStore(
            self.path
        )

        identity.create_organization(
            "Phase 4 Principal Tenant",
            now=NOW,
            organization_id=ORG_ID,
        )

        locked = self.lock_database()

        try:
            with self.assertRaises(
                IdentityStoreError
            ) as caught:
                identity.create_principal(
                    ORG_ID,
                    "Locked Principal",
                    principal_type=PrincipalType.USER,
                    role=OrganizationRole.OWNER,
                    now=NOW,
                    principal_id=OWNER_ID,
                )
        finally:
            locked.rollback()
            locked.close()

        self.assertEqual(
            caught.exception.code,
            "principal_create_failed",
        )

        connection = sqlite3.connect(self.path)

        try:
            row = connection.execute(
                """
                SELECT principal_id
                FROM principals
                WHERE principal_id = ?
                """,
                (OWNER_ID,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNone(
            row,
            msg=(
                "A locked principal creation must "
                "not persist partial identity state."
            ),
        )

    def test_locked_token_create_is_controlled(
        self,
    ) -> None:
        identity = ShortBusyIdentityStore(
            self.path
        )
        self.create_owner_identity(identity)

        token_id = (
            "55555555-5555-4555-8555-555555555555"
        )

        locked = self.lock_database()

        try:
            with self.assertRaises(
                IdentityStoreError
            ) as caught:
                identity.create_token(
                    OWNER_ID,
                    label="phase4-locked-create",
                    now=NOW,
                    token_id=token_id,
                )
        finally:
            locked.rollback()
            locked.close()

        self.assertEqual(
            caught.exception.code,
            "api_token_create_failed",
        )

        connection = sqlite3.connect(self.path)

        try:
            row = connection.execute(
                """
                SELECT token_id
                FROM api_tokens
                WHERE token_id = ?
                """,
                (token_id,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNone(
            row,
            msg=(
                "A locked API-token creation must "
                "not persist token metadata."
            ),
        )

    def test_locked_token_revoke_is_controlled(
        self,
    ) -> None:
        identity = ShortBusyIdentityStore(
            self.path
        )
        self.create_owner_identity(identity)

        issued = identity.create_token(
            OWNER_ID,
            label="phase4-revoke",
            now=NOW,
            token_id=(
                "66666666-6666-4666-8666-666666666666"
            ),
        )

        locked = self.lock_database()

        try:
            with self.assertRaises(
                IdentityStoreError
            ) as caught:
                identity.revoke_token(
                    issued.metadata.token_id,
                    now=NOW + timedelta(seconds=1),
                )
        finally:
            locked.rollback()
            locked.close()

        self.assertEqual(
            caught.exception.code,
            "api_token_revoke_failed",
        )

        connection = sqlite3.connect(self.path)

        try:
            row = connection.execute(
                """
                SELECT revoked_at
                FROM api_tokens
                WHERE token_id = ?
                """,
                (issued.metadata.token_id,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(row)
        self.assertIsNone(
            row[0],
            msg=(
                "A failed locked revocation must "
                "not mark the token revoked."
            ),
        )

    def test_locked_authorization_assignment_is_controlled(
        self,
    ) -> None:
        identity = ShortBusyIdentityStore(
            self.path
        )
        self.create_owner_identity(identity)

        locked = self.lock_database()

        try:
            with self.assertRaises(
                IdentityStoreError
            ) as caught:
                identity.assign_authorization(
                    ORG_ID,
                    AUTH_ID,
                    assigned_by=OWNER_ID,
                    now=NOW,
                )
        finally:
            locked.rollback()
            locked.close()

        self.assertEqual(
            caught.exception.code,
            "authorization_assignment_failed",
        )

        self.assertFalse(
            identity.authorization_is_assigned(
                ORG_ID,
                AUTH_ID,
            ),
            msg=(
                "A locked authorization assignment "
                "must not persist."
            ),
        )

    def test_locked_authentication_bookkeeping_is_controlled(
        self,
    ) -> None:
        identity = ShortBusyIdentityStore(
            self.path
        )
        self.create_owner_identity(identity)

        issued = identity.create_token(
            OWNER_ID,
            label="phase4-auth-bookkeeping",
            now=NOW,
            token_id=(
                "77777777-7777-4777-8777-777777777777"
            ),
        )

        locked = self.lock_database()

        try:
            with self.assertRaises(
                IdentityStoreError
            ) as caught:
                identity.authenticate_token(
                    issued.token,
                    now=NOW + timedelta(seconds=1),
                )
        finally:
            locked.rollback()
            locked.close()

        self.assertEqual(
            caught.exception.code,
            "api_token_authentication_failed",
        )

        connection = sqlite3.connect(self.path)

        try:
            row = connection.execute(
                """
                SELECT last_used_at
                FROM api_tokens
                WHERE token_id = ?
                """,
                (issued.metadata.token_id,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNotNone(row)
        self.assertIsNone(
            row[0],
            msg=(
                "Failed authentication bookkeeping "
                "must not partially update last_used_at."
            ),
        )

    def test_locked_audit_event_write_is_controlled(
        self,
    ) -> None:
        identity = ShortBusyIdentityStore(
            self.path
        )
        self.create_owner_identity(identity)

        issued = identity.create_token(
            OWNER_ID,
            label="phase4-audit",
            now=NOW,
            token_id=(
                "88888888-8888-4888-8888-888888888888"
            ),
        )

        event_id = (
            "99999999-9999-4999-8999-999999999999"
        )

        event = SecurityAuditEvent(
            event_id=event_id,
            request_id=(
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            ),
            organization_id=ORG_ID,
            principal_id=OWNER_ID,
            token_id=issued.metadata.token_id,
            action="phase4.lock-test",
            resource_type="identity_store",
            resource_id="phase4",
            outcome=AuditOutcome.SUCCEEDED,
            occurred_at=NOW,
        )

        locked = self.lock_database()

        try:
            with self.assertRaises(
                IdentityStoreError
            ) as caught:
                identity.record_audit_event(
                    event
                )
        finally:
            locked.rollback()
            locked.close()

        self.assertEqual(
            caught.exception.code,
            "audit_event_write_failed",
        )

        connection = sqlite3.connect(self.path)

        try:
            row = connection.execute(
                """
                SELECT event_id
                FROM security_audit_events
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()
        finally:
            connection.close()

        self.assertIsNone(
            row,
            msg=(
                "A failed locked audit write must "
                "not persist a partial audit event."
            ),
        )

    def lock_database_exclusive(self) -> sqlite3.Connection:
        """BEGIN IMMEDIATE (used by lock_database above) only blocks other
        writers: a plain SELECT from another connection still succeeds
        while a RESERVED lock is held, which is why every test above this
        point exercises a write path. Phase 6's C-6 finding is in three
        read-only IdentityStore methods, which need an EXCLUSIVE lock to
        reproduce a real blocked read."""

        connection = sqlite3.connect(
            self.path,
            isolation_level=None,
        )
        connection.execute("PRAGMA busy_timeout = 25")
        connection.execute("BEGIN EXCLUSIVE")
        return connection

    def test_locked_get_organization_is_controlled(self) -> None:
        """Phase 6 C-6: get_organization had try/finally with no
        except sqlite3.Error, unlike create_principal's write path two
        methods above it in the same file. A locked database raised a
        raw sqlite3.OperationalError instead of IdentityStoreError."""

        self.identity.create_organization(
            "Phase 6 Read Lock Tenant", now=NOW, organization_id=ORG_ID
        )
        identity = ShortBusyIdentityStore(self.path)
        locked = self.lock_database_exclusive()
        try:
            with self.assertRaises(IdentityStoreError) as caught:
                identity.get_organization(ORG_ID)
        finally:
            locked.rollback()
            locked.close()
        self.assertEqual(caught.exception.code, "organization_read_failed")

    def test_locked_get_principal_is_controlled(self) -> None:
        self.create_owner_identity(self.identity)
        identity = ShortBusyIdentityStore(self.path)
        locked = self.lock_database_exclusive()
        try:
            with self.assertRaises(IdentityStoreError) as caught:
                identity.get_principal(OWNER_ID)
        finally:
            locked.rollback()
            locked.close()
        self.assertEqual(caught.exception.code, "principal_read_failed")

    def test_locked_authorization_is_assigned_is_controlled(self) -> None:
        self.create_owner_identity(self.identity)
        self.identity.assign_authorization(
            ORG_ID, AUTH_ID, assigned_by=OWNER_ID, now=NOW
        )
        identity = ShortBusyIdentityStore(self.path)
        locked = self.lock_database_exclusive()
        try:
            with self.assertRaises(IdentityStoreError) as caught:
                identity.authorization_is_assigned(ORG_ID, AUTH_ID)
        finally:
            locked.rollback()
            locked.close()
        self.assertEqual(
            caught.exception.code, "authorization_assignment_read_failed"
        )


if __name__ == "__main__":
    unittest.main()
