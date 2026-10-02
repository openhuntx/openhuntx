"""SQLite-backed persistent scan-job queue."""

from __future__ import annotations

import base64
import os
import secrets
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from webguard_contracts import (
    SignedTrustScanPermit,
    ScanJobMode,
    ScanJobRecord,
    ScanJobRequest,
    ScanJobState,
    ScanScheduleRecord,
    ScanScheduleState,
    ScanStatus,
    load_signed_trustscan_permit_json,
)

from .permits import PersistedTrustScanPermit


from .service_secrets import (
    CURSOR_SECRET_NAME,
    default_service_secret_path,
    TRUSTSCAN_SECRET_NAME,
    ServiceSecretError,
    ServiceSecretFile,
    service_secrets_from_encoded,
)

DATABASE_SCHEMA_VERSION = 7


@dataclass(frozen=True, slots=True)
class LeasedScanJob:
    """One running job fenced to a specific worker lease."""

    record: ScanJobRecord
    worker_id: str
    lease_token: str
    lease_expires_at: datetime
    attempt_count: int


@dataclass(frozen=True, slots=True)
class LeaseRecoverySummary:
    """Counts returned after recovering expired worker leases."""

    requeued: int = 0
    cancelled: int = 0
    failed: int = 0

    @property
    def total(self) -> int:
        return self.requeued + self.cancelled + self.failed


class JobStoreError(ValueError):
    """Controlled persistent job-store failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None

    if not isinstance(value, str) or not value.endswith("Z"):
        raise JobStoreError(
            "job_store_persisted_state_invalid",
            "Persisted job-store state is invalid.",
        )

    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00"
        )
    except ValueError as exc:
        raise JobStoreError(
            "job_store_persisted_state_invalid",
            "Persisted job-store state is invalid.",
        ) from exc

    return parsed.astimezone(timezone.utc)


def _persisted_boolean(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, int) or value not in (0, 1):
        raise JobStoreError(
            'job_store_persisted_state_invalid',
            'Persisted boolean values must be encoded as integer 0 or 1.',
        )
    return value == 1


def _persisted_integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise JobStoreError(
            "job_store_persisted_state_invalid",
            "Persisted job-store state is invalid.",
        )

    return value


def _no_earlier_than(candidate: datetime, floor: datetime) -> datetime:
    """Never returns a value earlier than `floor`.

    A caller's `now` (worker.py's `self.clock()`, read once at the top
    of `run_once()`) is captured before this store even attempts to
    acquire the SQLite write lock for the transaction that will read
    and update a job row. Because SQLite serializes writers, that
    attempt can block until a concurrent transaction (e.g. a job
    submission that reads its own, later `now` for `submitted_at`)
    commits first. Once unblocked, the row this call selects or
    updates can carry a `submitted_at` later than the `now` this call
    started with, even though nothing about either clock reading was
    itself wrong. `ScanJobRecord.__post_init__` enforces that
    `updated_at`/`started_at` can never precede a job's own
    `submitted_at`; flooring the value written for those columns to
    the row's own `submitted_at` keeps that true by construction
    rather than by assuming a `now` read before a lock wait is still
    fresh once the wait ends. This only ever raises the value used,
    never lowers it: it does not fabricate an earlier event as
    having happened later for any other purpose (permit validity
    windows, lease-expiry filtering, and similar checks all keep using
    the caller's real `now` untouched)."""

    return candidate if candidate >= floor else floor


class ScanJobStore:
    """A small transactional queue using one SQLite database file."""

    def __init__(
        self,
        path: Path,
        *,
        service_secret_path: Path | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self.service_secret_path = (
            default_service_secret_path(self.path)
            if service_secret_path is None
            else Path(service_secret_path).expanduser()
        )
        self._service_secret_file = ServiceSecretFile(
            self.service_secret_path
        )

        database_existed = self._prepare_path()

        try:
            self._initialize(database_existed=database_existed)
            self._service_secrets = self._service_secret_file.load()
        except ServiceSecretError as exc:
            raise JobStoreError(
                exc.code,
                exc.message,
            ) from exc

    def _prepare_path(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.path.parent, 0o700)
        except OSError as exc:
            raise JobStoreError(
                "job_store_directory_create_failed",
                f"Unable to create job-store directory {self.path.parent}.",
            ) from exc
        try:
            exists = os.path.lexists(self.path)
        except OSError as exc:
            raise JobStoreError(
                "job_store_path_inspection_failed",
                f"Unable to inspect job-store path {self.path}.",
            ) from exc
        if exists:
            try:
                metadata = self.path.lstat()
            except OSError as exc:
                raise JobStoreError(
                    "job_store_path_inspection_failed",
                    f"Unable to inspect job-store path {self.path}.",
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise JobStoreError(
                    "job_store_symlink_not_allowed",
                    "Job-store database cannot be a symbolic link.",
                )
            if not stat.S_ISREG(metadata.st_mode):
                raise JobStoreError(
                    "job_store_not_regular_file",
                    "Job-store path must be a regular file.",
                )

        return exists

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=5.0,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise JobStoreError(
                "job_store_open_failed",
                "Unable to open the scan-job database.",
            ) from exc
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(
        self,
        *,
        database_existed: bool,
    ) -> None:
        connection = self._connect()
        try:
            if not database_existed:
                connection.executescript(
                    """
                    BEGIN IMMEDIATE;
                    CREATE TABLE service_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE scan_jobs (
                        job_id TEXT PRIMARY KEY,
                        idempotency_key TEXT NOT NULL UNIQUE,
                        request_fingerprint TEXT NOT NULL,
                        target TEXT NOT NULL,
                        authorization_id TEXT NOT NULL,
                        authorization_sha256 TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        submitted_at TEXT NOT NULL,
                        state TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        cancellation_requested INTEGER NOT NULL,
                        started_at TEXT,
                        completed_at TEXT,
                        scan_id TEXT,
                        result_status TEXT,
                        report_ref TEXT,
                        audit_ref TEXT,
                        error_code TEXT,
                        error_message TEXT
                    );
                    CREATE INDEX idx_scan_jobs_queue
                        ON scan_jobs(
                            state,
                            submitted_at,
                            job_id
                        );
                    CREATE TABLE job_scopes (
                        job_id TEXT PRIMARY KEY,
                        organization_id TEXT NOT NULL,
                        submitted_by TEXT NOT NULL,
                        FOREIGN KEY (job_id)
                            REFERENCES scan_jobs(job_id)
                            ON DELETE CASCADE
                    );
                    CREATE INDEX idx_job_scopes_organization
                        ON job_scopes(
                            organization_id,
                            job_id
                        );
                    INSERT INTO service_metadata(
                        key,
                        value
                    )
                    VALUES ('schema_version', '1');
                    COMMIT;
                    """
                )

            version = self._read_schema_version(connection)

            if version == 1:
                self._migrate_v1_to_v2(connection)
                version = 2

            if version == 2:
                self._migrate_v2_to_v3(connection)
                version = 3

            if version == 3:
                self._migrate_v3_to_v4(connection)
                version = 4

            if version == 4:
                self._migrate_v4_to_v5(connection)
                version = 5

            if version == 5:
                self._migrate_v5_to_v6(connection)
                version = 6

            if version == 6:
                self._migrate_v6_to_v7(connection)
                version = 7

            if version != DATABASE_SCHEMA_VERSION:
                raise JobStoreError(
                    "job_store_schema_unsupported",
                    "The job-store schema version is unsupported.",
                )

            self._validate_current_schema(connection)

        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_initialize_failed",
                "Unable to initialize the scan-job database.",
            ) from exc

        finally:
            connection.close()

        try:
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise JobStoreError(
                "job_store_permissions_failed",
                "Unable to apply owner-only database permissions.",
            ) from exc

    @staticmethod
    def _validate_current_schema(
        connection: sqlite3.Connection,
    ) -> None:
        """Fail closed when declared schema and storage disagree."""

        required_columns = {
            "service_metadata": {
                "key",
                "value",
            },
            "scan_jobs": {
                "job_id",
                "idempotency_key",
                "request_fingerprint",
                "target",
                "authorization_id",
                "authorization_sha256",
                "mode",
                "submitted_at",
                "state",
                "updated_at",
                "revision",
                "cancellation_requested",
                "started_at",
                "completed_at",
                "scan_id",
                "result_status",
                "report_ref",
                "audit_ref",
                "error_code",
                "error_message",
                "worker_id",
                "lease_token",
                "lease_expires_at",
                "heartbeat_at",
                "attempt_count",
            },
            "job_scopes": {
                "job_id",
                "organization_id",
                "submitted_by",
            },
            "scan_schedules": {
                "schedule_id",
                "organization_id",
                "created_by",
                "name",
                "target",
                "authorization_id",
                "authorization_sha256",
                "mode",
                "interval_seconds",
                "state",
                "created_at",
                "updated_at",
                "next_run_at",
                "revision",
                "last_enqueued_at",
                "last_job_id",
                "last_error_code",
                "last_error_at",
            },
            "scan_permits": {
                "permit_id",
                "organization_id",
                "authorization_id",
                "authorization_sha256",
                "target",
                "issued_by",
                "issued_at",
                "not_before",
                "expires_at",
                "permit_sha256",
                "signing_key_id",
                "document_json",
                "revoked_at",
                "revoked_by",
            },
            "job_permits": {
                "job_id",
                "permit_id",
                "permit_sha256",
            },
            "schedule_permits": {
                "schedule_id",
                "permit_id",
                "permit_sha256",
            },
            "job_safety_receipts": {
                "job_id",
                "receipt_ref",
                "receipt_sha256",
                "created_at",
            },
        }

        for table_name, expected in required_columns.items():
            table = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = ?
                """,
                (table_name,),
            ).fetchone()

            if table is None:
                raise JobStoreError(
                    "job_store_schema_invalid",
                    (
                        "The job-store schema does not match "
                        "its declared version."
                    ),
                )

            rows = connection.execute(
                """
                SELECT name
                FROM pragma_table_info(?)
                """,
                (table_name,),
            ).fetchall()

            actual = {
                row["name"]
                for row in rows
            }

            if not expected.issubset(actual):
                raise JobStoreError(
                    "job_store_schema_invalid",
                    (
                        "The job-store schema does not match "
                        "its declared version."
                    ),
                )

    @staticmethod
    def _migrate_v5_to_v6(connection: sqlite3.Connection) -> None:
        """Add immutable per-job TrustScan safety-receipt references."""
        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE job_safety_receipts (
                    job_id TEXT PRIMARY KEY,
                    receipt_ref TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (job_id) REFERENCES scan_jobs(job_id) ON DELETE CASCADE
                );
                UPDATE service_metadata SET value = '6' WHERE key = 'schema_version';
                COMMIT;
                """
            )
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    def _migrate_v6_to_v7(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        """Move long-lived service signing secrets outside SQLite."""

        try:
            rows = connection.execute(
                """
                SELECT key, value
                FROM service_secrets
                """
            ).fetchall()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "service_secret_legacy_state_invalid",
                "Unable to read legacy service-secret state.",
            ) from exc

        legacy_values = {
            row["key"]: row["value"]
            for row in rows
        }

        expected_names = {
            CURSOR_SECRET_NAME,
            TRUSTSCAN_SECRET_NAME,
        }

        if set(legacy_values) != expected_names:
            raise JobStoreError(
                "service_secret_legacy_state_invalid",
                "Legacy service-secret state is incomplete or invalid.",
            )

        legacy_material = service_secrets_from_encoded(
            legacy_values[CURSOR_SECRET_NAME],
            legacy_values[TRUSTSCAN_SECRET_NAME],
        )

        existing_material = self._service_secret_file.load_if_exists()

        if existing_material is None:
            installed_material = self._service_secret_file.create(
                legacy_material
            )
        else:
            installed_material = existing_material

        if installed_material != legacy_material:
            raise JobStoreError(
                "service_secret_mismatch",
                (
                    "External service-secret material does not match "
                    "the legacy database."
                ),
            )

        try:
            # Ensure content removed from the legacy secret table is
            # overwritten rather than retained in SQLite free pages.
            connection.execute("PRAGMA secure_delete = ON")
            connection.execute("BEGIN IMMEDIATE")

            locked_rows = connection.execute(
                """
                SELECT key, value
                FROM service_secrets
                """
            ).fetchall()

            locked_values = {
                row["key"]: row["value"]
                for row in locked_rows
            }

            if locked_values != legacy_values:
                raise JobStoreError(
                    "service_secret_mismatch",
                    (
                        "Legacy service-secret state changed during "
                        "migration."
                    ),
                )

            connection.execute("DROP TABLE service_secrets")
            connection.execute(
                """
                UPDATE service_metadata
                SET value = '7'
                WHERE key = 'schema_version'
                """
            )
            connection.execute("COMMIT")

        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass

            raise JobStoreError(
                "service_secret_migration_failed",
                "Unable to migrate service secrets outside SQLite.",
            ) from exc

    @staticmethod
    def _read_schema_version(connection: sqlite3.Connection) -> int:
        row = connection.execute(
            "SELECT value FROM service_metadata WHERE key = 'schema_version'"
        ).fetchone()
        if row is None:
            raise JobStoreError(
                "job_store_schema_unsupported",
                "The job-store schema version is missing.",
            )
        try:
            return int(row["value"])
        except (TypeError, ValueError) as exc:
            raise JobStoreError(
                "job_store_schema_unsupported",
                "The job-store schema version is invalid.",
            ) from exc

    @staticmethod
    def _migrate_v1_to_v2(connection: sqlite3.Connection) -> None:
        """Add durable worker leases and recover legacy running jobs."""

        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("ALTER TABLE scan_jobs ADD COLUMN worker_id TEXT")
            connection.execute("ALTER TABLE scan_jobs ADD COLUMN lease_token TEXT")
            connection.execute("ALTER TABLE scan_jobs ADD COLUMN lease_expires_at TEXT")
            connection.execute("ALTER TABLE scan_jobs ADD COLUMN heartbeat_at TEXT")
            connection.execute(
                "ALTER TABLE scan_jobs ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0"
            )
            connection.execute(
                """
                UPDATE scan_jobs
                SET state = ?, completed_at = updated_at, revision = revision + 1
                WHERE state = ? AND cancellation_requested = 1
                """,
                (ScanJobState.CANCELLED.value, ScanJobState.RUNNING.value),
            )
            connection.execute(
                """
                UPDATE scan_jobs
                SET state = ?, started_at = NULL, revision = revision + 1
                WHERE state = ?
                """,
                (ScanJobState.QUEUED.value, ScanJobState.RUNNING.value),
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scan_jobs_expired_lease
                ON scan_jobs(state, lease_expires_at, job_id)
                """
            )
            connection.execute(
                "UPDATE service_metadata SET value = '2' WHERE key = 'schema_version'"
            )
            connection.execute("COMMIT")
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    @staticmethod
    def _migrate_v2_to_v3(connection: sqlite3.Connection) -> None:
        """Add organization-scoped recurring scan schedules."""

        try:
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE scan_schedules (
                    schedule_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    authorization_sha256 TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    interval_seconds INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    next_run_at TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    last_enqueued_at TEXT,
                    last_job_id TEXT,
                    last_error_code TEXT,
                    last_error_at TEXT,
                    FOREIGN KEY (last_job_id) REFERENCES scan_jobs(job_id) ON DELETE SET NULL
                );
                CREATE INDEX idx_scan_schedules_organization
                    ON scan_schedules(organization_id, created_at, schedule_id);
                CREATE INDEX idx_scan_schedules_due
                    ON scan_schedules(state, next_run_at, schedule_id);
                UPDATE service_metadata SET value = '3' WHERE key = 'schema_version';
                COMMIT;
                """
            )
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    @staticmethod
    def _migrate_v3_to_v4(connection: sqlite3.Connection) -> None:
        """Add a private service secret for signed pagination cursors."""

        key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                CREATE TABLE service_secrets (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO service_secrets(key, value, created_at)
                VALUES ('pagination_cursor_hmac', ?, ?)
                """,
                (key, _timestamp(datetime.now(timezone.utc))),
            )
            connection.execute(
                """
                CREATE INDEX idx_scan_jobs_organization_feed
                ON scan_jobs(submitted_at DESC, job_id DESC)
                """
            )
            connection.execute(
                """
                CREATE INDEX idx_scan_schedules_organization_feed
                ON scan_schedules(organization_id, created_at DESC, schedule_id DESC)
                """
            )
            connection.execute(
                "UPDATE service_metadata SET value = '4' WHERE key = 'schema_version'"
            )
            connection.execute("COMMIT")
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    @staticmethod
    def _migrate_v4_to_v5(connection: sqlite3.Connection) -> None:
        """Add cryptographic TrustScan permits and scan bindings."""

        private_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
        now = _timestamp(datetime.now(timezone.utc))
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO service_secrets(key, value, created_at)
                VALUES ('trustscan_ed25519_private_key_v1', ?, ?)
                """,
                (private_key, now),
            )
            connection.execute(
                """
                CREATE TABLE scan_permits (
                    permit_id TEXT PRIMARY KEY,
                    organization_id TEXT NOT NULL,
                    authorization_id TEXT NOT NULL,
                    authorization_sha256 TEXT NOT NULL,
                    target TEXT NOT NULL,
                    issued_by TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    permit_sha256 TEXT NOT NULL UNIQUE,
                    signing_key_id TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    revoked_at TEXT,
                    revoked_by TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX idx_scan_permits_organization
                ON scan_permits(organization_id, issued_at DESC, permit_id DESC)
                """
            )
            connection.execute(
                """
                CREATE INDEX idx_scan_permits_authorization
                ON scan_permits(organization_id, authorization_id, expires_at)
                """
            )
            connection.execute(
                """
                CREATE TABLE job_permits (
                    job_id TEXT PRIMARY KEY,
                    permit_id TEXT NOT NULL,
                    permit_sha256 TEXT NOT NULL,
                    FOREIGN KEY (job_id) REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
                    FOREIGN KEY (permit_id) REFERENCES scan_permits(permit_id)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX idx_job_permits_permit
                ON job_permits(permit_id, job_id)
                """
            )
            connection.execute(
                """
                CREATE TABLE schedule_permits (
                    schedule_id TEXT PRIMARY KEY,
                    permit_id TEXT NOT NULL,
                    permit_sha256 TEXT NOT NULL,
                    FOREIGN KEY (schedule_id) REFERENCES scan_schedules(schedule_id) ON DELETE CASCADE,
                    FOREIGN KEY (permit_id) REFERENCES scan_permits(permit_id)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX idx_schedule_permits_permit
                ON schedule_permits(permit_id, schedule_id)
                """
            )
            connection.execute(
                "UPDATE service_metadata SET value = '5' WHERE key = 'schema_version'"
            )
            connection.execute("COMMIT")
        except sqlite3.Error:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    def trustscan_signing_private_key(self) -> bytes:
        """Return the externally stored private Ed25519 signing seed."""

        return self._service_secrets.trustscan_signing_private_key

    @staticmethod
    def _permit_from_row(row: sqlite3.Row) -> PersistedTrustScanPermit:
        try:
            permit = load_signed_trustscan_permit_json(row["document_json"])
        except ValueError as exc:
            raise JobStoreError(
                "trustscan_permit_document_invalid",
                "Persisted TrustScan permit document is invalid.",
            ) from exc
        revoked_at = _parse_timestamp(row["revoked_at"])
        return PersistedTrustScanPermit(
            permit=permit,
            revoked_at=revoked_at,
            revoked_by=row["revoked_by"],
        )

    def create_scan_permit(self, permit: SignedTrustScanPermit) -> PersistedTrustScanPermit:
        """Persist one signed immutable TrustScan permit."""

        claims = permit.claims
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO scan_permits(
                    permit_id, organization_id, authorization_id, authorization_sha256,
                    target, issued_by, issued_at, not_before, expires_at, permit_sha256,
                    signing_key_id, document_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claims.permit_id,
                    claims.organization_id,
                    claims.authorization_id,
                    claims.authorization_sha256,
                    claims.target,
                    claims.issued_by,
                    _timestamp(claims.issued_at),
                    _timestamp(claims.not_before),
                    _timestamp(claims.expires_at),
                    permit.fingerprint,
                    permit.signing_key_id,
                    permit.to_json(),
                ),
            )
            row = connection.execute(
                "SELECT * FROM scan_permits WHERE permit_id = ?",
                (claims.permit_id,),
            ).fetchone()
            connection.execute("COMMIT")
            assert row is not None
            return self._permit_from_row(row)
        except sqlite3.IntegrityError as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "trustscan_permit_conflict",
                "TrustScan permit conflicts with an existing permit.",
            ) from exc
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "trustscan_permit_create_failed",
                "Unable to persist the TrustScan permit.",
            ) from exc
        finally:
            connection.close()

    def get_scan_permit(self, permit_id: str) -> PersistedTrustScanPermit:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM scan_permits WHERE permit_id = ?",
                (permit_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "trustscan_permit_read_failed",
                "Unable to read the TrustScan permit.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            raise JobStoreError(
                "trustscan_permit_not_found",
                "TrustScan permit was not found.",
            )
        return self._permit_from_row(row)

    def get_scan_permit_scoped(
        self, permit_id: str, organization_id: str
    ) -> PersistedTrustScanPermit:
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        mirrors ``PostgresJobRepository.get_scan_permit_scoped``'s own
        atomic-scoping fix -- see that method's docstring."""

        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM scan_permits WHERE permit_id = ? AND organization_id = ?",
                (permit_id, organization_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "trustscan_permit_read_failed",
                "Unable to read the TrustScan permit.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            raise JobStoreError(
                "trustscan_permit_not_found",
                "TrustScan permit was not found.",
            )
        return self._permit_from_row(row)

    def revoke_scan_permit_scoped(
        self,
        permit_id: str,
        organization_id: str,
        *,
        revoked_by: str,
        now: datetime,
    ) -> PersistedTrustScanPermit:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM scan_permits WHERE permit_id = ? AND organization_id = ?",
                (permit_id, organization_id),
            ).fetchone()
            if row is None:
                raise JobStoreError(
                    "trustscan_permit_not_found",
                    "TrustScan permit was not found.",
                )
            if row["revoked_at"] is None:
                connection.execute(
                    """
                    UPDATE scan_permits
                    SET revoked_at = ?, revoked_by = ?
                    WHERE permit_id = ? AND organization_id = ? AND revoked_at IS NULL
                    """,
                    (_timestamp(now), revoked_by, permit_id, organization_id),
                )
            updated = connection.execute(
                "SELECT * FROM scan_permits WHERE permit_id = ?",
                (permit_id,),
            ).fetchone()
            connection.execute("COMMIT")
            assert updated is not None
            return self._permit_from_row(updated)
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "trustscan_permit_revoke_failed",
                "Unable to revoke the TrustScan permit.",
            ) from exc
        finally:
            connection.close()

    def get_job_permit_binding(self, job_id: str) -> tuple[str, str] | None:
        """Unscoped -- retained for internal/system callers that already
        hold an independently-verified ``job_id`` (see
        ``get_job_permit_binding_scoped`` for the customer/service-facing
        equivalent, which is what ``service.py`` must use)."""

        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT permit_id, permit_sha256 FROM job_permits WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "trustscan_job_binding_read_failed",
                "Unable to read TrustScan job permit binding.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            return None
        return row["permit_id"], row["permit_sha256"]

    def get_job_permit_binding_scoped(
        self, job_id: str, organization_id: str
    ) -> tuple[str, str] | None:
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        mirrors ``PostgresJobRepository.get_job_permit_binding_scoped``
        exactly -- ``job_permits`` has no ``organization_id`` of its own,
        so tenant scope is proven by joining to ``job_scopes`` (the
        authoritative job/organization relation in this backend) inside
        one query."""

        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT binding.permit_id, binding.permit_sha256
                FROM job_permits AS binding
                JOIN job_scopes AS scope ON scope.job_id = binding.job_id
                WHERE binding.job_id = ? AND scope.organization_id = ?
                """,
                (job_id, organization_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "trustscan_job_binding_read_failed",
                "Unable to read TrustScan job permit binding.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            return None
        return row["permit_id"], row["permit_sha256"]

    def get_job_safety_receipt_scoped(
        self, job_id: str, organization_id: str
    ) -> tuple[str, str] | None:
        """P1-C1: mirrors ``get_job_permit_binding_scoped``'s
        join-to-``job_scopes`` rationale exactly."""

        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT receipt.receipt_ref, receipt.receipt_sha256
                FROM job_safety_receipts AS receipt
                JOIN job_scopes AS scope ON scope.job_id = receipt.job_id
                WHERE receipt.job_id = ? AND scope.organization_id = ?
                """,
                (job_id, organization_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError("job_store_read_failed", "Unable to read TrustScan safety-receipt metadata.") from exc
        finally:
            connection.close()
        if row is None:
            return None
        return row["receipt_ref"], row["receipt_sha256"]

    def get_schedule_permit_binding(self, schedule_id: str) -> tuple[str, str] | None:
        """Unscoped -- retained for internal/system callers; see
        ``get_schedule_permit_binding_scoped`` for the customer/
        service-facing equivalent."""

        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT permit_id, permit_sha256 FROM schedule_permits WHERE schedule_id = ?",
                (schedule_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "trustscan_schedule_binding_read_failed",
                "Unable to read TrustScan schedule permit binding.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            return None
        return row["permit_id"], row["permit_sha256"]

    def get_schedule_permit_binding_scoped(
        self, schedule_id: str, organization_id: str
    ) -> tuple[str, str] | None:
        """P1-C1: ``schedule_permits`` has no ``organization_id`` of its
        own -- tenant scope is proven by joining to ``scan_schedules``
        (which carries ``organization_id`` directly in this backend,
        unlike jobs) inside one query."""

        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT binding.permit_id, binding.permit_sha256
                FROM schedule_permits AS binding
                JOIN scan_schedules AS schedules ON schedules.schedule_id = binding.schedule_id
                WHERE binding.schedule_id = ? AND schedules.organization_id = ?
                """,
                (schedule_id, organization_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "trustscan_schedule_binding_read_failed",
                "Unable to read TrustScan schedule permit binding.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            return None
        return row["permit_id"], row["permit_sha256"]

    def cursor_signing_key(self) -> bytes:
        """Return the externally stored HMAC key for opaque API cursors."""

        return self._service_secrets.cursor_signing_key

    @staticmethod
    def _schedule_from_row(row: sqlite3.Row) -> ScanScheduleRecord:
        try:
            mode = ScanJobMode(row["mode"])
            state = ScanScheduleState(row["state"])
        except (TypeError, ValueError) as exc:
            raise JobStoreError(
                "job_store_persisted_state_invalid",
                "Persisted job-store state is invalid.",
            ) from exc

        next_run_at = _parse_timestamp(row["next_run_at"])
        created_at = _parse_timestamp(row["created_at"])
        updated_at = _parse_timestamp(row["updated_at"])

        if (
            next_run_at is None
            or created_at is None
            or updated_at is None
        ):
            raise JobStoreError(
                "job_store_persisted_state_invalid",
                "Persisted job-store state is invalid.",
            )

        try:
            return ScanScheduleRecord(
                schedule_id=row["schedule_id"],
                organization_id=row["organization_id"],
                created_by=row["created_by"],
                name=row["name"],
                target=row["target"],
                authorization_id=row["authorization_id"],
                authorization_sha256=row["authorization_sha256"],
                mode=mode,
                interval_seconds=_persisted_integer(
                    row["interval_seconds"]
                ),
                state=state,
                created_at=created_at,
                updated_at=updated_at,
                next_run_at=next_run_at,
                revision=_persisted_integer(
                    row["revision"]
                ),
                last_enqueued_at=_parse_timestamp(
                    row["last_enqueued_at"]
                ),
                last_job_id=row["last_job_id"],
                last_error_code=row["last_error_code"],
                last_error_at=_parse_timestamp(
                    row["last_error_at"]
                ),
            )
        except (TypeError, ValueError) as exc:
            raise JobStoreError(
                "job_store_persisted_state_invalid",
                "Persisted job-store state is invalid.",
            ) from exc

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> ScanJobRecord:
        try:
            mode = ScanJobMode(row["mode"])
            state = ScanJobState(row["state"])
            result_status = (
                None
                if row["result_status"] is None
                else ScanStatus(row["result_status"])
            )
        except (TypeError, ValueError) as exc:
            raise JobStoreError(
                "job_store_persisted_state_invalid",
                "Persisted job-store state is invalid.",
            ) from exc

        submitted_at = _parse_timestamp(
            row["submitted_at"]
        )
        updated_at = _parse_timestamp(
            row["updated_at"]
        )

        if submitted_at is None or updated_at is None:
            raise JobStoreError(
                "job_store_persisted_state_invalid",
                "Persisted job-store state is invalid.",
            )

        try:
            request = ScanJobRequest(
                idempotency_key=row["idempotency_key"],
                target=row["target"],
                authorization_id=row["authorization_id"],
                authorization_sha256=row[
                    "authorization_sha256"
                ],
                mode=mode,
                submitted_at=submitted_at,
            )
        except (TypeError, ValueError) as exc:
            raise JobStoreError(
                "job_store_persisted_state_invalid",
                "Persisted job-store state is invalid.",
            ) from exc

        try:
            return ScanJobRecord(
                job_id=row["job_id"],
                request=request,
                state=state,
                updated_at=updated_at,
                revision=_persisted_integer(
                    row["revision"]
                ),
                cancellation_requested=bool(
                    row["cancellation_requested"]
                ),
                started_at=_parse_timestamp(
                    row["started_at"]
                ),
                completed_at=_parse_timestamp(
                    row["completed_at"]
                ),
                scan_id=row["scan_id"],
                result_status=result_status,
                report_ref=row["report_ref"],
                audit_ref=row["audit_ref"],
                error_code=row["error_code"],
                error_message=row["error_message"],
            )
        except (TypeError, ValueError) as exc:
            raise JobStoreError(
                "job_store_persisted_state_invalid",
                "Persisted job-store state is invalid.",
            ) from exc

    @classmethod
    def _lease_from_row(cls, row: sqlite3.Row) -> LeasedScanJob:
        expires_at = _parse_timestamp(row["lease_expires_at"])
        if (
            row["worker_id"] is None
            or row["lease_token"] is None
            or expires_at is None
        ):
            raise JobStoreError(
                "job_lease_metadata_invalid",
                "The running job does not contain complete lease metadata.",
            )
        return LeasedScanJob(
            record=cls._record_from_row(row),
            worker_id=row["worker_id"],
            lease_token=row["lease_token"],
            lease_expires_at=expires_at,
            attempt_count=_persisted_integer(
                row["attempt_count"]
            ),
        )

    @staticmethod
    def _worker_id(value: object) -> str:
        if not isinstance(value, str):
            raise JobStoreError(
                "job_worker_id_invalid",
                "worker_id must be a non-empty string.",
            )
        result = value.strip()
        if not result or len(result) > 128 or any(ord(char) < 33 or ord(char) > 126 for char in result):
            raise JobStoreError(
                "job_worker_id_invalid",
                "worker_id must contain 1 to 128 visible ASCII characters.",
            )
        return result

    @staticmethod
    def _lease_seconds(value: object) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise JobStoreError(
                "job_lease_duration_invalid",
                "lease_seconds must be numeric.",
            )
        result = float(value)
        if not 0.1 <= result <= 3600.0:
            raise JobStoreError(
                "job_lease_duration_invalid",
                "lease_seconds must be from 0.1 to 3600 seconds.",
            )
        return result

    @staticmethod
    def _maximum_attempts(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100:
            raise JobStoreError(
                "job_maximum_attempts_invalid",
                "maximum_attempts must be from 1 to 100.",
            )
        return value

    def submit(
        self,
        request: ScanJobRequest,
        *,
        job_id: str | None = None,
        organization_id: str | None = None,
        submitted_by: str | None = None,
        permit_id: str | None = None,
        permit_sha256: str | None = None,
    ) -> tuple[ScanJobRecord, bool]:
        """Insert a queued job or return the idempotent existing job."""

        if not isinstance(request, ScanJobRequest):
            raise JobStoreError(
                "job_store_request_invalid",
                "request must be a ScanJobRequest value.",
            )
        if (organization_id is None) != (submitted_by is None):
            raise JobStoreError(
                "job_scope_invalid",
                "organization_id and submitted_by must be supplied together.",
            )
        if (permit_id is None) != (permit_sha256 is None):
            raise JobStoreError(
                "trustscan_job_binding_invalid",
                "permit_id and permit_sha256 must be supplied together.",
            )
        if permit_id is not None and organization_id is None:
            raise JobStoreError(
                "trustscan_job_binding_invalid",
                "TrustScan job binding requires organization scope.",
            )
        effective_job_id = str(uuid4()) if job_id is None else job_id
        record = ScanJobRecord(
            job_id=effective_job_id,
            request=request,
            state=ScanJobState.QUEUED,
            updated_at=request.submitted_at,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM scan_jobs WHERE idempotency_key = ?",
                (request.idempotency_key,),
            ).fetchone()
            if existing is not None:
                existing_record = self._record_from_row(existing)
                if existing["request_fingerprint"] != request.fingerprint:
                    raise JobStoreError(
                        "job_idempotency_conflict",
                        "The idempotency key was already used for a different request.",
                    )
                if organization_id is not None:
                    scope = connection.execute(
                        "SELECT organization_id, submitted_by FROM job_scopes WHERE job_id = ?",
                        (existing_record.job_id,),
                    ).fetchone()
                    if scope is None or scope["organization_id"] != organization_id:
                        raise JobStoreError(
                            "job_idempotency_conflict",
                            "The idempotency key was already used outside this organization.",
                        )
                if permit_id is not None:
                    binding = connection.execute(
                        "SELECT permit_id, permit_sha256 FROM job_permits WHERE job_id = ?",
                        (existing_record.job_id,),
                    ).fetchone()
                    if (
                        binding is None
                        or binding["permit_id"] != permit_id
                        or binding["permit_sha256"] != permit_sha256
                    ):
                        raise JobStoreError(
                            "job_idempotency_conflict",
                            "The idempotency key was already used with a different TrustScan permit.",
                        )
                connection.execute("COMMIT")
                return existing_record, False
            connection.execute(
                """
                INSERT INTO scan_jobs (
                    job_id, idempotency_key, request_fingerprint,
                    target, authorization_id, authorization_sha256, mode,
                    submitted_at, state, updated_at, revision,
                    cancellation_requested
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.job_id,
                    request.idempotency_key,
                    request.fingerprint,
                    request.target,
                    request.authorization_id,
                    request.authorization_sha256,
                    request.mode.value,
                    _timestamp(request.submitted_at),
                    record.state.value,
                    _timestamp(record.updated_at),
                    record.revision,
                    0,
                ),
            )
            if organization_id is not None:
                connection.execute(
                    "INSERT INTO job_scopes(job_id, organization_id, submitted_by) VALUES (?, ?, ?)",
                    (record.job_id, organization_id, submitted_by),
                )
            if permit_id is not None:
                permit_row = connection.execute(
                    "SELECT organization_id, permit_sha256 FROM scan_permits WHERE permit_id = ?",
                    (permit_id,),
                ).fetchone()
                if (
                    permit_row is None
                    or permit_row["organization_id"] != organization_id
                    or permit_row["permit_sha256"] != permit_sha256
                ):
                    raise JobStoreError(
                        "trustscan_permit_not_found",
                        "TrustScan permit was not found for this organization.",
                    )
                connection.execute(
                    "INSERT INTO job_permits(job_id, permit_id, permit_sha256) VALUES (?, ?, ?)",
                    (record.job_id, permit_id, permit_sha256),
                )
            connection.execute("COMMIT")
            return record, True
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_submit_failed",
                "Unable to persist the scan job.",
            ) from exc
        finally:
            connection.close()

    def get(self, job_id: str) -> ScanJobRecord:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "job_store_read_failed",
                "Unable to read scan-job metadata.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            raise JobStoreError("job_not_found", "Scan job was not found.")
        return self._record_from_row(row)

    def get_scope(self, job_id: str) -> tuple[str, str] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT organization_id, submitted_by FROM job_scopes WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "job_store_read_failed",
                "Unable to read scan-job scope metadata.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            return None
        return row["organization_id"], row["submitted_by"]

    def get_scoped(self, job_id: str, organization_id: str) -> ScanJobRecord:
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        atomically scoped by ``organization_id`` via the same
        ``scan_jobs``/``job_scopes`` join ``list_jobs_scoped_page``
        already uses, not two separate unscoped fetches plus a
        Python-level compare -- this is the primary tenant-facing job
        lookup (``service.py`` calls it directly with a caller-supplied
        ``job_id``, and every ``_scoped`` mutation below it, e.g.
        ``request_cancellation_scoped``, relies on it failing closed)."""

        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT jobs.* FROM scan_jobs AS jobs
                JOIN job_scopes AS scope ON scope.job_id = jobs.job_id
                WHERE jobs.job_id = ? AND scope.organization_id = ?
                """,
                (job_id, organization_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "job_store_read_failed",
                "Unable to read scan-job metadata.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            raise JobStoreError("job_not_found", "Scan job was not found.")
        return self._record_from_row(row)

    def list_jobs_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        state: ScanJobState | None = None,
        mode: ScanJobMode | None = None,
    ) -> tuple[tuple[ScanJobRecord, ...], bool]:
        """List one stable descending organization job page."""

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise JobStoreError(
                "job_list_limit_invalid",
                "Job list limit must be from 1 to 100.",
            )
        clauses = ["scope.organization_id = ?"]
        parameters: list[object] = [organization_id]
        if state is not None:
            if not isinstance(state, ScanJobState):
                raise JobStoreError(
                    "job_list_state_invalid", "Job state filter is invalid."
                )
            clauses.append("jobs.state = ?")
            parameters.append(state.value)
        if mode is not None:
            if not isinstance(mode, ScanJobMode):
                raise JobStoreError(
                    "job_list_mode_invalid", "Job mode filter is invalid."
                )
            clauses.append("jobs.mode = ?")
            parameters.append(mode.value)
        if after is not None:
            if (
                not isinstance(after, tuple)
                or len(after) != 2
                or not all(isinstance(value, str) and value for value in after)
            ):
                raise JobStoreError(
                    "job_list_cursor_invalid", "Job cursor position is invalid."
                )
            clauses.append(
                "(jobs.submitted_at < ? OR "
                "(jobs.submitted_at = ? AND jobs.job_id < ?))"
            )
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        connection = self._connect()
        try:
            rows = connection.execute(
                f"""
                SELECT jobs.*
                FROM scan_jobs AS jobs
                JOIN job_scopes AS scope ON scope.job_id = jobs.job_id
                WHERE {' AND '.join(clauses)}
                ORDER BY jobs.submitted_at DESC, jobs.job_id DESC
                LIMIT ?
                """,  # noqa: S608
                tuple(parameters),
            ).fetchall()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "job_store_read_failed",
                "Unable to read organization scan jobs.",
            ) from exc
        finally:
            connection.close()
        has_more = len(rows) > limit
        selected = rows[:limit]
        return tuple(self._record_from_row(row) for row in selected), has_more

    def request_cancellation_scoped(
        self,
        job_id: str,
        organization_id: str,
        *,
        now: datetime,
    ) -> ScanJobRecord:
        self.get_scoped(job_id, organization_id)
        return self.request_cancellation(job_id, now=now)

    def organization_id_for_job(self, job_id: str) -> str | None:
        scope = self.get_scope(job_id)
        return None if scope is None else scope[0]

    @staticmethod
    def _select_claimable_row(
        connection: sqlite3.Connection,
        *,
        timestamp: str,
    ) -> sqlite3.Row | None:
        identity_ready = (
            connection.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table'
                  AND name = 'organization_authorizations'
                """
            ).fetchone()
            is not None
        )

        if identity_ready:
            return connection.execute(
                """
                SELECT jobs.*
                FROM scan_jobs AS jobs
                LEFT JOIN job_scopes AS scope
                  ON scope.job_id = jobs.job_id
                LEFT JOIN job_permits AS binding
                  ON binding.job_id = jobs.job_id
                WHERE jobs.state = ?
                  AND jobs.cancellation_requested = 0
                  AND (
                    scope.job_id IS NULL
                    OR EXISTS (
                        SELECT 1
                        FROM organization_authorizations AS assignment
                        WHERE assignment.organization_id = scope.organization_id
                          AND assignment.authorization_id = jobs.authorization_id
                    )
                  )
                  AND (
                    binding.permit_id IS NULL
                    OR (
                        EXISTS (
                            SELECT 1
                            FROM scan_permits AS permit
                            WHERE permit.permit_id = binding.permit_id
                              AND permit.permit_sha256 = binding.permit_sha256
                              AND permit.revoked_at IS NULL
                              AND permit.not_before <= ?
                              AND ? < permit.expires_at
                        )
                        AND NOT EXISTS (
                            SELECT 1
                            FROM scan_jobs AS running
                            JOIN job_permits AS running_binding
                              ON running_binding.job_id = running.job_id
                            WHERE running.state = 'running'
                              AND running_binding.permit_id = binding.permit_id
                        )
                    )
                  )
                ORDER BY jobs.submitted_at, jobs.job_id
                LIMIT 1
                """,
                (ScanJobState.QUEUED.value, timestamp, timestamp),
            ).fetchone()

        return connection.execute(
            """
            SELECT jobs.*
            FROM scan_jobs AS jobs
            LEFT JOIN job_permits AS binding
              ON binding.job_id = jobs.job_id
            WHERE jobs.state = ?
              AND jobs.cancellation_requested = 0
              AND (
                binding.permit_id IS NULL
                OR (
                    EXISTS (
                        SELECT 1
                        FROM scan_permits AS permit
                        WHERE permit.permit_id = binding.permit_id
                          AND permit.permit_sha256 = binding.permit_sha256
                          AND permit.revoked_at IS NULL
                          AND permit.not_before <= ?
                          AND ? < permit.expires_at
                    )
                    AND NOT EXISTS (
                        SELECT 1
                        FROM scan_jobs AS running
                        JOIN job_permits AS running_binding
                          ON running_binding.job_id = running.job_id
                        WHERE running.state = 'running'
                          AND running_binding.permit_id = binding.permit_id
                    )
                )
              )
            ORDER BY jobs.submitted_at, jobs.job_id
            LIMIT 1
            """,
            (ScanJobState.QUEUED.value, timestamp, timestamp),
        ).fetchone()

    def claim_next(self, *, now: datetime) -> ScanJobRecord | None:
        select_timestamp = _timestamp(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._select_claimable_row(
                connection,
                timestamp=select_timestamp,
            )
            if row is None:
                connection.execute("COMMIT")
                return None
            # See _no_earlier_than's own docstring: `now` was read
            # before this call could even try to acquire SQLite's
            # write lock, so the row this select just found can belong
            # to a submission that raced ahead of it and committed a
            # later submitted_at first.
            row_submitted_at = _parse_timestamp(row["submitted_at"])
            claim_timestamp = _timestamp(
                now if row_submitted_at is None else _no_earlier_than(now, row_submitted_at)
            )
            revision = _persisted_integer(
                row["revision"]
            ) + 1
            updated = connection.execute(
                """
                UPDATE scan_jobs
                SET state = ?, started_at = ?, updated_at = ?, revision = ?
                WHERE job_id = ? AND state = ? AND revision = ?
                """,
                (
                    ScanJobState.RUNNING.value,
                    claim_timestamp,
                    claim_timestamp,
                    revision,
                    row["job_id"],
                    ScanJobState.QUEUED.value,
                    row["revision"],
                ),
            )
            if updated.rowcount != 1:
                connection.execute("ROLLBACK")
                return None
            claimed = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (row["job_id"],),
            ).fetchone()
            connection.execute("COMMIT")
            assert claimed is not None
            return self._record_from_row(claimed)
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_claim_failed",
                "Unable to claim the next scan job.",
            ) from exc
        finally:
            connection.close()

    def claim_next_leased(
        self,
        *,
        now: datetime,
        worker_id: str,
        lease_seconds: float,
    ) -> LeasedScanJob | None:
        """Atomically claim the oldest queued job with a fenced worker lease."""

        effective_worker_id = self._worker_id(worker_id)
        duration = self._lease_seconds(lease_seconds)
        select_timestamp = _timestamp(now)
        lease_token = str(uuid4())
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._select_claimable_row(
                connection,
                timestamp=select_timestamp,
            )
            if row is None:
                connection.execute("COMMIT")
                return None
            # See _no_earlier_than's own docstring: `now` was read
            # before this call could even try to acquire SQLite's
            # write lock, so the row this select just found can belong
            # to a submission that raced ahead of it and committed a
            # later submitted_at first. The lease itself is derived
            # from the same floored moment, so a job's lease always
            # runs lease_seconds from when it could actually have
            # started, not from a stale pre-lock-wait reading.
            row_submitted_at = _parse_timestamp(row["submitted_at"])
            claim_now = now if row_submitted_at is None else _no_earlier_than(now, row_submitted_at)
            claim_timestamp = _timestamp(claim_now)
            expires_text = _timestamp(claim_now + timedelta(seconds=duration))
            revision = _persisted_integer(
                row["revision"]
            ) + 1
            updated = connection.execute(
                """
                UPDATE scan_jobs
                SET state = ?, started_at = ?, updated_at = ?, revision = ?,
                    worker_id = ?, lease_token = ?, lease_expires_at = ?,
                    heartbeat_at = ?, attempt_count = attempt_count + 1
                WHERE job_id = ? AND state = ? AND revision = ?
                """,
                (
                    ScanJobState.RUNNING.value,
                    claim_timestamp,
                    claim_timestamp,
                    revision,
                    effective_worker_id,
                    lease_token,
                    expires_text,
                    claim_timestamp,
                    row["job_id"],
                    ScanJobState.QUEUED.value,
                    row["revision"],
                ),
            )
            if updated.rowcount != 1:
                connection.execute("ROLLBACK")
                return None
            claimed = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (row["job_id"],),
            ).fetchone()
            connection.execute("COMMIT")
            assert claimed is not None
            return self._lease_from_row(claimed)
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_claim_failed",
                "Unable to claim the next scan job with a worker lease.",
            ) from exc
        finally:
            connection.close()

    def renew_lease(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_token: str,
        now: datetime,
        lease_seconds: float,
    ) -> LeasedScanJob:
        """Extend one unexpired lease owned by the same worker and token."""

        effective_worker_id = self._worker_id(worker_id)
        duration = self._lease_seconds(lease_seconds)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobStoreError("job_not_found", "Scan job was not found.")
            self._require_active_lease(
                row,
                worker_id=effective_worker_id,
                lease_token=lease_token,
                now=now,
            )
            # See _no_earlier_than's own docstring. This row is already
            # RUNNING, so its existing updated_at is already >=
            # submitted_at; flooring here defends the same invariant
            # against the same class of stale-`now` race, not a defect
            # specific to renewal.
            row_submitted_at = _parse_timestamp(row["submitted_at"])
            renew_now = now if row_submitted_at is None else _no_earlier_than(now, row_submitted_at)
            timestamp = _timestamp(renew_now)
            expires_text = _timestamp(renew_now + timedelta(seconds=duration))
            revision = _persisted_integer(row["revision"]) + 1
            updated = connection.execute(
                """
                UPDATE scan_jobs
                SET heartbeat_at = ?, lease_expires_at = ?,
                    updated_at = ?, revision = ?
                WHERE job_id = ? AND state = ? AND revision = ?
                    AND worker_id = ? AND lease_token = ?
                """,
                (
                    timestamp,
                    expires_text,
                    timestamp,
                    revision,
                    job_id,
                    ScanJobState.RUNNING.value,
                    row["revision"],
                    effective_worker_id,
                    lease_token,
                ),
            )
            if updated.rowcount != 1:
                raise JobStoreError(
                    "job_lease_lost",
                    "The worker lease is no longer current.",
                )
            renewed = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            connection.execute("COMMIT")
            assert renewed is not None
            return self._lease_from_row(renewed)
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_lease_renew_failed",
                "Unable to renew the worker lease.",
            ) from exc
        finally:
            connection.close()

    def recover_expired_leases(
        self,
        *,
        now: datetime,
        maximum_attempts: int,
    ) -> LeaseRecoverySummary:
        """Requeue, cancel, or fail running jobs whose worker lease expired."""

        limit = self._maximum_attempts(maximum_attempts)
        timestamp = _timestamp(now)
        requeued = cancelled = failed = 0
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT * FROM scan_jobs
                WHERE state = ?
                    AND lease_expires_at IS NOT NULL
                    AND lease_expires_at <= ?
                ORDER BY lease_expires_at, job_id
                """,
                (ScanJobState.RUNNING.value, timestamp),
            ).fetchall()
            for row in rows:
                revision = _persisted_integer(row["revision"]) + 1
                # See _no_earlier_than's own docstring. `timestamp`
                # above is the true `now` used to find expired leases
                # (a genuine elapsed-time filter, left untouched); the
                # value actually WRITTEN to this row's own timestamp
                # columns is floored to its own submitted_at instead,
                # per row, since a batch recovery sweep can touch jobs
                # submitted at different times.
                row_submitted_at = _parse_timestamp(row["submitted_at"])
                row_timestamp = (
                    timestamp
                    if row_submitted_at is None
                    else _timestamp(_no_earlier_than(now, row_submitted_at))
                )
                common = (
                    row_timestamp,
                    revision,
                    row["job_id"],
                    ScanJobState.RUNNING.value,
                    row["revision"],
                    row["lease_token"],
                )
                if _persisted_boolean(row["cancellation_requested"]):
                    result = connection.execute(
                        """
                        UPDATE scan_jobs
                        SET state = ?, completed_at = ?, updated_at = ?,
                            revision = ?, worker_id = NULL, lease_token = NULL,
                            lease_expires_at = NULL, heartbeat_at = NULL
                        WHERE job_id = ? AND state = ? AND revision = ?
                            AND lease_token = ?
                        """,
                        (ScanJobState.CANCELLED.value, row_timestamp, *common),
                    )
                    cancelled += result.rowcount
                elif _persisted_integer(row["attempt_count"]) >= limit:
                    result = connection.execute(
                        """
                        UPDATE scan_jobs
                        SET state = ?, completed_at = ?, updated_at = ?,
                            revision = ?, worker_id = NULL, lease_token = NULL,
                            lease_expires_at = NULL, heartbeat_at = NULL,
                            error_code = ?, error_message = ?
                        WHERE job_id = ? AND state = ? AND revision = ?
                            AND lease_token = ?
                        """,
                        (
                            ScanJobState.FAILED.value,
                            row_timestamp,
                            row_timestamp,
                            revision,
                            "worker_lease_attempts_exhausted",
                            "The scan job exceeded the permitted worker recovery attempts.",
                            row["job_id"],
                            ScanJobState.RUNNING.value,
                            row["revision"],
                            row["lease_token"],
                        ),
                    )
                    failed += result.rowcount
                else:
                    result = connection.execute(
                        """
                        UPDATE scan_jobs
                        SET state = ?, started_at = NULL, updated_at = ?,
                            revision = ?, worker_id = NULL, lease_token = NULL,
                            lease_expires_at = NULL, heartbeat_at = NULL
                        WHERE job_id = ? AND state = ? AND revision = ?
                            AND lease_token = ?
                        """,
                        (
                            ScanJobState.QUEUED.value,
                            row_timestamp,
                            revision,
                            row["job_id"],
                            ScanJobState.RUNNING.value,
                            row["revision"],
                            row["lease_token"],
                        ),
                    )
                    requeued += result.rowcount
            connection.execute("COMMIT")
            return LeaseRecoverySummary(
                requeued=requeued,
                cancelled=cancelled,
                failed=failed,
            )
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_lease_recovery_failed",
                "Unable to recover expired worker leases.",
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _require_active_lease(
        row: sqlite3.Row,
        *,
        worker_id: str,
        lease_token: str,
        now: datetime,
    ) -> None:
        if (
            row["state"] != ScanJobState.RUNNING.value
            or row["worker_id"] != worker_id
            or row["lease_token"] != lease_token
        ):
            raise JobStoreError(
                "job_lease_lost",
                "The worker lease is no longer current.",
            )
        expires_at = _parse_timestamp(row["lease_expires_at"])
        if expires_at is None or expires_at <= now.astimezone(timezone.utc):
            raise JobStoreError(
                "job_lease_expired",
                "The worker lease has expired.",
            )

    def request_cancellation(
        self,
        job_id: str,
        *,
        now: datetime,
    ) -> ScanJobRecord:
        timestamp = _timestamp(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobStoreError("job_not_found", "Scan job was not found.")
            record = self._record_from_row(row)
            if record.state.is_terminal:
                connection.execute("COMMIT")
                return record
            revision = record.revision + 1
            if record.state is ScanJobState.QUEUED:
                connection.execute(
                    """
                    UPDATE scan_jobs
                    SET state = ?, cancellation_requested = 1,
                        completed_at = ?, updated_at = ?, revision = ?
                    WHERE job_id = ? AND revision = ?
                    """,
                    (
                        ScanJobState.CANCELLED.value,
                        timestamp,
                        timestamp,
                        revision,
                        job_id,
                        record.revision,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE scan_jobs
                    SET cancellation_requested = 1,
                        updated_at = ?, revision = ?
                    WHERE job_id = ? AND revision = ?
                    """,
                    (timestamp, revision, job_id, record.revision),
                )
            updated = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            connection.execute("COMMIT")
            assert updated is not None
            return self._record_from_row(updated)
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_cancel_failed",
                "Unable to request scan-job cancellation.",
            ) from exc
        finally:
            connection.close()

    def is_cancellation_requested(self, job_id: str) -> bool:
        return self.get(job_id).cancellation_requested

    def finish_result(
        self,
        job_id: str,
        *,
        scan_id: str,
        result_status: ScanStatus,
        report_ref: str,
        audit_ref: str,
        now: datetime,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> ScanJobRecord:
        state_by_status = {
            ScanStatus.COMPLETED: ScanJobState.COMPLETED,
            ScanStatus.COMPLETED_WITH_ERRORS: ScanJobState.COMPLETED_WITH_ERRORS,
            ScanStatus.FAILED: ScanJobState.FAILED,
            ScanStatus.CANCELLED: ScanJobState.CANCELLED,
        }
        try:
            state = state_by_status[result_status]
        except KeyError as exc:
            raise JobStoreError(
                "job_store_result_status_invalid",
                "Queued or running scan results cannot finish a job.",
            ) from exc
        return self._terminal_update(
            job_id,
            state=state,
            now=now,
            scan_id=scan_id,
            result_status=result_status,
            report_ref=report_ref,
            audit_ref=audit_ref,
            safety_receipt_ref=safety_receipt_ref,
            safety_receipt_sha256=safety_receipt_sha256,
        )

    def finish_result_leased(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_token: str,
        scan_id: str,
        result_status: ScanStatus,
        report_ref: str,
        audit_ref: str,
        now: datetime,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> ScanJobRecord:
        state_by_status = {
            ScanStatus.COMPLETED: ScanJobState.COMPLETED,
            ScanStatus.COMPLETED_WITH_ERRORS: ScanJobState.COMPLETED_WITH_ERRORS,
            ScanStatus.FAILED: ScanJobState.FAILED,
            ScanStatus.CANCELLED: ScanJobState.CANCELLED,
        }
        try:
            state = state_by_status[result_status]
        except KeyError as exc:
            raise JobStoreError(
                "job_store_result_status_invalid",
                "Queued or running scan results cannot finish a job.",
            ) from exc
        return self._terminal_update(
            job_id,
            state=state,
            now=now,
            worker_id=worker_id,
            lease_token=lease_token,
            scan_id=scan_id,
            result_status=result_status,
            report_ref=report_ref,
            audit_ref=audit_ref,
            safety_receipt_ref=safety_receipt_ref,
            safety_receipt_sha256=safety_receipt_sha256,
        )

    def complete(
        self,
        job_id: str,
        *,
        state: ScanJobState,
        scan_id: str,
        result_status: ScanStatus,
        report_ref: str,
        audit_ref: str,
        now: datetime,
    ) -> ScanJobRecord:
        if state not in {
            ScanJobState.COMPLETED,
            ScanJobState.COMPLETED_WITH_ERRORS,
        }:
            raise JobStoreError(
                "job_store_completion_state_invalid",
                "Completed jobs require a completed job state.",
            )
        expected = {
            ScanJobState.COMPLETED: ScanStatus.COMPLETED,
            ScanJobState.COMPLETED_WITH_ERRORS: ScanStatus.COMPLETED_WITH_ERRORS,
        }[state]
        if result_status is not expected:
            raise JobStoreError(
                "job_store_completion_status_mismatch",
                "Job completion state and scan status do not match.",
            )
        return self.finish_result(
            job_id,
            scan_id=scan_id,
            result_status=result_status,
            report_ref=report_ref,
            audit_ref=audit_ref,
            now=now,
        )

    def fail(
        self,
        job_id: str,
        *,
        error_code: str,
        error_message: str,
        now: datetime,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> ScanJobRecord:
        return self._terminal_update(
            job_id,
            state=ScanJobState.FAILED,
            now=now,
            error_code=error_code,
            error_message=error_message,
            safety_receipt_ref=safety_receipt_ref,
            safety_receipt_sha256=safety_receipt_sha256,
        )

    def cancel_running(self, job_id: str, *, now: datetime) -> ScanJobRecord:
        return self._terminal_update(
            job_id,
            state=ScanJobState.CANCELLED,
            now=now,
        )

    def fail_leased(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_token: str,
        error_code: str,
        error_message: str,
        now: datetime,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> ScanJobRecord:
        return self._terminal_update(
            job_id,
            state=ScanJobState.FAILED,
            now=now,
            worker_id=worker_id,
            lease_token=lease_token,
            error_code=error_code,
            error_message=error_message,
            safety_receipt_ref=safety_receipt_ref,
            safety_receipt_sha256=safety_receipt_sha256,
        )

    def cancel_running_leased(
        self,
        job_id: str,
        *,
        worker_id: str,
        lease_token: str,
        now: datetime,
    ) -> ScanJobRecord:
        return self._terminal_update(
            job_id,
            state=ScanJobState.CANCELLED,
            now=now,
            worker_id=worker_id,
            lease_token=lease_token,
        )

    def _terminal_update(
        self,
        job_id: str,
        *,
        state: ScanJobState,
        now: datetime,
        worker_id: str | None = None,
        lease_token: str | None = None,
        scan_id: str | None = None,
        result_status: ScanStatus | None = None,
        report_ref: str | None = None,
        audit_ref: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        safety_receipt_ref: str | None = None,
        safety_receipt_sha256: str | None = None,
    ) -> ScanJobRecord:
        if (safety_receipt_ref is None) != (safety_receipt_sha256 is None):
            raise JobStoreError(
                "trustscan_safety_receipt_metadata_invalid",
                "Safety receipt reference and digest must be supplied together.",
            )
        if (worker_id is None) != (lease_token is None):
            raise JobStoreError(
                "job_lease_credentials_invalid",
                "worker_id and lease_token must be supplied together.",
            )
        effective_worker_id = (
            None if worker_id is None else self._worker_id(worker_id)
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise JobStoreError("job_not_found", "Scan job was not found.")
            record = self._record_from_row(row)
            if record.state is not ScanJobState.RUNNING:
                raise JobStoreError(
                    "job_state_transition_invalid",
                    "Only running jobs can enter a terminal worker state.",
                )
            # See _no_earlier_than's own docstring. ScanJobRecord also
            # requires completed_at not precede the job's start
            # boundary (started_at if set, else submitted_at); floor
            # against whichever of the two is later so both that check
            # and the updated_at/submitted_at one hold regardless of
            # whether this row's own `now` reading raced a concurrent
            # write. This row is already RUNNING, so its own
            # started_at/updated_at are already consistent with that
            # boundary; this defends the same invariant class against
            # the same stale-`now` race, not a defect specific to
            # terminal writes.
            terminal_floor = record.started_at or record.request.submitted_at
            timestamp = _timestamp(_no_earlier_than(now, terminal_floor))
            if row["lease_token"] is not None:
                if effective_worker_id is None or lease_token is None:
                    raise JobStoreError(
                        "job_lease_required",
                        "A current worker lease is required for this transition.",
                    )
                self._require_active_lease(
                    row,
                    worker_id=effective_worker_id,
                    lease_token=lease_token,
                    now=now,
                )
            elif effective_worker_id is not None:
                raise JobStoreError(
                    "job_lease_lost",
                    "The worker lease is no longer current.",
                )

            revision = record.revision + 1
            parameters = [
                state.value,
                timestamp,
                timestamp,
                revision,
                scan_id,
                None if result_status is None else result_status.value,
                report_ref,
                audit_ref,
                error_code,
                error_message,
                job_id,
                ScanJobState.RUNNING.value,
                record.revision,
            ]
            lease_predicate = ""
            if effective_worker_id is not None:
                lease_predicate = " AND worker_id = ? AND lease_token = ?"
                parameters.extend([effective_worker_id, lease_token])
            updated_count = connection.execute(
                f"""
                UPDATE scan_jobs
                SET state = ?, completed_at = ?, updated_at = ?, revision = ?,
                    scan_id = ?, result_status = ?, report_ref = ?, audit_ref = ?,
                    error_code = ?, error_message = ?, worker_id = NULL,
                    lease_token = NULL, lease_expires_at = NULL, heartbeat_at = NULL
                WHERE job_id = ? AND state = ? AND revision = ?{lease_predicate}
                """,  # noqa: S608
                tuple(parameters),
            )
            if updated_count.rowcount != 1:
                raise JobStoreError(
                    "job_lease_lost" if effective_worker_id is not None else "job_state_transition_conflict",
                    "The worker lease is no longer current."
                    if effective_worker_id is not None
                    else "The scan-job state changed before the transition completed.",
                )
            if safety_receipt_ref is not None:
                if (
                    not isinstance(safety_receipt_ref, str)
                    or not safety_receipt_ref
                    or safety_receipt_ref.startswith("/")
                    or ".." in safety_receipt_ref.split("/")
                ):
                    raise JobStoreError(
                        "trustscan_safety_receipt_reference_invalid",
                        "Safety receipt reference must be a safe relative path.",
                    )
                if (
                    not isinstance(safety_receipt_sha256, str)
                    or len(safety_receipt_sha256) != 64
                    or any(c not in "0123456789abcdef" for c in safety_receipt_sha256)
                ):
                    raise JobStoreError(
                        "trustscan_safety_receipt_digest_invalid",
                        "Safety receipt digest must be a lower-case SHA-256 value.",
                    )
                connection.execute(
                    "INSERT INTO job_safety_receipts(job_id, receipt_ref, receipt_sha256, created_at) VALUES (?, ?, ?, ?)",
                    (job_id, safety_receipt_ref, safety_receipt_sha256, timestamp),
                )
            updated = connection.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            connection.execute("COMMIT")
            assert updated is not None
            return self._record_from_row(updated)
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "job_store_transition_failed",
                "Unable to persist the scan-job state transition.",
            ) from exc
        finally:
            connection.close()


    def create_schedule(
        self,
        *,
        organization_id: str,
        created_by: str,
        name: str,
        target: str,
        authorization_id: str,
        authorization_sha256: str,
        mode: ScanJobMode,
        interval_seconds: int,
        starts_at: datetime,
        now: datetime,
        schedule_id: str | None = None,
        permit_id: str | None = None,
        permit_sha256: str | None = None,
    ) -> ScanScheduleRecord:
        if (permit_id is None) != (permit_sha256 is None):
            raise JobStoreError(
                "trustscan_schedule_binding_invalid",
                "permit_id and permit_sha256 must be supplied together.",
            )
        record = ScanScheduleRecord(
            schedule_id=str(uuid4()) if schedule_id is None else schedule_id,
            organization_id=organization_id,
            created_by=created_by,
            name=name,
            target=target,
            authorization_id=authorization_id,
            authorization_sha256=authorization_sha256,
            mode=mode,
            interval_seconds=interval_seconds,
            state=ScanScheduleState.ACTIVE,
            created_at=now,
            updated_at=now,
            next_run_at=starts_at,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO scan_schedules(
                    schedule_id, organization_id, created_by, name, target,
                    authorization_id, authorization_sha256, mode,
                    interval_seconds, state, created_at, updated_at,
                    next_run_at, revision, last_enqueued_at, last_job_id,
                    last_error_code, last_error_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL)
                """,
                (
                    record.schedule_id,
                    record.organization_id,
                    record.created_by,
                    record.name,
                    record.target,
                    record.authorization_id,
                    record.authorization_sha256,
                    record.mode.value,
                    record.interval_seconds,
                    record.state.value,
                    _timestamp(record.created_at),
                    _timestamp(record.updated_at),
                    _timestamp(record.next_run_at),
                    record.revision,
                ),
            )
            if permit_id is not None:
                permit_row = connection.execute(
                    "SELECT organization_id, permit_sha256 FROM scan_permits WHERE permit_id = ?",
                    (permit_id,),
                ).fetchone()
                if (
                    permit_row is None
                    or permit_row["organization_id"] != organization_id
                    or permit_row["permit_sha256"] != permit_sha256
                ):
                    raise JobStoreError(
                        "trustscan_permit_not_found",
                        "TrustScan permit was not found for this organization.",
                    )
                connection.execute(
                    "INSERT INTO schedule_permits(schedule_id, permit_id, permit_sha256) VALUES (?, ?, ?)",
                    (record.schedule_id, permit_id, permit_sha256),
                )
            connection.execute("COMMIT")
            return record
        except sqlite3.IntegrityError as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "schedule_conflict",
                "The scan schedule conflicts with an existing record.",
            ) from exc
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "schedule_create_failed",
                "Unable to persist the scan schedule.",
            ) from exc
        finally:
            connection.close()

    def get_schedule_scoped(
        self,
        schedule_id: str,
        organization_id: str,
    ) -> ScanScheduleRecord:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT * FROM scan_schedules
                WHERE schedule_id = ? AND organization_id = ?
                """,
                (schedule_id, organization_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "schedule_read_failed",
                "Unable to read scan-schedule metadata.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            raise JobStoreError("schedule_not_found", "Scan schedule was not found.")
        return self._schedule_from_row(row)

    def list_schedules_scoped_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        state: ScanScheduleState | None = None,
        target: str | None = None,
    ) -> tuple[tuple[ScanScheduleRecord, ...], bool]:
        """List one stable descending organization schedule page."""

        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise JobStoreError(
                "schedule_list_limit_invalid",
                "Schedule list limit must be from 1 to 100.",
            )
        clauses = ["organization_id = ?"]
        parameters: list[object] = [organization_id]
        if state is not None:
            if not isinstance(state, ScanScheduleState):
                raise JobStoreError(
                    "schedule_list_state_invalid",
                    "Schedule state filter is invalid.",
                )
            clauses.append("state = ?")
            parameters.append(state.value)
        if target is not None:
            clauses.append("target = ?")
            parameters.append(target)
        if after is not None:
            if (
                not isinstance(after, tuple)
                or len(after) != 2
                or not all(isinstance(value, str) and value for value in after)
            ):
                raise JobStoreError(
                    "schedule_list_cursor_invalid",
                    "Schedule cursor position is invalid.",
                )
            clauses.append(
                "(created_at < ? OR (created_at = ? AND schedule_id < ?))"
            )
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        connection = self._connect()
        try:
            rows = connection.execute(
                f"""
                SELECT * FROM scan_schedules
                WHERE {' AND '.join(clauses)}
                ORDER BY created_at DESC, schedule_id DESC
                LIMIT ?
                """,  # noqa: S608
                tuple(parameters),
            ).fetchall()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "schedule_read_failed",
                "Unable to read scan-schedule metadata.",
            ) from exc
        finally:
            connection.close()
        has_more = len(rows) > limit
        selected = rows[:limit]
        return tuple(self._schedule_from_row(row) for row in selected), has_more

    def list_schedules_scoped(
        self,
        organization_id: str,
        *,
        limit: int = 100,
    ) -> tuple[ScanScheduleRecord, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise JobStoreError(
                "schedule_list_limit_invalid",
                "Schedule list limit must be from 1 to 1000.",
            )
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM scan_schedules
                WHERE organization_id = ?
                ORDER BY created_at, schedule_id
                LIMIT ?
                """,
                (organization_id, limit),
            ).fetchall()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "schedule_read_failed",
                "Unable to read scan-schedule metadata.",
            ) from exc
        finally:
            connection.close()
        return tuple(self._schedule_from_row(row) for row in rows)

    def pause_schedule_scoped(
        self,
        schedule_id: str,
        organization_id: str,
        *,
        now: datetime,
    ) -> ScanScheduleRecord:
        return self._set_schedule_state(
            schedule_id,
            organization_id,
            state=ScanScheduleState.PAUSED,
            now=now,
            next_run_at=None,
        )

    def resume_schedule_scoped(
        self,
        schedule_id: str,
        organization_id: str,
        *,
        now: datetime,
    ) -> ScanScheduleRecord:
        current = self.get_schedule_scoped(schedule_id, organization_id)
        return self._set_schedule_state(
            schedule_id,
            organization_id,
            state=ScanScheduleState.ACTIVE,
            now=now,
            next_run_at=now + timedelta(seconds=current.interval_seconds),
        )

    def _set_schedule_state(
        self,
        schedule_id: str,
        organization_id: str,
        *,
        state: ScanScheduleState,
        now: datetime,
        next_run_at: datetime | None,
    ) -> ScanScheduleRecord:
        timestamp = _timestamp(now)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM scan_schedules
                WHERE schedule_id = ? AND organization_id = ?
                """,
                (schedule_id, organization_id),
            ).fetchone()
            if row is None:
                raise JobStoreError("schedule_not_found", "Scan schedule was not found.")
            revision = _persisted_integer(row["revision"]) + 1
            effective_next = row["next_run_at"] if next_run_at is None else _timestamp(next_run_at)
            connection.execute(
                """
                UPDATE scan_schedules
                SET state = ?, updated_at = ?, next_run_at = ?, revision = ?,
                    last_error_code = NULL, last_error_at = NULL
                WHERE schedule_id = ? AND organization_id = ? AND revision = ?
                """,
                (
                    state.value,
                    timestamp,
                    effective_next,
                    revision,
                    schedule_id,
                    organization_id,
                    row["revision"],
                ),
            )
            updated = connection.execute(
                "SELECT * FROM scan_schedules WHERE schedule_id = ?",
                (schedule_id,),
            ).fetchone()
            connection.execute("COMMIT")
            assert updated is not None
            return self._schedule_from_row(updated)
        except JobStoreError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "schedule_update_failed",
                "Unable to update the scan schedule.",
            ) from exc
        finally:
            connection.close()

    def list_due_schedules(
        self,
        *,
        now: datetime,
        limit: int = 100,
    ) -> tuple[ScanScheduleRecord, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise JobStoreError(
                "schedule_batch_limit_invalid",
                "Schedule batch limit must be from 1 to 1000.",
            )
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM scan_schedules
                WHERE state = ? AND next_run_at <= ?
                ORDER BY next_run_at, schedule_id
                LIMIT ?
                """,
                (ScanScheduleState.ACTIVE.value, _timestamp(now), limit),
            ).fetchall()
        except sqlite3.Error as exc:
            raise JobStoreError(
                "schedule_due_read_failed",
                "Unable to read due scan schedules.",
            ) from exc
        finally:
            connection.close()
        return tuple(self._schedule_from_row(row) for row in rows)

    @staticmethod
    def _next_schedule_time(
        scheduled_for: datetime,
        *,
        interval_seconds: int,
        now: datetime,
    ) -> datetime:
        interval = timedelta(seconds=interval_seconds)
        next_run = scheduled_for + interval
        if next_run > now:
            return next_run
        intervals = ((now - scheduled_for) // interval) + 1
        return scheduled_for + (interval * intervals)

    def enqueue_due_schedule(
        self,
        schedule_id: str,
        *,
        expected_revision: int,
        authorization_sha256: str,
        permit_id: str,
        permit_sha256: str,
        now: datetime,
    ) -> tuple[ScanScheduleRecord, ScanJobRecord] | None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM scan_schedules WHERE schedule_id = ?",
                (schedule_id,),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            schedule = self._schedule_from_row(row)
            if (
                schedule.state is not ScanScheduleState.ACTIVE
                or schedule.revision != expected_revision
                or schedule.next_run_at > now
            ):
                connection.execute("COMMIT")
                return None
            identity_ready = (
                connection.execute(
                    """
                    SELECT 1
                    FROM sqlite_master
                    WHERE type = 'table'
                      AND name = 'organization_authorizations'
                    """
                ).fetchone()
                is not None
            )

            if identity_ready:
                assignment = connection.execute(
                    """
                    SELECT 1
                    FROM organization_authorizations
                    WHERE organization_id = ?
                      AND authorization_id = ?
                    """,
                    (
                        schedule.organization_id,
                        schedule.authorization_id,
                    ),
                ).fetchone()

                if assignment is None:
                    connection.execute("COMMIT")
                    return None

            binding = connection.execute(
                "SELECT permit_id, permit_sha256 FROM schedule_permits WHERE schedule_id = ?",
                (schedule.schedule_id,),
            ).fetchone()
            if (
                binding is None
                or binding["permit_id"] != permit_id
                or binding["permit_sha256"] != permit_sha256
            ):
                raise JobStoreError(
                    "trustscan_schedule_binding_changed",
                    "TrustScan schedule permit binding changed before enqueue.",
                )

            permit_row = connection.execute(
                """
                SELECT permit_id
                FROM scan_permits
                WHERE permit_id = ?
                  AND organization_id = ?
                  AND permit_sha256 = ?
                  AND revoked_at IS NULL
                  AND not_before <= ?
                  AND ? < expires_at
                """,
                (
                    permit_id,
                    schedule.organization_id,
                    permit_sha256,
                    _timestamp(now),
                    _timestamp(now),
                ),
            ).fetchone()

            if permit_row is None:
                connection.execute("COMMIT")
                return None

            scheduled_for = schedule.next_run_at
            idempotency_key = (
                f"schedule:{schedule.schedule_id}:{_timestamp(scheduled_for)}"
            )
            request = ScanJobRequest(
                idempotency_key=idempotency_key,
                target=schedule.target,
                authorization_id=schedule.authorization_id,
                authorization_sha256=authorization_sha256,
                mode=schedule.mode,
                submitted_at=now,
            )
            record = ScanJobRecord(
                job_id=str(uuid4()),
                request=request,
                state=ScanJobState.QUEUED,
                updated_at=now,
            )
            connection.execute(
                """
                INSERT INTO scan_jobs(
                    job_id, idempotency_key, request_fingerprint,
                    target, authorization_id, authorization_sha256, mode,
                    submitted_at, state, updated_at, revision,
                    cancellation_requested
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.job_id,
                    request.idempotency_key,
                    request.fingerprint,
                    request.target,
                    request.authorization_id,
                    request.authorization_sha256,
                    request.mode.value,
                    _timestamp(request.submitted_at),
                    record.state.value,
                    _timestamp(record.updated_at),
                    record.revision,
                    0,
                ),
            )
            connection.execute(
                """
                INSERT INTO job_scopes(job_id, organization_id, submitted_by)
                VALUES (?, ?, ?)
                """,
                (record.job_id, schedule.organization_id, schedule.created_by),
            )
            connection.execute(
                "INSERT INTO job_permits(job_id, permit_id, permit_sha256) VALUES (?, ?, ?)",
                (record.job_id, permit_id, permit_sha256),
            )
            next_run_at = self._next_schedule_time(
                scheduled_for,
                interval_seconds=schedule.interval_seconds,
                now=now,
            )
            updated_count = connection.execute(
                """
                UPDATE scan_schedules
                SET authorization_sha256 = ?, updated_at = ?, next_run_at = ?,
                    revision = revision + 1, last_enqueued_at = ?, last_job_id = ?,
                    last_error_code = NULL, last_error_at = NULL
                WHERE schedule_id = ? AND revision = ? AND state = ?
                """,
                (
                    authorization_sha256,
                    _timestamp(now),
                    _timestamp(next_run_at),
                    _timestamp(now),
                    record.job_id,
                    schedule.schedule_id,
                    expected_revision,
                    ScanScheduleState.ACTIVE.value,
                ),
            )
            if updated_count.rowcount != 1:
                connection.execute("ROLLBACK")
                return None
            updated = connection.execute(
                "SELECT * FROM scan_schedules WHERE schedule_id = ?",
                (schedule.schedule_id,),
            ).fetchone()
            connection.execute("COMMIT")
            assert updated is not None
            return self._schedule_from_row(updated), record
        except sqlite3.IntegrityError as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "schedule_enqueue_conflict",
                "The scheduled run conflicts with an existing job.",
            ) from exc
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "schedule_enqueue_failed",
                "Unable to enqueue the scheduled scan.",
            ) from exc
        finally:
            connection.close()

    def block_due_schedule(
        self,
        schedule_id: str,
        *,
        expected_revision: int,
        error_code: str,
        now: datetime,
    ) -> ScanScheduleRecord | None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            updated_count = connection.execute(
                """
                UPDATE scan_schedules
                SET state = ?, updated_at = ?, revision = revision + 1,
                    last_error_code = ?, last_error_at = ?
                WHERE schedule_id = ? AND revision = ? AND state = ?
                """,
                (
                    ScanScheduleState.PAUSED.value,
                    _timestamp(now),
                    error_code,
                    _timestamp(now),
                    schedule_id,
                    expected_revision,
                    ScanScheduleState.ACTIVE.value,
                ),
            )
            if updated_count.rowcount != 1:
                connection.execute("COMMIT")
                return None
            row = connection.execute(
                "SELECT * FROM scan_schedules WHERE schedule_id = ?",
                (schedule_id,),
            ).fetchone()
            connection.execute("COMMIT")
            assert row is not None
            return self._schedule_from_row(row)
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise JobStoreError(
                "schedule_block_failed",
                "Unable to pause the invalid scan schedule.",
            ) from exc
        finally:
            connection.close()


__all__ = [
    "DATABASE_SCHEMA_VERSION",
    "JobStoreError",
    "LeaseRecoverySummary",
    "LeasedScanJob",
    "ScanJobStore",
]
