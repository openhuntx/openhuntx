"""SQLite-backed organizations, principals, API tokens, and audit events."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from uuid import uuid4

from webguard_contracts import (
    ApiTokenMetadata,
    AuditOutcome,
    Organization,
    OrganizationRole,
    OrganizationStatus,
    Principal,
    PrincipalType,
    SecurityAuditEvent,
    TenancyContractError,
)


IDENTITY_SCHEMA_VERSION = 2
DEFAULT_TOKEN_VALIDITY_DAYS = 90
MAXIMUM_TOKEN_VALIDITY_DAYS = 366
TOKEN_PREFIX = "wgt"  # noqa: S105
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32

# Slice 16: identity tokens (email verification / password reset /
# invitation) share one lifecycle shape -- high-entropy, hashed at
# rest, single-purpose, expiry-bounded, single-use, principal/org
# bound -- so they share one table with a `purpose` discriminator
# rather than three near-identical ones.
class IdentityTokenPurpose(str, Enum):
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"  # noqa: S105 - a token purpose label, not a credential
    INVITATION = "invitation"


EMAIL_VERIFICATION_TOKEN_TTL = timedelta(hours=24)
PASSWORD_RESET_TOKEN_TTL = timedelta(hours=1)
INVITATION_TOKEN_TTL = timedelta(days=7)
IDENTITY_TOKEN_PREFIX = "wgi"  # noqa: S105


class IdentityStoreError(ValueError):
    """Controlled identity, authentication, or authorization-store failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class IssuedApiToken:
    """One-time API token result; the raw token is never persisted."""

    metadata: ApiTokenMetadata
    token: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class IdentityTokenRecord:
    """Metadata for an email-verification / password-reset / invitation
    token. The raw token is never persisted -- only its hash -- and is
    returned exactly once, by whichever method just issued it."""

    token_id: str
    principal_id: str
    organization_id: str
    purpose: IdentityTokenPurpose
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None

    @property
    def is_usable(self) -> bool:
        return self.used_at is None


@dataclass(frozen=True, slots=True)
class IssuedIdentityToken:
    record: IdentityTokenRecord
    token: str = field(repr=False)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _hash_secret(secret: str, *, salt: bytes | None = None) -> str:
    effective_salt = secrets.token_bytes(16) if salt is None else salt
    digest = hashlib.scrypt(
        secret.encode("utf-8"),
        salt=effective_salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(effective_salt)}${_b64(digest)}"


def _verify_secret(secret: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_text, digest_text = encoded.split("$", 5)
        if algorithm != "scrypt":
            return False
        salt = _unb64(salt_text)
        expected = _unb64(digest_text)
        actual = hashlib.scrypt(
            secret.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def _token_parts(token: object) -> tuple[str, str]:
    if not isinstance(token, str):
        raise IdentityStoreError("api_token_invalid", "API token is invalid.")
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX or not parts[2]:
        raise IdentityStoreError("api_token_invalid", "API token is invalid.")
    try:
        metadata = ApiTokenMetadata(
            token_id=parts[1],
            organization_id="00000000-0000-0000-0000-000000000000",
            principal_id="00000000-0000-0000-0000-000000000000",
            label="validation",
            created_at=datetime(2000, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2000, 1, 2, tzinfo=timezone.utc),
        )
    except TenancyContractError as exc:
        raise IdentityStoreError("api_token_invalid", "API token is invalid.") from exc
    return metadata.token_id, parts[2]


def _parse_prefixed_secret(token: object, *, prefix: str, error_code: str) -> tuple[str, str]:
    """Generic ``{prefix}_{uuid}_{secret}`` parser shared by identity
    tokens and browser sessions (API tokens keep their own historical
    `_token_parts`, unchanged)."""

    if not isinstance(token, str):
        raise IdentityStoreError(error_code, "Token is invalid.")
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != prefix or not parts[2]:
        raise IdentityStoreError(error_code, "Token is invalid.")
    try:
        canonical = str(uuid.UUID(parts[1]))
    except (ValueError, AttributeError) as exc:
        raise IdentityStoreError(error_code, "Token is invalid.") from exc
    if canonical != parts[1]:
        raise IdentityStoreError(error_code, "Token is invalid.")
    return canonical, parts[2]


def _persisted_boolean(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, int) or value not in (0, 1):
        raise IdentityStoreError(
            'identity_persisted_state_invalid',
            'Persisted boolean values must be encoded as integer 0 or 1.',
        )
    return value == 1


class IdentityStore:
    """Persistent tenant identity and access-control metadata."""

    def __init__(self, database_path: Path) -> None:
        self.path = Path(database_path).expanduser()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "identity_store_open_failed",
                "Unable to open the identity database.",
            ) from exc
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        if not self.path.is_file():
            raise IdentityStoreError(
                "identity_database_missing",
                (
                    "Initialize the scan-job database before "
                    "the identity store."
                ),
            )

        connection = self._connect()

        try:
            connection.execute("BEGIN IMMEDIATE")

            required_tables = {
                "identity_metadata",
                "organizations",
                "principals",
                "api_tokens",
                "organization_authorizations",
                "security_audit_events",
                "password_credentials",
                "identity_tokens",
                "browser_sessions",
            }

            rows = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            ).fetchall()

            existing_tables = {
                row["name"]
                for row in rows
                if row["name"] in required_tables
            }

            if not existing_tables:
                self._create_identity_schema(
                    connection
                )

            elif existing_tables != required_tables:
                raise IdentityStoreError(
                    "identity_schema_invalid",
                    (
                        "The identity-store schema does not "
                        "match its declared version."
                    ),
                )

            row = connection.execute(
                """
                SELECT value
                FROM identity_metadata
                WHERE key = 'schema_version'
                """
            ).fetchone()

            if row is None:
                raise IdentityStoreError(
                    "identity_schema_unsupported",
                    (
                        "The identity-store schema version "
                        "is missing."
                    ),
                )

            try:
                version = int(row["value"])
            except (TypeError, ValueError) as exc:
                raise IdentityStoreError(
                    "identity_schema_unsupported",
                    (
                        "The identity-store schema version "
                        "is unsupported."
                    ),
                ) from exc

            if version != IDENTITY_SCHEMA_VERSION:
                raise IdentityStoreError(
                    "identity_schema_unsupported",
                    (
                        "The identity-store schema version "
                        "is unsupported."
                    ),
                )

            self._validate_current_schema(
                connection
            )

            connection.execute("COMMIT")

        except IdentityStoreError:
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

            raise IdentityStoreError(
                "identity_initialize_failed",
                (
                    "Unable to initialize identity and "
                    "RBAC tables."
                ),
            ) from exc

        finally:
            connection.close()

        os.chmod(self.path, 0o600)

    @staticmethod
    def _create_identity_schema(
        connection: sqlite3.Connection,
    ) -> None:
        connection.execute(
            """
            CREATE TABLE identity_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE organizations (
                organization_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                name_key TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE principals (
                principal_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                display_name TEXT NOT NULL,
                principal_type TEXT NOT NULL,
                role TEXT NOT NULL,
                active INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                email TEXT UNIQUE,
                email_verified_at TEXT,
                last_login_at TEXT,
                FOREIGN KEY (organization_id)
                    REFERENCES organizations(
                        organization_id
                    )
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX idx_principals_organization
            ON principals(
                organization_id,
                active,
                role
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE password_credentials (
                principal_id TEXT PRIMARY KEY,
                algorithm TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (principal_id)
                    REFERENCES principals(principal_id)
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE identity_tokens (
                token_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                purpose TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                FOREIGN KEY (principal_id)
                    REFERENCES principals(principal_id),
                FOREIGN KEY (organization_id)
                    REFERENCES organizations(organization_id)
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX idx_identity_tokens_principal
            ON identity_tokens(
                principal_id,
                purpose,
                used_at
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE browser_sessions (
                session_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                csrf_hash TEXT NOT NULL,
                assurance_level TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                idle_expires_at TEXT NOT NULL,
                absolute_expires_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                user_agent TEXT,
                ip_address TEXT,
                FOREIGN KEY (principal_id)
                    REFERENCES principals(principal_id),
                FOREIGN KEY (organization_id)
                    REFERENCES organizations(organization_id)
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX idx_browser_sessions_principal
            ON browser_sessions(
                principal_id,
                revoked_at
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE api_tokens (
                token_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                label TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                last_used_at TEXT,
                FOREIGN KEY (organization_id)
                    REFERENCES organizations(
                        organization_id
                    ),
                FOREIGN KEY (principal_id)
                    REFERENCES principals(
                        principal_id
                    )
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX idx_api_tokens_principal
            ON api_tokens(
                principal_id,
                revoked_at,
                expires_at
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE organization_authorizations (
                organization_id TEXT NOT NULL,
                authorization_id TEXT NOT NULL,
                assigned_by TEXT NOT NULL,
                assigned_at TEXT NOT NULL,
                PRIMARY KEY (
                    organization_id,
                    authorization_id
                ),
                FOREIGN KEY (organization_id)
                    REFERENCES organizations(
                        organization_id
                    ),
                FOREIGN KEY (assigned_by)
                    REFERENCES principals(
                        principal_id
                    )
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE security_audit_events (
                event_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                token_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                outcome TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                detail_code TEXT,
                FOREIGN KEY (organization_id)
                    REFERENCES organizations(
                        organization_id
                    ),
                FOREIGN KEY (principal_id)
                    REFERENCES principals(
                        principal_id
                    )
                -- Slice 16: token_id is no longer always an api_tokens
                -- row -- it is a browser_sessions.session_id for
                -- session-authenticated actions, or a fresh, otherwise-
                -- unused UUID for the handful of identity events that
                -- happen before a session exists or after one has
                -- already been consumed (see
                -- WebGuardJobService._audit_identity_event). A foreign
                -- key naming one specific credential table is no longer
                -- a correct constraint for this column.
            )
            """
        )

        connection.execute(
            """
            CREATE INDEX idx_security_audit_org_time
            ON security_audit_events(
                organization_id,
                occurred_at DESC,
                event_id DESC
            )
            """
        )

        connection.execute(
            """
            INSERT INTO identity_metadata(
                key,
                value
            )
            VALUES ('schema_version', ?)
            """,
            (str(IDENTITY_SCHEMA_VERSION),),
        )

    @staticmethod
    def _validate_current_schema(
        connection: sqlite3.Connection,
    ) -> None:
        required_columns = {
            "identity_metadata": {
                "key",
                "value",
            },
            "organizations": {
                "organization_id",
                "name",
                "name_key",
                "status",
                "created_at",
            },
            "principals": {
                "principal_id",
                "organization_id",
                "display_name",
                "principal_type",
                "role",
                "active",
                "created_at",
                "email",
                "email_verified_at",
                "last_login_at",
            },
            "api_tokens": {
                "token_id",
                "organization_id",
                "principal_id",
                "label",
                "secret_hash",
                "created_at",
                "expires_at",
                "revoked_at",
                "last_used_at",
            },
            "organization_authorizations": {
                "organization_id",
                "authorization_id",
                "assigned_by",
                "assigned_at",
            },
            "security_audit_events": {
                "event_id",
                "request_id",
                "organization_id",
                "principal_id",
                "token_id",
                "action",
                "resource_type",
                "resource_id",
                "outcome",
                "occurred_at",
                "detail_code",
            },
            "password_credentials": {
                "principal_id",
                "algorithm",
                "password_hash",
                "created_at",
                "updated_at",
            },
            "identity_tokens": {
                "token_id",
                "principal_id",
                "organization_id",
                "purpose",
                "secret_hash",
                "created_at",
                "expires_at",
                "used_at",
            },
            "browser_sessions": {
                "session_id",
                "principal_id",
                "organization_id",
                "secret_hash",
                "csrf_hash",
                "assurance_level",
                "issued_at",
                "idle_expires_at",
                "absolute_expires_at",
                "last_used_at",
                "revoked_at",
                "user_agent",
                "ip_address",
            },
        }

        for table_name, expected in required_columns.items():
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
                raise IdentityStoreError(
                    "identity_schema_invalid",
                    (
                        "The identity-store schema does not "
                        "match its declared version."
                    ),
                )

        required_indexes = {
            "idx_principals_organization",
            "idx_api_tokens_principal",
            "idx_security_audit_org_time",
            "idx_identity_tokens_principal",
            "idx_browser_sessions_principal",
        }

        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index'
            """
        ).fetchall()

        indexes = {
            row["name"]
            for row in rows
        }

        if not required_indexes.issubset(indexes):
            raise IdentityStoreError(
                "identity_schema_invalid",
                (
                    "The identity-store schema does not "
                    "match its declared version."
                ),
            )

    @staticmethod
    def _persisted_timestamp(
        value: object,
        *,
        required: bool,
    ):
        try:
            parsed = _parse_timestamp(value)
        except (TypeError, ValueError) as exc:
            raise IdentityStoreError(
                "identity_persisted_state_invalid",
                "Persisted identity-store state is invalid.",
            ) from exc

        if required and parsed is None:
            raise IdentityStoreError(
                "identity_persisted_state_invalid",
                "Persisted identity-store state is invalid.",
            )

        return parsed

    @staticmethod
    def _organization(row: sqlite3.Row) -> Organization:
        try:
            created_at = IdentityStore._persisted_timestamp(
                row["created_at"],
                required=True,
            )

            return Organization(
                organization_id=row["organization_id"],
                name=row["name"],
                status=OrganizationStatus(
                    row["status"]
                ),
                created_at=created_at,
            )

        except IdentityStoreError:
            raise

        except (
            IndexError,
            TypeError,
            ValueError,
            TenancyContractError,
        ) as exc:
            raise IdentityStoreError(
                "identity_persisted_state_invalid",
                "Persisted identity-store state is invalid.",
            ) from exc

    @staticmethod
    def _principal(row: sqlite3.Row) -> Principal:
        try:
            created_at = IdentityStore._persisted_timestamp(
                row["created_at"],
                required=True,
            )

            return Principal(
                principal_id=row["principal_id"],
                organization_id=row["organization_id"],
                display_name=row["display_name"],
                principal_type=PrincipalType(
                    row["principal_type"]
                ),
                role=OrganizationRole(
                    row["role"]
                ),
                active=_persisted_boolean(row["active"]),
                created_at=created_at,
                email=row["email"],
                email_verified_at=IdentityStore._persisted_timestamp(
                    row["email_verified_at"], required=False
                ),
                last_login_at=IdentityStore._persisted_timestamp(
                    row["last_login_at"], required=False
                ),
            )

        except IdentityStoreError:
            raise

        except (
            IndexError,
            TypeError,
            ValueError,
            TenancyContractError,
        ) as exc:
            raise IdentityStoreError(
                "identity_persisted_state_invalid",
                "Persisted identity-store state is invalid.",
            ) from exc

    @staticmethod
    def _token_metadata(
        row: sqlite3.Row,
    ) -> ApiTokenMetadata:
        try:
            created_at = IdentityStore._persisted_timestamp(
                row["created_at"],
                required=True,
            )
            expires_at = IdentityStore._persisted_timestamp(
                row["expires_at"],
                required=True,
            )

            return ApiTokenMetadata(
                token_id=row["token_id"],
                organization_id=row["organization_id"],
                principal_id=row["principal_id"],
                label=row["label"],
                created_at=created_at,
                expires_at=expires_at,
                revoked_at=IdentityStore._persisted_timestamp(
                    row["revoked_at"],
                    required=False,
                ),
                last_used_at=IdentityStore._persisted_timestamp(
                    row["last_used_at"],
                    required=False,
                ),
            )

        except IdentityStoreError:
            raise

        except (
            IndexError,
            TypeError,
            ValueError,
            TenancyContractError,
        ) as exc:
            raise IdentityStoreError(
                "identity_persisted_state_invalid",
                "Persisted identity-store state is invalid.",
            ) from exc

    def create_organization(
        self,
        name: str,
        *,
        now: datetime,
        organization_id: str | None = None,
    ) -> Organization:
        value = Organization(
            organization_id=str(uuid4()) if organization_id is None else organization_id,
            name=name,
            status=OrganizationStatus.ACTIVE,
            created_at=now,
        )
        connection = self._connect()
        try:
            connection.execute(
                "INSERT INTO organizations VALUES (?, ?, ?, ?, ?)",
                (
                    value.organization_id,
                    value.name,
                    value.name.casefold(),
                    value.status.value,
                    _timestamp(value.created_at),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityStoreError(
                "organization_conflict",
                "An organization with that identifier or name already exists.",
            ) from exc
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "organization_create_failed",
                "Unable to persist the organization.",
            ) from exc
        finally:
            connection.close()
        return value

    def get_organization(self, organization_id: str) -> Organization:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM organizations WHERE organization_id = ?",
                (organization_id,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "organization_read_failed",
                "Unable to read organization metadata.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            raise IdentityStoreError("organization_not_found", "Organization was not found.")
        return self._organization(row)

    def create_principal(
        self,
        organization_id: str,
        display_name: str,
        *,
        principal_type: PrincipalType,
        role: OrganizationRole,
        now: datetime,
        principal_id: str | None = None,
        email: str | None = None,
    ) -> Principal:
        organization = self.get_organization(organization_id)
        if organization.status is not OrganizationStatus.ACTIVE:
            raise IdentityStoreError("organization_disabled", "Organization is disabled.")
        value = Principal(
            principal_id=str(uuid4()) if principal_id is None else principal_id,
            organization_id=organization.organization_id,
            display_name=display_name,
            principal_type=principal_type,
            role=role,
            active=True,
            created_at=now,
            email=email,
        )
        connection = self._connect()
        try:
            connection.execute(
                "INSERT INTO principals VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    value.principal_id,
                    value.organization_id,
                    value.display_name,
                    value.principal_type.value,
                    value.role.value,
                    1,
                    _timestamp(value.created_at),
                    value.email,
                    None,
                    None,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if value.email is not None:
                raise IdentityStoreError(
                    "principal_email_conflict",
                    "An account with that email address already exists.",
                ) from exc
            raise IdentityStoreError(
                "principal_conflict",
                "Principal already exists.",
            ) from exc
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "principal_create_failed",
                "Unable to persist the principal.",
            ) from exc
        finally:
            connection.close()
        return value

    def get_principal(self, principal_id: str) -> Principal:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM principals WHERE principal_id = ?", (principal_id,)
            ).fetchone()
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "principal_read_failed",
                "Unable to read principal metadata.",
            ) from exc
        finally:
            connection.close()
        if row is None:
            raise IdentityStoreError("principal_not_found", "Principal was not found.")
        return self._principal(row)

    def get_principal_scoped(self, principal_id: str, *, organization_id: str) -> Principal:
        principal = self.get_principal(principal_id)
        if principal.organization_id != organization_id:
            raise IdentityStoreError("principal_not_found", "Principal was not found.")
        return principal

    def list_principals(self, organization_id: str) -> tuple[Principal, ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM principals WHERE organization_id = ? ORDER BY created_at",
                (organization_id,),
            ).fetchall()
        finally:
            connection.close()
        return tuple(self._principal(row) for row in rows)

    def update_principal_role(
        self, principal_id: str, *, organization_id: str, role: OrganizationRole, now: datetime
    ) -> Principal:
        """P1-C1 (docs/audit/WEBGUARD_P1_REMEDIATION_TRACKING_2026-08.md):
        mirrors ``PostgresIdentityRepository.update_principal_role``'s
        atomic-mutation fix -- see that method's docstring."""

        principal = self.get_principal_scoped(principal_id, organization_id=organization_id)
        connection = self._connect()
        try:
            connection.execute(
                "UPDATE principals SET role = ? WHERE principal_id = ? AND organization_id = ?",
                (role.value, principal_id, organization_id),
            )
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "principal_role_update_failed", "Unable to update the principal's role."
            ) from exc
        finally:
            connection.close()
        return Principal(
            principal_id=principal.principal_id,
            organization_id=principal.organization_id,
            display_name=principal.display_name,
            principal_type=principal.principal_type,
            role=role,
            active=principal.active,
            created_at=principal.created_at,
            email=principal.email,
            email_verified_at=principal.email_verified_at,
            last_login_at=principal.last_login_at,
        )

    def set_principal_active(
        self, principal_id: str, *, organization_id: str, active: bool, now: datetime
    ) -> Principal:
        """P1-C1: mirrors ``update_principal_role``'s atomic-mutation
        fix -- see that method's docstring."""

        principal = self.get_principal_scoped(principal_id, organization_id=organization_id)
        connection = self._connect()
        try:
            connection.execute(
                "UPDATE principals SET active = ? WHERE principal_id = ? AND organization_id = ?",
                (1 if active else 0, principal_id, organization_id),
            )
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "principal_status_update_failed", "Unable to update the principal's status."
            ) from exc
        finally:
            connection.close()
        return Principal(
            principal_id=principal.principal_id,
            organization_id=principal.organization_id,
            display_name=principal.display_name,
            principal_type=principal.principal_type,
            role=principal.role,
            active=active,
            created_at=principal.created_at,
            email=principal.email,
            email_verified_at=principal.email_verified_at,
            last_login_at=principal.last_login_at,
        )

    def get_principal_by_email(self, email: str) -> Principal | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM principals WHERE email = ?", (email.strip().casefold(),)
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else self._principal(row)

    def set_principal_email_verified(self, principal_id: str, organization_id: str, *, now: datetime) -> Principal:
        del organization_id  # accepted for signature parity with PostgresIdentityRepository; unused here
        principal = self.get_principal(principal_id)
        connection = self._connect()
        try:
            connection.execute(
                "UPDATE principals SET email_verified_at = ? WHERE principal_id = ?",
                (_timestamp(now), principal_id),
            )
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "principal_email_verify_failed", "Unable to record email verification."
            ) from exc
        finally:
            connection.close()
        return Principal(
            principal_id=principal.principal_id,
            organization_id=principal.organization_id,
            display_name=principal.display_name,
            principal_type=principal.principal_type,
            role=principal.role,
            active=principal.active,
            created_at=principal.created_at,
            email=principal.email,
            email_verified_at=now,
            last_login_at=principal.last_login_at,
        )

    def touch_last_login(self, principal_id: str, organization_id: str, *, now: datetime) -> None:
        del organization_id  # accepted for signature parity with PostgresIdentityRepository; unused here
        connection = self._connect()
        try:
            connection.execute(
                "UPDATE principals SET last_login_at = ? WHERE principal_id = ?",
                (_timestamp(now), principal_id),
            )
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "principal_login_touch_failed", "Unable to record the login timestamp."
            ) from exc
        finally:
            connection.close()

    def set_password_hash(
        self, principal_id: str, organization_id: str, *, algorithm: str, password_hash: str, now: datetime
    ) -> None:
        # organization_id is accepted, not used: this table has no
        # organization_id column here either (matching Postgres's
        # schema), and SQLite has no RLS/tenant-context concept for it
        # to scope. The parameter exists only so this method's signature
        # matches PostgresIdentityRepository's, which both service.py
        # call sites rely on interchangeably regardless of backend.
        del organization_id
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO password_credentials (principal_id, algorithm, password_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(principal_id) DO UPDATE SET
                    algorithm = excluded.algorithm,
                    password_hash = excluded.password_hash,
                    updated_at = excluded.updated_at
                """,
                (principal_id, algorithm, password_hash, _timestamp(now), _timestamp(now)),
            )
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "password_credential_write_failed", "Unable to persist the password credential."
            ) from exc
        finally:
            connection.close()

    def get_password_hash(self, principal_id: str) -> str | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT password_hash FROM password_credentials WHERE principal_id = ?",
                (principal_id,),
            ).fetchone()
        finally:
            connection.close()
        return None if row is None else row["password_hash"]

    def create_identity_token(
        self,
        principal_id: str,
        organization_id: str,
        *,
        purpose: IdentityTokenPurpose,
        ttl: timedelta,
        now: datetime,
    ) -> IssuedIdentityToken:
        token_id = str(uuid4())
        secret = secrets.token_urlsafe(32)
        raw = f"{IDENTITY_TOKEN_PREFIX}_{token_id}_{secret}"
        expires_at = now + ttl
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO identity_tokens
                    (token_id, principal_id, organization_id, purpose, secret_hash, created_at, expires_at, used_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    token_id,
                    principal_id,
                    organization_id,
                    purpose.value,
                    _hash_secret(secret),
                    _timestamp(now),
                    _timestamp(expires_at),
                ),
            )
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "identity_token_create_failed", "Unable to persist the identity token."
            ) from exc
        finally:
            connection.close()
        record = IdentityTokenRecord(
            token_id=token_id,
            principal_id=principal_id,
            organization_id=organization_id,
            purpose=purpose,
            created_at=now,
            expires_at=expires_at,
        )
        return IssuedIdentityToken(record=record, token=raw)

    def consume_identity_token(
        self, token: object, *, purpose: IdentityTokenPurpose, now: datetime
    ) -> IdentityTokenRecord:
        token_id, secret = _parse_prefixed_secret(
            token, prefix=IDENTITY_TOKEN_PREFIX, error_code="identity_token_invalid"
        )
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM identity_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if row is None or not _verify_secret(secret, row["secret_hash"]):
                raise IdentityStoreError("identity_token_invalid", "Token is invalid.")
            if row["purpose"] != purpose.value:
                raise IdentityStoreError("identity_token_invalid", "Token is invalid.")
            if row["used_at"] is not None:
                raise IdentityStoreError("identity_token_used", "Token has already been used.")
            expires_at = _parse_timestamp(row["expires_at"])
            if now.astimezone(timezone.utc) >= expires_at:
                raise IdentityStoreError("identity_token_expired", "Token has expired.")
            connection.execute(
                "UPDATE identity_tokens SET used_at = ? WHERE token_id = ?",
                (_timestamp(now), token_id),
            )
        except IdentityStoreError:
            raise
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "identity_token_consume_failed", "Unable to consume the identity token."
            ) from exc
        finally:
            connection.close()
        return IdentityTokenRecord(
            token_id=str(row["token_id"]),
            principal_id=str(row["principal_id"]),
            organization_id=str(row["organization_id"]),
            purpose=IdentityTokenPurpose(row["purpose"]),
            created_at=_parse_timestamp(row["created_at"]),
            expires_at=expires_at,
            used_at=now,
        )

    def invalidate_identity_tokens(
        self, principal_id: str, organization_id: str, *, purpose: IdentityTokenPurpose, now: datetime
    ) -> None:
        del organization_id  # accepted for signature parity with PostgresIdentityRepository; unused here
        connection = self._connect()
        try:
            connection.execute(
                """
                UPDATE identity_tokens SET used_at = ?
                WHERE principal_id = ? AND purpose = ? AND used_at IS NULL
                """,
                (_timestamp(now), principal_id, purpose.value),
            )
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "identity_token_invalidate_failed", "Unable to invalidate prior identity tokens."
            ) from exc
        finally:
            connection.close()

    def list_tokens_for_principal(self, principal_id: str, organization_id: str) -> tuple[ApiTokenMetadata, ...]:
        del organization_id  # accepted for signature parity with PostgresIdentityRepository; unused here
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM api_tokens WHERE principal_id = ? ORDER BY created_at DESC",
                (principal_id,),
            ).fetchall()
        finally:
            connection.close()
        return tuple(self._token_metadata(row) for row in rows)

    def revoke_token_owned(
        self, token_id: str, organization_id: str, *, principal_id: str, now: datetime
    ) -> ApiTokenMetadata:
        del organization_id  # accepted for signature parity with PostgresIdentityRepository; unused here
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM api_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if row is None or row["principal_id"] != principal_id:
                raise IdentityStoreError("api_token_not_found", "API token was not found.")
            metadata = self._token_metadata(row)
            if metadata.revoked_at is None:
                connection.execute(
                    "UPDATE api_tokens SET revoked_at = ? WHERE token_id = ?",
                    (_timestamp(now), token_id),
                )
                metadata = ApiTokenMetadata(
                    token_id=metadata.token_id,
                    organization_id=metadata.organization_id,
                    principal_id=metadata.principal_id,
                    label=metadata.label,
                    created_at=metadata.created_at,
                    expires_at=metadata.expires_at,
                    revoked_at=now,
                    last_used_at=metadata.last_used_at,
                )
            return metadata
        except IdentityStoreError:
            raise
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "api_token_revoke_failed", "Unable to revoke the API token."
            ) from exc
        finally:
            connection.close()

    def create_token(
        self,
        principal_id: str,
        *,
        label: str,
        now: datetime,
        validity_days: int = DEFAULT_TOKEN_VALIDITY_DAYS,
        token_id: str | None = None,
    ) -> IssuedApiToken:
        if isinstance(validity_days, bool) or not isinstance(validity_days, int) or not 1 <= validity_days <= MAXIMUM_TOKEN_VALIDITY_DAYS:
            raise IdentityStoreError(
                "token_validity_invalid",
                f"Token validity must be from 1 to {MAXIMUM_TOKEN_VALIDITY_DAYS} days.",
            )
        principal = self.get_principal(principal_id)
        if not principal.active:
            raise IdentityStoreError("principal_disabled", "Principal is disabled.")
        organization = self.get_organization(principal.organization_id)
        if organization.status is not OrganizationStatus.ACTIVE:
            raise IdentityStoreError("organization_disabled", "Organization is disabled.")
        effective_id = str(uuid4()) if token_id is None else token_id
        secret = secrets.token_urlsafe(32)
        raw = f"{TOKEN_PREFIX}_{effective_id}_{secret}"
        metadata = ApiTokenMetadata(
            token_id=effective_id,
            organization_id=principal.organization_id,
            principal_id=principal.principal_id,
            label=label,
            created_at=now,
            expires_at=now + timedelta(days=validity_days),
        )
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO api_tokens (
                    token_id, organization_id, principal_id, label, secret_hash,
                    created_at, expires_at, revoked_at, last_used_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)
                """,
                (
                    metadata.token_id,
                    metadata.organization_id,
                    metadata.principal_id,
                    metadata.label,
                    _hash_secret(secret),
                    _timestamp(metadata.created_at),
                    _timestamp(metadata.expires_at),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityStoreError(
                "api_token_conflict",
                "API token already exists.",
            ) from exc
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "api_token_create_failed",
                "Unable to persist the API token.",
            ) from exc
        finally:
            connection.close()
        return IssuedApiToken(metadata=metadata, token=raw)

    def authenticate_token(self, token: object, *, now: datetime) -> tuple[ApiTokenMetadata, Principal, Organization]:
        token_id, secret = _token_parts(token)
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM api_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if row is None or not _verify_secret(secret, row["secret_hash"]):
                raise IdentityStoreError("api_token_invalid", "API token is invalid.")
            metadata = self._token_metadata(row)
            if metadata.revoked_at is not None:
                raise IdentityStoreError("api_token_revoked", "API token has been revoked.")
            if now.astimezone(timezone.utc) >= metadata.expires_at:
                raise IdentityStoreError("api_token_expired", "API token has expired.")
            principal_row = connection.execute(
                "SELECT * FROM principals WHERE principal_id = ?", (metadata.principal_id,)
            ).fetchone()
            organization_row = connection.execute(
                "SELECT * FROM organizations WHERE organization_id = ?",
                (metadata.organization_id,),
            ).fetchone()
            if principal_row is None or organization_row is None:
                raise IdentityStoreError("api_token_invalid", "API token is invalid.")
            principal = self._principal(principal_row)
            organization = self._organization(organization_row)
            if not principal.active:
                raise IdentityStoreError("principal_disabled", "Principal is disabled.")
            if organization.status is not OrganizationStatus.ACTIVE:
                raise IdentityStoreError("organization_disabled", "Organization is disabled.")
            connection.execute(
                "UPDATE api_tokens SET last_used_at = ? WHERE token_id = ?",
                (_timestamp(now), token_id),
            )
        except IdentityStoreError:
            raise
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "api_token_authentication_failed",
                "Unable to authenticate the API token.",
            ) from exc
        finally:
            connection.close()
        updated = ApiTokenMetadata(
            token_id=metadata.token_id,
            organization_id=metadata.organization_id,
            principal_id=metadata.principal_id,
            label=metadata.label,
            created_at=metadata.created_at,
            expires_at=metadata.expires_at,
            revoked_at=metadata.revoked_at,
            last_used_at=now,
        )
        return updated, principal, organization

    def revoke_token(self, token_id: str, *, now: datetime) -> ApiTokenMetadata:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM api_tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if row is None:
                raise IdentityStoreError("api_token_not_found", "API token was not found.")
            metadata = self._token_metadata(row)
            if metadata.revoked_at is None:
                connection.execute(
                    "UPDATE api_tokens SET revoked_at = ? WHERE token_id = ?",
                    (_timestamp(now), token_id),
                )
                metadata = ApiTokenMetadata(
                    token_id=metadata.token_id,
                    organization_id=metadata.organization_id,
                    principal_id=metadata.principal_id,
                    label=metadata.label,
                    created_at=metadata.created_at,
                    expires_at=metadata.expires_at,
                    revoked_at=now,
                    last_used_at=metadata.last_used_at,
                )
            return metadata
        except IdentityStoreError:
            raise
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "api_token_revoke_failed",
                "Unable to revoke the API token.",
            ) from exc
        finally:
            connection.close()

    def assign_authorization(
        self,
        organization_id: str,
        authorization_id: str,
        *,
        assigned_by: str,
        now: datetime,
    ) -> None:
        principal = self.get_principal(assigned_by)
        if principal.organization_id != organization_id:
            raise IdentityStoreError(
                "cross_tenant_assignment_rejected",
                "The assigning principal does not belong to the organization.",
            )
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT OR IGNORE INTO organization_authorizations
                    (organization_id, authorization_id, assigned_by, assigned_at)
                VALUES (?, ?, ?, ?)
                """,
                (organization_id, authorization_id, assigned_by, _timestamp(now)),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityStoreError(
                "authorization_assignment_invalid",
                "Unable to assign the authorization to the organization.",
            ) from exc
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "authorization_assignment_failed",
                "Unable to persist the authorization assignment.",
            ) from exc
        finally:
            connection.close()

    def authorization_is_assigned(self, organization_id: str, authorization_id: str) -> bool:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT 1 FROM organization_authorizations
                WHERE organization_id = ? AND authorization_id = ?
                """,
                (organization_id, authorization_id),
            ).fetchone()
            return row is not None
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "authorization_assignment_read_failed",
                "Unable to read organization authorization assignments.",
            ) from exc
        finally:
            connection.close()

    def list_assigned_authorization_ids(self, organization_id: str) -> tuple[str, ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT authorization_id FROM organization_authorizations WHERE organization_id = ?",
                (organization_id,),
            ).fetchall()
        finally:
            connection.close()
        return tuple(row["authorization_id"] for row in rows)

    def record_audit_event(self, event: SecurityAuditEvent) -> None:
        if not isinstance(event, SecurityAuditEvent):
            raise IdentityStoreError("audit_event_invalid", "event must be a SecurityAuditEvent.")
        connection = self._connect()
        try:
            connection.execute(
                """
                INSERT INTO security_audit_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.request_id,
                    event.organization_id,
                    event.principal_id,
                    event.token_id,
                    event.action,
                    event.resource_type,
                    event.resource_id,
                    event.outcome.value,
                    _timestamp(event.occurred_at),
                    event.detail_code,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise IdentityStoreError(
                "audit_event_conflict",
                "Audit event already exists.",
            ) from exc
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "audit_event_write_failed",
                "Unable to persist the security audit event.",
            ) from exc
        finally:
            connection.close()

    @staticmethod
    def _audit_event(
        row: sqlite3.Row,
    ) -> SecurityAuditEvent:
        try:
            occurred_at = IdentityStore._persisted_timestamp(
                row["occurred_at"],
                required=True,
            )

            return SecurityAuditEvent(
                event_id=row["event_id"],
                request_id=row["request_id"],
                organization_id=row["organization_id"],
                principal_id=row["principal_id"],
                token_id=row["token_id"],
                action=row["action"],
                resource_type=row["resource_type"],
                resource_id=row["resource_id"],
                outcome=AuditOutcome(
                    row["outcome"]
                ),
                occurred_at=occurred_at,
                detail_code=row["detail_code"],
            )

        except IdentityStoreError:
            raise

        except (
            IndexError,
            TypeError,
            ValueError,
            TenancyContractError,
        ) as exc:
            raise IdentityStoreError(
                "identity_persisted_state_invalid",
                "Persisted identity-store state is invalid.",
            ) from exc

    def list_audit_events_page(
        self,
        organization_id: str,
        *,
        limit: int,
        after: tuple[str, str] | None = None,
        outcome: AuditOutcome | None = None,
    ) -> tuple[tuple[SecurityAuditEvent, ...], bool]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise IdentityStoreError(
                "audit_limit_invalid", "Audit limit must be from 1 to 100."
            )
        clauses = ["organization_id = ?"]
        parameters: list[object] = [organization_id]
        if outcome is not None:
            if not isinstance(outcome, AuditOutcome):
                raise IdentityStoreError(
                    "audit_outcome_invalid", "Audit outcome filter is invalid."
                )
            clauses.append("outcome = ?")
            parameters.append(outcome.value)
        if after is not None:
            if (
                not isinstance(after, tuple)
                or len(after) != 2
                or not all(isinstance(value, str) and value for value in after)
            ):
                raise IdentityStoreError(
                    "audit_cursor_invalid", "Audit cursor position is invalid."
                )
            clauses.append(
                "(occurred_at < ? OR (occurred_at = ? AND event_id < ?))"
            )
            parameters.extend((after[0], after[0], after[1]))
        parameters.append(limit + 1)
        connection = self._connect()
        try:
            rows = connection.execute(
                f"""
                SELECT * FROM security_audit_events
                WHERE {' AND '.join(clauses)}
                ORDER BY occurred_at DESC, event_id DESC
                LIMIT ?
                """,  # noqa: S608
                tuple(parameters),
            ).fetchall()
        except sqlite3.Error as exc:
            raise IdentityStoreError(
                "audit_read_failed", "Unable to read security audit events."
            ) from exc
        finally:
            connection.close()
        has_more = len(rows) > limit
        return tuple(self._audit_event(row) for row in rows[:limit]), has_more

    def list_audit_events(self, organization_id: str, *, limit: int = 100) -> tuple[SecurityAuditEvent, ...]:
        events, _ = self.list_audit_events_page(
            organization_id,
            limit=min(limit, 100),
        )
        return events


__all__ = [
    "DEFAULT_TOKEN_VALIDITY_DAYS",
    "IDENTITY_SCHEMA_VERSION",
    "IdentityStore",
    "IdentityStoreError",
    "IssuedApiToken",
    "MAXIMUM_TOKEN_VALIDITY_DAYS",
    "TOKEN_PREFIX",
]
