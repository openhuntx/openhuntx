from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from webguard_api import AuthorizationRepository, AuthorizationRepositoryError
from webguard_contracts import write_owned_target_authorization_file

from tests.unit.service_test_support import AUTH_ID, authorization, write_authorization


class AuthorizationRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.directory = self.root / "authorizations"
        write_authorization(self.directory)
        self.repository = AuthorizationRepository(self.directory)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_loads_authorization_by_id(self) -> None:
        result = self.repository.get(AUTH_ID)
        self.assertEqual(result.organization, "InternStack")

    def test_unknown_id_is_controlled(self) -> None:
        with self.assertRaisesRegex(AuthorizationRepositoryError, "No server-side"):
            self.repository.get("b6a39765-16c6-42b4-91f0-998bf07f1912")

    def test_duplicate_id_is_rejected(self) -> None:
        second = self.directory / "second.json"
        write_owned_target_authorization_file(authorization(), second)
        os.chmod(second, 0o600)
        with self.assertRaisesRegex(AuthorizationRepositoryError, "Multiple"):
            self.repository.get(AUTH_ID)

    def test_insecure_permissions_are_rejected(self) -> None:
        path = self.directory / "example.com.json"
        os.chmod(path, 0o644)
        with self.assertRaisesRegex(AuthorizationRepositoryError, "owner-only"):
            self.repository.get(AUTH_ID)

    def test_symlink_file_is_rejected(self) -> None:
        target = self.directory / "example.com.json"
        link = self.directory / "linked.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(AuthorizationRepositoryError, "symbolic link"):
            self.repository.get(AUTH_ID)

    def test_symlink_directory_is_rejected(self) -> None:
        link = self.root / "linked-authorizations"
        link.symlink_to(self.directory, target_is_directory=True)
        repository = AuthorizationRepository(link)
        with self.assertRaisesRegex(AuthorizationRepositoryError, "symbolic link"):
            repository.get(AUTH_ID)

    def test_missing_directory_is_controlled(self) -> None:
        repository = AuthorizationRepository(self.root / "missing")
        with self.assertRaisesRegex(AuthorizationRepositoryError, "Unable to inspect"):
            repository.get(AUTH_ID)

    def test_invalid_document_is_rejected(self) -> None:
        path = self.directory / "invalid.json"
        path.write_text("{}", encoding="utf-8")
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(AuthorizationRepositoryError, "invalid"):
            self.repository.get(AUTH_ID)

    def test_non_json_file_is_ignored(self) -> None:
        (self.directory / "README.txt").write_text("not an authorization", encoding="utf-8")
        self.assertEqual(self.repository.get(AUTH_ID).authorization_id, AUTH_ID)

    def test_another_tenants_bad_document_does_not_leak_its_name_or_content(
        self,
    ) -> None:
        """Phase 6 C-2: every tenant's authorization document lives in
        this one shared directory, and get() always scans all of them
        (it must, to detect a duplicate authorization_id), regardless of
        which tenant's ID a caller is looking for. A caller looking up
        their own, perfectly valid authorization must not learn another
        tenant's filename or the reason that tenant's own document is
        invalid, purely because that other file happens to sort into the
        same scan and fail first."""

        secret_marker = "confidential-tenant-b-secret-detail"
        other_tenant_path = self.directory / "zz-other-tenant-name.json"
        other_tenant_path.write_text(
            f'{{"organization": "{secret_marker}"}}', encoding="utf-8"
        )
        os.chmod(other_tenant_path, 0o600)

        with self.assertRaises(AuthorizationRepositoryError) as caught:
            self.repository.get(AUTH_ID)

        message = caught.exception.message
        self.assertNotIn("zz-other-tenant-name", message)
        self.assertNotIn(secret_marker, message)
        self.assertNotIn(str(self.directory), message)


if __name__ == "__main__":
    unittest.main()
