"""Authorization rejections must happen before any DNS lookup.

These tests instrument the real boundary: socket.getaddrinfo, the call
scope_validator.resolve_host makes. validate_target_url itself is not
patched, so a regression that moved the lookup ahead of the authorization
checks would be caught here even though it would pass a test that only
mocks validate_target_url. The control tests prove the instrument works:
a valid authorization does reach getaddrinfo, and a valid authorization
for a host that resolves to a private address is still refused afterward.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from webguard_contracts import (
    OwnedTargetAuthorization,
    ScanCoverage,
    ScanResult,
    ScanStatus,
    write_owned_target_authorization_file,
)
from webguard_scanner import cli, scope_validator

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)
AUTHORIZATION_ID = "0be715fb-e4ef-4f8d-b4b3-a1850f41b6c0"
TARGET = "https://example.com/"
PUBLIC_ANSWER = [(2, 1, 6, "", ("93.184.216.34", 443))]
PRIVATE_ANSWER = [(2, 1, 6, "", ("10.0.0.5", 443))]


def completed_result(scan_id: str) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        scan_type="passive-http-headers",
        status=ScanStatus.COMPLETED,
        target=TARGET,
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=NOW,
        completed_at=NOW,
        coverage=ScanCoverage(),
    )


class AuthorizationDnsBoundaryTests(unittest.TestCase):
    def write_authorization(
        self,
        directory: str,
        *,
        issued: timedelta = timedelta(days=-1),
        expires: timedelta = timedelta(days=30),
    ) -> Path:
        path = Path(directory) / "authorization.json"
        write_owned_target_authorization_file(
            OwnedTargetAuthorization(
                authorization_id=AUTHORIZATION_ID,
                organization="Example Ltd",
                authorized_by="Security Owner",
                target=TARGET,
                allowed_hosts=("example.com",),
                issued_at=NOW + issued,
                expires_at=NOW + expires,
                purpose="Resolver-boundary test fixture",
            ),
            path,
        )
        return path

    def run_scan(self, argv: list[str], answer=PUBLIC_ANSWER):
        """Run the real CLI with the real validator; return (code, stderr, getaddrinfo mock)."""

        lookup = MagicMock(return_value=answer)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(cli, "_utc_now", return_value=NOW), patch.object(
            scope_validator.socket, "getaddrinfo", lookup
        ), patch.object(
            cli,
            "run_passive_header_scan",
            side_effect=lambda *a, **k: completed_result(k["scan_id"]),
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(argv)
        return code, stderr.getvalue(), lookup

    def scan(self, path: Path, *extra: str, target: str = TARGET, confirm: str = AUTHORIZATION_ID):
        return [
            "scan", target,
            "--authorization-file", str(path),
            "--confirm-authorization", confirm,
            *extra,
        ]

    def assert_rejected_before_dns(self, argv: list[str], code_fragment: str) -> None:
        exit_code, stderr, lookup = self.run_scan(argv)
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED, stderr)
        self.assertIn(code_fragment, stderr)
        lookup.assert_not_called()

    def test_control_a_valid_authorization_does_reach_the_resolver(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_authorization(directory)
            output = Path(directory) / "report.json"
            exit_code, stderr, lookup = self.run_scan(self.scan(path, "--output", str(output)))
        self.assertEqual(exit_code, cli.EXIT_SUCCESS, stderr)
        lookup.assert_called_once()
        self.assertEqual(lookup.call_args.args[:2], ("example.com", 443))

    def test_control_destination_validation_still_runs_after_a_valid_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_authorization(directory)
            output = Path(directory) / "report.json"
            exit_code, stderr, lookup = self.run_scan(
                self.scan(path, "--output", str(output)), answer=PRIVATE_ANSWER
            )
            self.assertFalse(output.exists())
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("non_public_address", stderr)
        lookup.assert_called_once()

    def test_malformed_authorization_is_rejected_before_dns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorization.json"
            path.write_text("{not valid json", encoding="utf-8")
            self.assert_rejected_before_dns(self.scan(path), "owned_target_json_invalid")

    def test_expired_authorization_is_rejected_before_dns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_authorization(directory, issued=timedelta(days=-60), expires=timedelta(days=-30))
            self.assert_rejected_before_dns(self.scan(path), "owned_target_authorization_expired")

    def test_not_yet_valid_authorization_is_rejected_before_dns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_authorization(directory, issued=timedelta(days=1), expires=timedelta(days=30))
            self.assert_rejected_before_dns(self.scan(path), "owned_target_authorization_not_yet_valid")

    def test_wrong_confirmation_is_rejected_before_dns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_authorization(directory)
            self.assert_rejected_before_dns(
                self.scan(path, confirm="11111111-1111-4111-8111-111111111111"),
                "owned_target_confirmation_mismatch",
            )

    def test_target_mismatch_is_rejected_before_dns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_authorization(directory)
            self.assert_rejected_before_dns(
                self.scan(path, target="https://not-example.com/"),
                "owned_target_canonical_target_mismatch",
            )

    def test_plain_http_target_is_rejected_before_dns(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_authorization(directory)
            self.assert_rejected_before_dns(
                self.scan(path, target="http://example.com/"),
                "owned_target_https_required",
            )

    def test_the_gate_also_runs_for_preflight_only_and_crawl_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_authorization(directory, issued=timedelta(days=-60), expires=timedelta(days=-30))
            for extra in (["--preflight-only"], ["--crawl"]):
                with self.subTest(mode=extra):
                    self.assert_rejected_before_dns(
                        self.scan(path, *extra), "owned_target_authorization_expired"
                    )


if __name__ == "__main__":
    unittest.main()
