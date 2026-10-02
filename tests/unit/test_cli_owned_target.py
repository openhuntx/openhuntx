from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from webguard_contracts import (
    OwnedTargetAuthorization,
    OwnedTargetLimits,
    ScanCoverage,
    ScanResult,
    ScanStatus,
    load_owned_target_audit_file,
    load_owned_target_authorization_file,
    load_scan_result_file,
    write_owned_target_authorization_file,
)
from webguard_scanner import cli
from webguard_scanner.scope_validator import ValidatedTarget


NOW = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)
AUTHORIZATION_ID = "0be715fb-e4ef-4f8d-b4b3-a1850f41b6c0"
TARGET = ValidatedTarget(
    original_url="https://example.com/",
    normalised_url="https://example.com/",
    scheme="https",
    hostname="example.com",
    port=443,
    resolved_addresses=("93.184.216.34",),
)


def completed_result(scan_id: str) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        scan_type="passive-http-headers",
        status=ScanStatus.COMPLETED,
        target=TARGET.normalised_url,
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=NOW,
        completed_at=NOW,
        coverage=ScanCoverage(),
    )


class OwnedTargetCliTests(unittest.TestCase):
    def run_cli(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli.main(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def authorization_file(
        self,
        directory: str,
        *,
        limits: OwnedTargetLimits | None = None,
    ) -> Path:
        path = Path(directory) / "authorization.json"
        write_owned_target_authorization_file(
            OwnedTargetAuthorization(
                authorization_id=AUTHORIZATION_ID,
                organization="Example Ltd",
                authorized_by="Security Owner",
                target=TARGET.normalised_url,
                allowed_hosts=(TARGET.hostname,),
                issued_at=NOW - timedelta(days=1),
                expires_at=NOW + timedelta(days=30),
                purpose="Controlled passive owned-target assessment",
                limits=OwnedTargetLimits() if limits is None else limits,
            ),
            path,
        )
        return path

    def scan_arguments(
        self,
        authorization: Path,
        *extra: str,
    ) -> list[str]:
        return [
            "scan",
            TARGET.normalised_url,
            "--authorization-file",
            str(authorization),
            "--confirm-authorization",
            AUTHORIZATION_ID,
            *extra,
        ]

    def test_external_scan_requires_authorization_file(self) -> None:
        with patch.object(cli, "validate_target_url") as validate:
            exit_code, stdout, stderr = self.run_cli(
                ["scan", TARGET.normalised_url]
            )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertEqual(stdout, "")
        self.assertIn("owned_target_authorization_required", stderr)
        validate.assert_not_called()

    def test_external_scan_requires_exact_confirmation_option(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            with patch.object(cli, "validate_target_url") as validate:
                exit_code, stdout, stderr = self.run_cli(
                    [
                        "scan",
                        TARGET.normalised_url,
                        "--authorization-file",
                        str(authorization),
                    ]
                )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertEqual(stdout, "")
        self.assertIn("owned_target_confirmation_required", stderr)
        validate.assert_not_called()

    def test_lab_mode_rejects_owned_target_options(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            with patch.object(cli, "validate_target_url") as validate:
                exit_code, _, stderr = self.run_cli(
                    [
                        "scan",
                        "http://127.0.0.1:3000/",
                        "--lab",
                        "--allow-host",
                        "127.0.0.1",
                        "--authorization-file",
                        str(authorization),
                        "--confirm-authorization",
                        AUTHORIZATION_ID,
                    ]
                )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("owned_target_option_requires_commercial_mode", stderr)
        validate.assert_not_called()

    def test_confirmation_mismatch_sends_no_scan_and_writes_no_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            output = Path(directory) / "report.json"
            audit = Path(str(output) + cli.DEFAULT_OWNED_AUDIT_SUFFIX)
            with patch.object(
                cli, "_utc_now", return_value=NOW
            ), patch.object(
                cli, "validate_target_url"
            ) as validate, patch.object(cli, "run_passive_header_scan") as scan:
                exit_code, _, stderr = self.run_cli(
                    [
                        "scan",
                        TARGET.normalised_url,
                        "--authorization-file",
                        str(authorization),
                        "--confirm-authorization",
                        "11111111-1111-4111-8111-111111111111",
                        "--output",
                        str(output),
                    ]
                )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("owned_target_confirmation_mismatch", stderr)
        self.assertFalse(output.exists())
        self.assertFalse(audit.exists())
        scan.assert_not_called()
        # The mismatch is detected from the authorization document and the
        # raw target string alone, before validate_target_url's DNS
        # resolution runs -- not just before the scan.
        validate.assert_not_called()

    def test_expired_authorization_is_rejected_before_dns_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorization.json"
            write_owned_target_authorization_file(
                OwnedTargetAuthorization(
                    authorization_id=AUTHORIZATION_ID,
                    organization="Example Ltd",
                    authorized_by="Security Owner",
                    target=TARGET.normalised_url,
                    allowed_hosts=(TARGET.hostname,),
                    issued_at=NOW - timedelta(days=60),
                    expires_at=NOW - timedelta(days=30),
                    purpose="Deliberately expired fixture for verification",
                ),
                path,
            )
            output = Path(directory) / "report.json"
            audit = Path(str(output) + cli.DEFAULT_OWNED_AUDIT_SUFFIX)

            with patch.object(
                cli, "_utc_now", return_value=NOW
            ), patch.object(
                cli, "validate_target_url"
            ) as validate, patch.object(cli, "run_passive_header_scan") as scan:
                exit_code, _, stderr = self.run_cli(
                    self.scan_arguments(path, "--output", str(output))
                )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("owned_target_authorization_expired", stderr)
        self.assertFalse(output.exists())
        self.assertFalse(audit.exists())
        scan.assert_not_called()
        validate.assert_not_called()

    def test_malformed_authorization_json_is_rejected_before_dns_resolution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorization.json"
            path.write_text("{not valid json", encoding="utf-8")
            output = Path(directory) / "report.json"

            with patch.object(
                cli, "validate_target_url"
            ) as validate, patch.object(cli, "run_passive_header_scan") as scan:
                exit_code, _, stderr = self.run_cli(
                    self.scan_arguments(path, "--output", str(output))
                )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("owned_target_json_invalid", stderr)
        self.assertFalse(output.exists())
        scan.assert_not_called()
        validate.assert_not_called()

    def test_target_mismatch_is_rejected_before_dns_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            output = Path(directory) / "report.json"
            audit = Path(str(output) + cli.DEFAULT_OWNED_AUDIT_SUFFIX)

            with patch.object(
                cli, "_utc_now", return_value=NOW
            ), patch.object(
                cli, "validate_target_url"
            ) as validate, patch.object(cli, "run_passive_header_scan") as scan:
                exit_code, _, stderr = self.run_cli(
                    [
                        "scan",
                        "https://not-example.com/",
                        "--authorization-file",
                        str(authorization),
                        "--confirm-authorization",
                        AUTHORIZATION_ID,
                        "--output",
                        str(output),
                    ]
                )

        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("owned_target_canonical_target_mismatch", stderr)
        self.assertFalse(output.exists())
        self.assertFalse(audit.exists())
        scan.assert_not_called()
        # The authorization is scoped to a different host than the one
        # being scanned, so this is rejected from the two raw URL strings
        # alone -- the mismatched target's hostname is never looked up.
        validate.assert_not_called()

    def test_preflight_only_sends_no_http_and_writes_no_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            with patch.object(
                cli, "_utc_now", return_value=NOW
            ), patch.object(
                cli, "validate_target_url", return_value=TARGET
            ), patch.object(cli, "run_passive_header_scan") as single, patch.object(
                cli, "run_passive_crawl_scan"
            ) as crawl:
                exit_code, stdout, stderr = self.run_cli(
                    self.scan_arguments(
                        authorization,
                        "--crawl",
                        "--preflight-only",
                    )
                )
                files = tuple(Path(directory).iterdir())
        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        self.assertEqual(stderr, "")
        self.assertIn("Owned-target readiness: approved", stdout)
        self.assertIn(f"Authorization ID: {AUTHORIZATION_ID}", stdout)
        self.assertIn("Mode: passive same-origin crawl", stdout)
        self.assertIn("No HTTP request was sent.", stdout)
        self.assertEqual(files, (authorization,))
        single.assert_not_called()
        crawl.assert_not_called()

    def test_preflight_only_rejects_output_options(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            output = Path(directory) / "report.json"
            exit_code, _, stderr = self.run_cli(
                self.scan_arguments(
                    authorization,
                    "--preflight-only",
                    "--output",
                    str(output),
                )
            )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("preflight_only_output_option_invalid", stderr)
        self.assertFalse(output.exists())

    def test_external_crawl_uses_conservative_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            output = Path(directory) / "report.json"
            captured: dict[str, object] = {}

            def run(_target, **kwargs):
                captured.update(kwargs)
                return completed_result(kwargs["scan_id"])

            with patch.object(
                cli, "_utc_now", return_value=NOW
            ), patch.object(
                cli, "validate_target_url", return_value=TARGET
            ), patch.object(
                cli, "run_passive_crawl_scan", side_effect=run
            ):
                exit_code, _, stderr = self.run_cli(
                    self.scan_arguments(
                        authorization,
                        "--crawl",
                        "--output",
                        str(output),
                    )
                )

            policy = captured["crawl_policy"]
            retry = captured["retry_policy"]
            fetch = captured["fetch_policy"]

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        self.assertEqual(stderr, "")
        self.assertEqual(policy.maximum_pages, 10)
        self.assertEqual(policy.maximum_depth, 1)
        self.assertEqual(policy.maximum_links_per_page, 50)
        self.assertEqual(policy.minimum_delay_seconds, 1.0)
        self.assertEqual(policy.maximum_execution_seconds, 60.0)
        self.assertEqual(policy.maximum_request_attempts, 15)
        self.assertEqual(retry.maximum_attempts, 1)
        self.assertEqual(fetch.timeout_seconds, 10.0)

    def test_external_override_exceeding_authorization_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            with patch.object(
                cli, "_utc_now", return_value=NOW
            ), patch.object(
                cli, "validate_target_url", return_value=TARGET
            ), patch.object(cli, "run_passive_crawl_scan") as scan:
                exit_code, _, stderr = self.run_cli(
                    self.scan_arguments(
                        authorization,
                        "--crawl",
                        "--crawl-max-pages",
                        "11",
                    )
                )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("owned_target_page_limit_exceeded", stderr)
        scan.assert_not_called()

    def test_real_owned_scan_writes_audit_before_scanner_and_matches_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization_path = self.authorization_file(directory)
            authorization = load_owned_target_authorization_file(
                authorization_path
            )
            output = Path(directory) / "report.json"
            audit_path = Path(str(output) + cli.DEFAULT_OWNED_AUDIT_SUFFIX)

            def run(_target, **kwargs):
                self.assertTrue(audit_path.exists())
                audit = load_owned_target_audit_file(audit_path)
                self.assertEqual(audit.scan_id, kwargs["scan_id"])
                return completed_result(kwargs["scan_id"])

            with patch.object(
                cli, "_utc_now", return_value=NOW
            ), patch.object(
                cli, "validate_target_url", return_value=TARGET
            ), patch.object(
                cli, "run_passive_header_scan", side_effect=run
            ):
                exit_code, stdout, stderr = self.run_cli(
                    self.scan_arguments(
                        authorization_path,
                        "--output",
                        str(output),
                    )
                )

            audit = load_owned_target_audit_file(audit_path)
            report = load_scan_result_file(output)

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        self.assertEqual(stderr, "")
        self.assertEqual(audit.scan_id, report.scan_id)
        self.assertEqual(audit.authorization_id, AUTHORIZATION_ID)
        self.assertEqual(
            audit.authorization_sha256,
            authorization.fingerprint,
        )
        self.assertEqual(audit.target, TARGET.normalised_url)
        self.assertIn("Saved authorization audit:", stdout)
        self.assertIn("Saved report:", stdout)

    def test_custom_audit_path_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            output = Path(directory) / "report.json"
            audit = Path(directory) / "audit.json"
            with patch.object(
                cli, "_utc_now", return_value=NOW
            ), patch.object(
                cli, "validate_target_url", return_value=TARGET
            ), patch.object(
                cli,
                "run_passive_header_scan",
                side_effect=lambda _target, **kwargs: completed_result(
                    kwargs["scan_id"]
                ),
            ):
                exit_code, _, stderr = self.run_cli(
                    self.scan_arguments(
                        authorization,
                        "--output",
                        str(output),
                        "--audit-output",
                        str(audit),
                    )
                )
                audit_exists = audit.exists()
        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        self.assertEqual(stderr, "")
        self.assertTrue(audit_exists)

    def test_audit_and_report_paths_must_differ(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            output = Path(directory) / "report.json"
            exit_code, _, stderr = self.run_cli(
                self.scan_arguments(
                    authorization,
                    "--output",
                    str(output),
                    "--audit-output",
                    str(output),
                )
            )
        self.assertEqual(exit_code, cli.EXIT_OUTPUT_FAILED)
        self.assertIn("owned_target_audit_report_path_conflict", stderr)

    def test_audit_cannot_overwrite_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            output = Path(directory) / "report.json"
            exit_code, _, stderr = self.run_cli(
                self.scan_arguments(
                    authorization,
                    "--output",
                    str(output),
                    "--audit-output",
                    str(authorization),
                )
            )
        self.assertEqual(exit_code, cli.EXIT_OUTPUT_FAILED)
        self.assertIn("owned_target_audit_authorization_path_conflict", stderr)

    def test_existing_audit_requires_explicit_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            output = Path(directory) / "report.json"
            audit = Path(str(output) + cli.DEFAULT_OWNED_AUDIT_SUFFIX)
            audit.write_text("existing", encoding="utf-8")
            exit_code, _, stderr = self.run_cli(
                self.scan_arguments(
                    authorization,
                    "--output",
                    str(output),
                )
            )
        self.assertEqual(exit_code, cli.EXIT_OUTPUT_FAILED)
        self.assertIn("output_exists", stderr)

    def test_authorization_create_canonicalizes_and_adds_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorization.json"
            with patch.object(cli, "_utc_now", return_value=NOW):
                exit_code, stdout, stderr = self.run_cli(
                    [
                        "authorization",
                        "create",
                        "https://EXAMPLE.com",
                        "--organization",
                        "Example Ltd",
                        "--authorized-by",
                        "Security Owner",
                        "--purpose",
                        "Controlled passive assessment",
                        "--authorization-id",
                        AUTHORIZATION_ID,
                        "--allow-host",
                        "www.EXAMPLE.com",
                        "--output",
                        str(path),
                    ]
                )
            authorization = load_owned_target_authorization_file(path)

        self.assertEqual(exit_code, cli.EXIT_SUCCESS)
        self.assertEqual(stderr, "")
        self.assertEqual(authorization.target, "https://example.com/")
        self.assertEqual(
            authorization.allowed_hosts,
            ("example.com", "www.example.com"),
        )
        self.assertEqual(authorization.authorization_id, AUTHORIZATION_ID)
        self.assertEqual(authorization.expires_at, NOW + timedelta(days=30))
        self.assertIn("Created authorization:", stdout)

    def test_authorization_create_rejects_http_target_as_preflight_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorization.json"
            exit_code, _, stderr = self.run_cli(
                [
                    "authorization",
                    "create",
                    "http://example.com/",
                    "--organization",
                    "Example Ltd",
                    "--authorized-by",
                    "Security Owner",
                    "--purpose",
                    "Controlled passive assessment",
                    "--output",
                    str(path),
                ]
            )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("owned_target_https_required", stderr)
        self.assertFalse(path.exists())

    def test_authorization_create_requires_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorization.json"
            path.write_text("existing", encoding="utf-8")
            with patch.object(cli, "_utc_now", return_value=NOW):
                exit_code, _, stderr = self.run_cli(
                    [
                        "authorization",
                        "create",
                        TARGET.normalised_url,
                        "--organization",
                        "Example Ltd",
                        "--authorized-by",
                        "Security Owner",
                        "--purpose",
                        "Controlled passive assessment",
                        "--output",
                        str(path),
                    ]
                )
        self.assertEqual(exit_code, cli.EXIT_OUTPUT_FAILED)
        self.assertIn("owned_target_file_exists", stderr)

    def test_authorization_validate_and_inspect_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.authorization_file(directory)
            validate_code, validate_stdout, validate_stderr = self.run_cli(
                ["authorization", "validate", str(path)]
            )
            inspect_code, inspect_stdout, inspect_stderr = self.run_cli(
                ["authorization", "inspect", str(path), "--json"]
            )
            document = json.loads(inspect_stdout)

        self.assertEqual(validate_code, cli.EXIT_SUCCESS)
        self.assertEqual(validate_stderr, "")
        self.assertIn("Valid authorization:", validate_stdout)
        self.assertEqual(inspect_code, cli.EXIT_SUCCESS)
        self.assertEqual(inspect_stderr, "")
        self.assertEqual(document["authorization_id"], AUTHORIZATION_ID)
        self.assertEqual(document["target"], TARGET.normalised_url)

    def test_preflight_rejects_noncanonical_authorized_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            authorization = self.authorization_file(directory)
            mismatched = ValidatedTarget(
                original_url="https://example.com/path",
                normalised_url="https://example.com/path",
                scheme="https",
                hostname="example.com",
                port=443,
                resolved_addresses=("93.184.216.34",),
            )
            with patch.object(
                cli, "_utc_now", return_value=NOW
            ), patch.object(
                cli, "validate_target_url", return_value=mismatched
            ), patch.object(cli, "run_passive_header_scan") as scan:
                exit_code, _, stderr = self.run_cli(
                    self.scan_arguments(authorization, "--preflight-only")
                )
        self.assertEqual(exit_code, cli.EXIT_PREFLIGHT_FAILED)
        self.assertIn("owned_target_canonical_target_mismatch", stderr)
        scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
