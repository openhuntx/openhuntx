from __future__ import annotations

import contextlib
import io
import json
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from webguard_contracts import ScanCoverage, ScanResult, ScanStatus
from webguard_scanner import cli


_NOW = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)


def _completed_result(scan_id: str, target: str = "https://example.com/") -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        scan_type="passive-http-headers",
        status=ScanStatus.COMPLETED,
        target=target,
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=_NOW,
        completed_at=_NOW,
        coverage=ScanCoverage(),
    )


class CliWorkspaceTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli.main(argv)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_init_creates_restricted_workspace_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "workspace"

            code, stdout, stderr = self._run(
                ["init", "--directory", str(home)]
            )

            self.assertEqual(code, cli.EXIT_SUCCESS)
            self.assertEqual(stderr, "")
            self.assertIn("Created:", stdout)

            # The printed next steps must use flags the parser really has.
            self.assertIn("--authorization-file", stdout)
            self.assertIn("--confirm-authorization", stdout)
            self.assertIn("--lab --allow-host", stdout)
            self.assertNotIn("--authorization <", stdout)

            for subdirectory in ("authorizations", "scan-results", "reports"):
                target = home / subdirectory
                self.assertTrue(target.is_dir())
                mode = stat.S_IMODE(target.stat().st_mode)
                self.assertEqual(mode, 0o700)

    def test_init_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "workspace"
            self._run(["init", "--directory", str(home)])

            code, stdout, _ = self._run(["init", "--directory", str(home)])

            self.assertEqual(code, cli.EXIT_SUCCESS)
            self.assertIn("already existed", stdout)

    def test_doctor_reports_ok_for_a_writable_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, stdout, stderr = self._run(
                ["doctor", "--directory", directory]
            )

            self.assertEqual(code, cli.EXIT_SUCCESS)
            self.assertEqual(stderr, "")
            self.assertIn("[OK] Python version", stdout)
            self.assertIn("[OK] Write access", stdout)

    def test_doctor_fails_closed_for_an_unwritable_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "locked"
            target.mkdir(mode=0o500)

            try:
                code, stdout, _ = self._run(
                    ["doctor", "--directory", str(target)]
                )
            finally:
                target.chmod(0o700)

            self.assertEqual(code, cli.EXIT_DOCTOR_CHECK_FAILED)
            self.assertIn("[FAIL] Write access", stdout)

    def test_results_list_reports_no_results_for_a_missing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "scan-results"

            code, stdout, stderr = self._run(
                ["results", "list", "--directory", str(missing)]
            )

            self.assertEqual(code, cli.EXIT_SUCCESS)
            self.assertEqual(stderr, "")
            self.assertIn("No stored results found", stdout)

    def test_results_list_summarises_a_stored_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "example.json"
            cli._write_report(
                _completed_result("11111111-1111-1111-1111-111111111111"),
                output,
                overwrite=False,
            )

            code, stdout, _ = self._run(
                ["results", "list", "--directory", directory]
            )

            self.assertEqual(code, cli.EXIT_SUCCESS)
            self.assertIn("completed", stdout)
            self.assertIn("https://example.com/", stdout)
            self.assertIn("11111111-1111-1111-1111-111111111111", stdout)

    def test_results_list_json_is_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "example.json"
            cli._write_report(
                _completed_result("22222222-2222-2222-2222-222222222222"),
                output,
                overwrite=False,
            )

            code, stdout, _ = self._run(
                ["results", "list", "--directory", directory, "--json"]
            )

            self.assertEqual(code, cli.EXIT_SUCCESS)
            rows = json.loads(stdout)
            self.assertEqual(len(rows), 1)
            self.assertEqual(
                rows[0]["scan_id"],
                "22222222-2222-2222-2222-222222222222",
            )
            self.assertTrue(rows[0]["readable"])

    def test_results_list_marks_unreadable_files_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "garbage.json").write_text("not a report", encoding="utf-8")

            code, stdout, _ = self._run(
                ["results", "list", "--directory", directory]
            )

            self.assertEqual(code, cli.EXIT_SUCCESS)
            self.assertIn("[UNREADABLE]", stdout)

    def test_results_commands_leave_authorization_audit_records_alone(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "example.json"
            audit = Path(directory) / ("example.json" + cli.DEFAULT_OWNED_AUDIT_SUFFIX)
            cli._write_report(
                _completed_result("55555555-5555-5555-5555-555555555555"),
                report,
                overwrite=False,
            )
            audit.write_text("{}", encoding="utf-8")

            _, listing, _ = self._run(["results", "list", "--directory", directory])
            self.assertIn("example.json", listing)
            self.assertNotIn("UNREADABLE", listing)
            self.assertNotIn("authorization-audit", listing)

            code, stdout, _ = self._run(["results", "clean", "--directory", directory, "--yes"])
            self.assertEqual(code, cli.EXIT_SUCCESS)
            self.assertIn("Deleted 1 of 1", stdout)
            self.assertFalse(report.exists())
            self.assertTrue(audit.exists(), "the audit record must survive `results clean`")

    def test_results_clean_without_yes_is_a_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "example.json"
            cli._write_report(
                _completed_result("33333333-3333-3333-3333-333333333333"),
                output,
                overwrite=False,
            )

            code, stdout, _ = self._run(
                ["results", "clean", "--directory", directory]
            )

            self.assertEqual(code, cli.EXIT_SUCCESS)
            self.assertIn("Would delete 1 file", stdout)
            self.assertTrue(output.exists())

    def test_results_clean_with_yes_deletes_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "example.json"
            cli._write_report(
                _completed_result("44444444-4444-4444-4444-444444444444"),
                output,
                overwrite=False,
            )

            code, stdout, _ = self._run(
                ["results", "clean", "--directory", directory, "--yes"]
            )

            self.assertEqual(code, cli.EXIT_SUCCESS)
            self.assertIn("Deleted 1 of 1", stdout)
            self.assertFalse(output.exists())

    def test_unhandled_exception_fails_closed_with_a_dedicated_exit_code(self) -> None:
        def _boom(_args) -> int:
            raise RuntimeError("boom")

        with patch.object(cli, "_doctor_command", side_effect=_boom):
            code, stdout, stderr = self._run(["doctor"])

        self.assertEqual(code, cli.EXIT_UNEXPECTED_ERROR)
        self.assertEqual(stdout, "")
        self.assertIn("unexpected_error", stderr)
        self.assertIn("RuntimeError", stderr)
        self.assertIn("boom", stderr)

    def test_keyboard_interrupt_exits_130_without_a_traceback(self) -> None:
        def _interrupt(_args) -> int:
            raise KeyboardInterrupt()

        with patch.object(cli, "_doctor_command", side_effect=_interrupt):
            code, stdout, stderr = self._run(["doctor"])

        self.assertEqual(code, 130)
        self.assertEqual(stdout, "")
        self.assertIn("cancelled", stderr)


if __name__ == "__main__":
    unittest.main()
