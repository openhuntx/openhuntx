from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release-publish.py"
_SPEC = importlib.util.spec_from_file_location("release_publish", _SCRIPT)
publish = importlib.util.module_from_spec(_SPEC)
sys.modules["release_publish"] = publish
_SPEC.loader.exec_module(publish)

VERSION = "0.1.0"
CONTRACTS_WHEEL = f"openhuntx_webguard_contracts-{VERSION}-py3-none-any.whl"
WEBGUARD_WHEEL = f"openhuntx_webguard-{VERSION}-py3-none-any.whl"
CONTRACTS_BYTES = b"contracts wheel bytes"
WEBGUARD_BYTES = b"webguard wheel bytes"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_release_dir(root: Path) -> Path:
    release = root / "release"
    (release / "dist").mkdir(parents=True)
    (release / "dist" / CONTRACTS_WHEEL).write_bytes(CONTRACTS_BYTES)
    (release / "dist" / WEBGUARD_WHEEL).write_bytes(WEBGUARD_BYTES)
    (release / "SHA256SUMS").write_text(
        f"{digest(CONTRACTS_BYTES)}  {CONTRACTS_WHEEL}\n{digest(WEBGUARD_BYTES)}  {WEBGUARD_WHEEL}\n",
        encoding="utf-8",
    )
    return release


def stage(release: Path, stage_dir: Path, distribution: str = "contracts", **overrides):
    options = {
        "expect_version": VERSION,
        "expect_contracts_sha256": digest(CONTRACTS_BYTES),
        "expect_webguard_sha256": digest(WEBGUARD_BYTES),
    }
    options.update(overrides)
    return publish.stage(release, distribution, stage_dir, **options)


class StageTests(unittest.TestCase):
    def test_stages_only_the_assigned_wheel_and_reports_both(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            release = make_release_dir(root)
            values = stage(release, root / "stage", "webguard")
            self.assertEqual([p.name for p in (root / "stage").iterdir()], [WEBGUARD_WHEEL])
            self.assertEqual(values["filename"], WEBGUARD_WHEEL)
            self.assertEqual(values["sha256"], digest(WEBGUARD_BYTES))
            self.assertEqual(values["contracts_filename"], CONTRACTS_WHEEL)
            self.assertEqual(values["contracts_sha256"], digest(CONTRACTS_BYTES))

    def assert_refused(self, fragment: str, mutate, **overrides) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            release = make_release_dir(root)
            mutate(release)
            with self.assertRaises(publish.ReleaseStateError) as raised:
                stage(release, root / "stage", **overrides)
            self.assertIn(fragment, str(raised.exception))
            self.assertFalse((root / "stage").exists() and any((root / "stage").iterdir()))

    def test_extra_file_in_the_artifact_is_refused(self) -> None:
        self.assert_refused("unexpected artifact contents", lambda r: (r / "dist" / "extra.txt").write_text("x"))

    def test_extra_file_at_the_top_level_is_refused(self) -> None:
        self.assert_refused("unexpected artifact contents", lambda r: (r / "notes.txt").write_text("x"))

    def test_a_modified_wheel_fails_the_manifest(self) -> None:
        self.assert_refused("does not match SHA256SUMS", lambda r: (r / "dist" / WEBGUARD_WHEEL).write_bytes(b"tampered"))

    def test_a_manifest_edited_to_match_a_tampered_wheel_still_fails_the_build_job_output(self) -> None:
        def tamper(release: Path) -> None:
            (release / "dist" / WEBGUARD_WHEEL).write_bytes(b"tampered")
            (release / "SHA256SUMS").write_text(
                f"{digest(CONTRACTS_BYTES)}  {CONTRACTS_WHEEL}\n{digest(b'tampered')}  {WEBGUARD_WHEEL}\n",
                encoding="utf-8",
            )

        self.assert_refused("webguard checksum differs from the build job", tamper)

    def test_version_must_match_the_build_job(self) -> None:
        self.assert_refused("differs from the build job", lambda r: None, expect_version="0.2.0")

    def test_manifest_with_the_wrong_number_of_lines_is_refused(self) -> None:
        self.assert_refused("exactly 2 lines", lambda r: (r / "SHA256SUMS").write_text(f"{digest(b'x')}  {WEBGUARD_WHEEL}\n"))

    def test_manifest_naming_a_foreign_file_is_refused(self) -> None:
        def mutate(release: Path) -> None:
            (release / "SHA256SUMS").write_text(
                f"{digest(CONTRACTS_BYTES)}  {CONTRACTS_WHEEL}\n{digest(b'x')}  evil-1.0-py3-none-any.whl\n"
            )

        self.assert_refused("unexpected SHA256SUMS line", mutate)

    def test_a_symlinked_wheel_is_refused(self) -> None:
        def mutate(release: Path) -> None:
            target = release.parent / "elsewhere.whl"
            target.write_bytes(WEBGUARD_BYTES)
            (release / "dist" / WEBGUARD_WHEEL).unlink()
            (release / "dist" / WEBGUARD_WHEEL).symlink_to(target)

        self.assert_refused("not a regular file", mutate)

    def test_a_non_empty_stage_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            release = make_release_dir(root)
            (root / "stage").mkdir()
            (root / "stage" / "leftover").write_text("x")
            with self.assertRaises(publish.ReleaseStateError):
                stage(release, root / "stage")


def pypi_record(files: dict[str, str]) -> bytes:
    return json.dumps(
        {"urls": [{"filename": name, "digests": {"sha256": sha}} for name, sha in files.items()]}
    ).encode()


def fetcher(status: int, body: bytes = b""):
    calls: list[str] = []

    def fetch(url: str) -> tuple[int, bytes]:
        calls.append(url)
        return status, body

    fetch.calls = calls  # type: ignore[attr-defined]
    return fetch


GOOD = digest(CONTRACTS_BYTES)
PROJECT = publish.CONTRACTS_PROJECT


class ClassifyTests(unittest.TestCase):
    def classify(self, fetch) -> str:
        return publish.classify(PROJECT, VERSION, CONTRACTS_WHEEL, GOOD, fetch)

    def test_404_means_absent_and_uses_the_version_json_url(self) -> None:
        fetch = fetcher(404)
        self.assertEqual(self.classify(fetch), "absent")
        self.assertEqual(fetch.calls, [f"https://pypi.org/pypi/{PROJECT}/{VERSION}/json"])

    def test_matching_filename_and_hash_is_verified(self) -> None:
        self.assertEqual(self.classify(fetcher(200, pypi_record({CONTRACTS_WHEEL: GOOD}))), "verified")

    def test_a_different_hash_stops_the_release(self) -> None:
        with self.assertRaises(publish.ReleaseStateError) as raised:
            self.classify(fetcher(200, pypi_record({CONTRACTS_WHEEL: digest(b"other")})))
        self.assertIn("cannot be replaced", str(raised.exception))

    def test_an_unexpected_extra_file_stops_the_release(self) -> None:
        record = pypi_record({CONTRACTS_WHEEL: GOOD, "openhuntx-webguard-contracts-0.1.0.tar.gz": digest(b"s")})
        with self.assertRaises(publish.ReleaseStateError):
            self.classify(fetcher(200, record))

    def test_a_release_without_the_expected_file_stops_the_release(self) -> None:
        with self.assertRaises(publish.ReleaseStateError):
            self.classify(fetcher(200, pypi_record({})))

    def test_other_statuses_are_errors_not_absent(self) -> None:
        for status in (301, 403, 429, 500, 503):
            with self.subTest(status=status), self.assertRaises(publish.ReleaseStateError):
                self.classify(fetcher(status))

    def test_an_unreadable_record_is_an_error(self) -> None:
        for body in (b"not json", b"{}", b'{"urls": 3}'):
            with self.subTest(body=body), self.assertRaises(publish.ReleaseStateError):
                self.classify(fetcher(200, body))


class AwaitTests(unittest.TestCase):
    def run_await(self, responses, timeout=30.0):
        sequence = iter(responses)
        now = [0.0]
        sleeps: list[float] = []

        def fetch(url: str):
            return next(sequence)

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            now[0] += seconds

        publish.await_verified(
            PROJECT, VERSION, CONTRACTS_WHEEL, GOOD,
            timeout=timeout, interval=10.0, fetch=fetch, sleep=sleep, clock=lambda: now[0],
        )
        return sleeps

    def test_waits_through_absent_until_verified(self) -> None:
        verified = (200, pypi_record({CONTRACTS_WHEEL: GOOD}))
        self.assertEqual(self.run_await([(404, b""), (404, b""), verified]), [10.0, 10.0])

    def test_times_out_when_the_file_never_appears(self) -> None:
        with self.assertRaises(publish.ReleaseStateError) as raised:
            self.run_await([(404, b"")] * 10, timeout=25.0)
        self.assertIn("did not appear", str(raised.exception))

    def test_a_hash_mismatch_while_waiting_stops_immediately(self) -> None:
        wrong = (200, pypi_record({CONTRACTS_WHEEL: digest(b"other")}))
        with self.assertRaises(publish.ReleaseStateError):
            self.run_await([(404, b""), wrong])


if __name__ == "__main__":
    unittest.main()
