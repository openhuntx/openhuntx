from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify-release-artifacts.py"
_SPEC = importlib.util.spec_from_file_location("verify_release_artifacts", _SCRIPT)
release = importlib.util.module_from_spec(_SPEC)
sys.modules["verify_release_artifacts"] = release
_SPEC.loader.exec_module(release)


def make_wheel(
    directory: Path,
    distribution: str,
    *,
    version: str = "0.1.0",
    metadata_name: str | None = None,
    metadata_version: str | None = None,
    requires: tuple[str, ...] = (),
    extra_members: dict[str, str] | None = None,
    console_script: str | None = None,
) -> Path:
    prefix = distribution.replace("-", "_")
    root = release.IMPORT_ROOTS[distribution]
    dist_info = f"{prefix}-{version}.dist-info"
    path = directory / f"{prefix}-{version}-py3-none-any.whl"

    lines = [
        "Metadata-Version: 2.4",
        f"Name: {metadata_name or distribution}",
        f"Version: {metadata_version or version}",
        "Requires-Python: >=3.11,<3.15",
        *(f"Requires-Dist: {requirement}" for requirement in requires),
    ]
    if console_script is None and distribution == release.WEBGUARD:
        console_script = release.CONSOLE_SCRIPT

    members = {
        f"{root}/__init__.py": "",
        f"{dist_info}/METADATA": "\n".join(lines) + "\n",
        f"{dist_info}/WHEEL": "Wheel-Version: 1.0\n",
        f"{dist_info}/RECORD": "",
        f"{dist_info}/top_level.txt": f"{root}\n",
    }
    if console_script:
        members[f"{dist_info}/entry_points.txt"] = f"[console_scripts]\n{console_script}\n"
    members.update(extra_members or {})

    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return path


def make_valid_pair(directory: Path, **webguard_overrides) -> None:
    make_wheel(directory, release.CONTRACTS)
    options = {"requires": (f"{release.CONTRACTS}==0.1.0",)}
    options.update(webguard_overrides)
    make_wheel(directory, release.WEBGUARD, **options)


class ReleaseArtifactValidationTests(unittest.TestCase):
    def assert_rejected(self, directory: Path, fragment: str) -> None:
        with self.assertRaises(release.ReleaseCheckError) as raised:
            release.validate_distributions(directory)
        self.assertIn(fragment, str(raised.exception))

    def test_valid_pair_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            make_valid_pair(Path(name))
            infos = release.validate_distributions(Path(name))
        self.assertEqual(set(infos), {release.CONTRACTS, release.WEBGUARD})
        self.assertEqual({info.version for info in infos.values()}, {"0.1.0"})

    def test_license_files_in_dist_info_are_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            make_wheel(
                directory,
                release.CONTRACTS,
                extra_members={"openhuntx_webguard_contracts-0.1.0.dist-info/licenses/LICENSE": "x"},
            )
            make_wheel(
                directory,
                release.WEBGUARD,
                requires=(f"{release.CONTRACTS}==0.1.0",),
                extra_members={"openhuntx_webguard-0.1.0.dist-info/licenses/LICENSE": "x"},
            )
            release.validate_distributions(directory)

    def test_extra_file_in_dist_is_rejected(self) -> None:
        for stray in ("SHA256SUMS", "openhuntx_webguard-0.1.0.tar.gz", "notes.txt"):
            with self.subTest(stray=stray), tempfile.TemporaryDirectory() as name:
                make_valid_pair(Path(name))
                (Path(name) / stray).write_text("x")
                self.assert_rejected(Path(name), stray)

    def test_subdirectory_in_dist_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            make_valid_pair(Path(name))
            (Path(name) / "nested").mkdir()
            self.assert_rejected(Path(name), "nested")

    def test_second_wheel_for_the_same_distribution_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            make_valid_pair(Path(name))
            make_wheel(Path(name), release.WEBGUARD, version="0.1.1",
                       requires=(f"{release.CONTRACTS}==0.1.1",))
            self.assert_rejected(Path(name), "unexpected entries")

    def test_missing_wheel_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            make_wheel(Path(name), release.CONTRACTS)
            self.assert_rejected(Path(name), "missing wheel")

    def test_metadata_name_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            make_valid_pair(Path(name), metadata_name="openhuntx-webguard-scanner")
            self.assert_rejected(Path(name), "METADATA Name")

    def test_metadata_version_must_match_filename(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            make_valid_pair(Path(name), metadata_version="0.2.0")
            self.assert_rejected(Path(name), "does not match the filename version")

    def test_the_two_wheels_must_share_a_version(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            make_wheel(directory, release.CONTRACTS, version="0.1.0")
            make_wheel(directory, release.WEBGUARD, version="0.1.1",
                       requires=(f"{release.CONTRACTS}==0.1.1",))
            self.assert_rejected(directory, "disagree on version")

    def test_contracts_dependency_must_be_pinned_to_the_release_version(self) -> None:
        for requirement in (
            f"{release.CONTRACTS}==0.0.9",
            f"{release.CONTRACTS}>=0.1.0",
            release.CONTRACTS,
        ):
            with self.subTest(requirement=requirement), tempfile.TemporaryDirectory() as name:
                make_valid_pair(Path(name), requires=(requirement,))
                self.assert_rejected(Path(name), "must depend on exactly")

    def test_an_additional_dependency_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            make_valid_pair(
                Path(name),
                requires=(f"{release.CONTRACTS}==0.1.0", "requests>=2"),
            )
            self.assert_rejected(Path(name), "must depend on exactly")

    def test_contracts_must_stay_dependency_free(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            make_wheel(directory, release.CONTRACTS, requires=("requests",))
            make_wheel(directory, release.WEBGUARD, requires=(f"{release.CONTRACTS}==0.1.0",))
            self.assert_rejected(directory, "must have no dependencies")

    def test_unexpected_content_is_rejected(self) -> None:
        cases = {
            "tests/test_x.py": "outside",
            "webguard_scanner/data.db": "unexpected package file",
            "webguard_scanner/__pycache__/x.pyc": "unexpected package file",
            "webguard_scanner/../escape.py": "unsafe path",
            "openhuntx_webguard-0.1.0.dist-info/secrets.json": "unexpected dist-info file",
        }
        for member, fragment in cases.items():
            with self.subTest(member=member), tempfile.TemporaryDirectory() as name:
                make_valid_pair(Path(name), extra_members={member: "x"})
                self.assert_rejected(Path(name), fragment)

    def test_console_script_must_be_exactly_the_webguard_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            make_valid_pair(Path(name), console_script="webguard = somewhere.else:main")
            self.assert_rejected(Path(name), "console scripts")

    def test_corrupt_wheel_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            make_valid_pair(Path(name))
            (Path(name) / "openhuntx_webguard-0.1.0-py3-none-any.whl").write_bytes(b"not a zip")
            self.assert_rejected(Path(name), "not a valid wheel archive")

    def test_snapshot_changes_when_a_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            make_valid_pair(Path(name))
            before = release.snapshot(Path(name))
            (Path(name) / "openhuntx_webguard-0.1.0-py3-none-any.whl").write_bytes(b"tampered")
            self.assertNotEqual(before, release.snapshot(Path(name)))


if __name__ == "__main__":
    unittest.main()
