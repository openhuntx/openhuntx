from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

import webguard_contracts
import webguard_scanner
from webguard_scanner.passive_scan import ENGINE_VERSION

ROOT = Path(__file__).resolve().parents[2]


def project(path: str) -> dict:
    return tomllib.loads((ROOT / path / "pyproject.toml").read_text(encoding="utf-8"))["project"]


class VersionConsistencyTests(unittest.TestCase):
    """The release ships two lockstep versions; every literal copy must agree."""

    def test_package_literals_match_the_pyproject_versions(self) -> None:
        contracts = project("packages/contracts/python")["version"]
        scanner = project("workers/scanner")["version"]
        self.assertEqual(contracts, scanner, "the two published packages release in lockstep")
        self.assertEqual(webguard_contracts.__version__, contracts)
        self.assertEqual(webguard_scanner.__version__, scanner)
        self.assertEqual(ENGINE_VERSION, scanner, "`webguard --version` prints ENGINE_VERSION")

    def test_dependency_pins_follow_the_release_version(self) -> None:
        version = project("workers/scanner")["version"]
        self.assertIn(f"openhuntx-webguard-contracts=={version}", project("workers/scanner")["dependencies"])
        archived_api = project("apps/api")["dependencies"]
        self.assertIn(f"openhuntx-webguard-contracts=={version}", archived_api)
        self.assertIn(f"openhuntx-webguard=={version}", archived_api)


if __name__ == "__main__":
    unittest.main()
