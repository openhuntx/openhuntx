from __future__ import annotations

import importlib.util
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("apply_license", ROOT / "scripts" / "apply-license.py")
apply_license = importlib.util.module_from_spec(_SPEC)
sys.modules["apply_license"] = apply_license
_SPEC.loader.exec_module(apply_license)

EXPECTED_FILES = {
    "LICENSE",
    "packages/contracts/python/LICENSE",
    "packages/contracts/python/pyproject.toml",
    "workers/scanner/LICENSE",
    "workers/scanner/pyproject.toml",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "docs/CLI_RELEASE_CHECKLIST.md",
    "docs/LICENSE_OPTIONS.md",
    "docs/RELEASE_NOTES_DRAFT.md",
}


@unittest.skipIf(
    (ROOT / "LICENSE").exists(),
    "a license has been applied; scripts/apply-license.py has done its job",
)
class ApplyLicensePlanTests(unittest.TestCase):
    def relative(self, changes: dict[Path, str]) -> dict[str, str]:
        return {path.relative_to(ROOT).as_posix(): text for path, text in changes.items()}

    def test_each_license_plans_exactly_the_expected_files_and_writes_nothing(self) -> None:
        for license_id in ("MIT", "Apache-2.0"):
            with self.subTest(license=license_id):
                changes = self.relative(apply_license.plan(license_id, "Test Holder", 2026))
                self.assertEqual(set(changes), EXPECTED_FILES)
        self.assertFalse((ROOT / "LICENSE").exists())

    def test_mit_text_has_the_year_and_holder_and_no_placeholders(self) -> None:
        text = self.relative(apply_license.plan("MIT", "Test Holder", 2026))["LICENSE"]
        self.assertIn("Copyright (c) 2026 Test Holder", text)
        self.assertNotIn("[year]", text)
        self.assertNotIn("[fullname]", text)

    def test_apache_text_is_the_canonical_template_unmodified(self) -> None:
        template = (ROOT / "scripts" / "license-texts" / "Apache-2.0.template").read_text(encoding="utf-8")
        text = self.relative(apply_license.plan("Apache-2.0", "", 2026))["LICENSE"]
        self.assertEqual(text, template)

    def test_every_license_file_copy_is_identical(self) -> None:
        changes = self.relative(apply_license.plan("MIT", "Test Holder", 2026))
        self.assertEqual(changes["packages/contracts/python/LICENSE"], changes["LICENSE"])
        self.assertEqual(changes["workers/scanner/LICENSE"], changes["LICENSE"])

    def test_package_metadata_stays_valid_toml_with_the_license_fields(self) -> None:
        for license_id in ("MIT", "Apache-2.0"):
            changes = self.relative(apply_license.plan(license_id, "Test Holder", 2026))
            for package in apply_license.PUBLISHED_PACKAGES:
                with self.subTest(license=license_id, package=package):
                    project = tomllib.loads(changes[f"{package}/pyproject.toml"])["project"]
                    self.assertEqual(project["license"], license_id)
                    self.assertEqual(project["license-files"], ["LICENSE"])

    def test_readme_gains_a_license_section_and_loses_the_no_license_claims(self) -> None:
        readme = self.relative(apply_license.plan("MIT", "Test Holder", 2026))["README.md"]
        self.assertIn("## License", readme)
        self.assertNotIn("No license chosen yet.", readme)
        self.assertNotIn("No license file yet.", readme)

    def test_mit_requires_a_holder(self) -> None:
        with self.assertRaises(apply_license.PlanError):
            apply_license.plan("MIT", "  ", 2026)

    def test_unsupported_license_is_refused(self) -> None:
        with self.assertRaises(apply_license.PlanError):
            apply_license.plan("GPL-3.0-only", "Test Holder", 2026)

    def test_replace_once_refuses_a_missing_or_repeated_anchor(self) -> None:
        with self.assertRaises(apply_license.PlanError):
            apply_license.replace_once("abc", "x", "y", "t")
        with self.assertRaises(apply_license.PlanError):
            apply_license.replace_once("xx", "x", "y", "t")


if __name__ == "__main__":
    unittest.main()
