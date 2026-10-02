#!/usr/bin/env python3
"""Apply a chosen license to this repository, in one step.

Nothing in the repository is licensed until this is run for real. Without
--apply it only prints the unified diff of everything it would change, so
the decision can be reviewed before it is made:

    python scripts/apply-license.py --license MIT --holder "Name" --dry-run
    python scripts/apply-license.py --license MIT --holder "Name" --apply

It writes the root LICENSE and a byte-identical copy beside each published
package's pyproject.toml (setuptools can only bundle license files from
inside the project directory), adds the PEP 639 license expression and
license-files fields to those two pyproject.toml files, and updates the
three documents that currently say no license is chosen. Every edit to an
existing file is an exact-text anchor that must match exactly once, so the
script refuses to run, instead of guessing, if those documents have drifted.

The license texts in scripts/license-texts/ are the canonical bodies from
GitHub's licenses API (choosealicense.com data). They carry a .template
suffix on purpose: only a root LICENSE file should ever read as the
repository's license. For Apache-2.0 the text is used unmodified; --holder
only fills the MIT copyright line.
"""

from __future__ import annotations

import argparse
import datetime
import difflib
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TEXTS = REPOSITORY_ROOT / "scripts" / "license-texts"

LICENSES = {
    "MIT": ("MIT License", "MIT.template"),
    "Apache-2.0": ("Apache License 2.0", "Apache-2.0.template"),
}
PUBLISHED_PACKAGES = ("packages/contracts/python", "workers/scanner")


class PlanError(Exception):
    """The repository is not in the state this script expects."""


def replace_once(text: str, old: str, new: str, where: str) -> str:
    count = text.count(old)
    if count != 1:
        raise PlanError(f"{where}: expected to find the anchor exactly once, found {count}")
    return text.replace(old, new)


def render_license(license_id: str, holder: str, year: int) -> str:
    _, template_name = LICENSES[license_id]
    text = (TEXTS / template_name).read_text(encoding="utf-8")
    if license_id == "MIT":
        text = replace_once(text, "[year]", str(year), template_name)
        text = replace_once(text, "[fullname]", holder, template_name)
    return text


def plan(
    license_id: str,
    holder: str,
    year: int,
    root: Path = REPOSITORY_ROOT,
) -> dict[Path, str]:
    """Return {path: new content} for every file to write. Reads only."""

    if license_id not in LICENSES:
        raise PlanError(f"unsupported license {license_id!r}; choose from {sorted(LICENSES)}")
    if license_id == "MIT" and not holder.strip():
        raise PlanError("--holder is required for MIT (it fills the copyright line)")
    if (root / "LICENSE").exists():
        raise PlanError("a LICENSE file already exists; this script only applies a first license")

    name = LICENSES[license_id][0]
    changes: dict[Path, str] = {}

    text = render_license(license_id, holder.strip(), year)
    changes[root / "LICENSE"] = text
    for package in PUBLISHED_PACKAGES:
        changes[root / package / "LICENSE"] = text

        pyproject = root / package / "pyproject.toml"
        original = pyproject.read_text(encoding="utf-8")
        if "license" in original.lower():
            raise PlanError(f"{package}/pyproject.toml already mentions a license")
        lines = original.splitlines(keepends=True)
        description = [i for i, line in enumerate(lines) if line.startswith("description = ")]
        if len(description) != 1:
            raise PlanError(f"{package}/pyproject.toml: expected one description line")
        lines.insert(
            description[0] + 1,
            f'license = "{license_id}"\nlicense-files = ["LICENSE"]\n',
        )
        changes[pyproject] = "".join(lines)

    readme_path = root / "README.md"
    readme = readme_path.read_text(encoding="utf-8")
    status_bullet = next(
        (line for line in readme.splitlines(keepends=True) if line.startswith("- **No license chosen yet.**")),
        None,
    )
    if status_bullet is None:
        raise PlanError("README.md: the 'No license chosen yet' bullet was not found")
    readme = replace_once(readme, status_bullet, "", "README.md status bullet")
    readme = replace_once(readme, "- No license file yet. Same section.\n", "", "README.md limitations bullet")
    readme = replace_once(
        readme,
        "## Responsible use\n",
        f"## License\n\nWebGuard is released under the {name}. See [`LICENSE`](LICENSE).\n\n## Responsible use\n",
        "README.md section heading",
    )
    changes[readme_path] = readme

    notices_path = root / "THIRD_PARTY_NOTICES.md"
    changes[notices_path] = replace_once(
        notices_path.read_text(encoding="utf-8"),
        "Their distribution licence must be defined by OpenHuntX before an external source/binary "
        "distribution that requires such a licence declaration.",
        f"The repository's `LICENSE` ({license_id}) covers all of them.",
        "THIRD_PARTY_NOTICES.md",
    )

    checklist_path = root / "docs" / "CLI_RELEASE_CHECKLIST.md"
    checklist = checklist_path.read_text(encoding="utf-8")
    item = next(
        (line for line in checklist.splitlines(keepends=True) if line.startswith("- [ ] **License.**")),
        None,
    )
    if item is None:
        raise PlanError("docs/CLI_RELEASE_CHECKLIST.md: the License checklist item was not found")
    changes[checklist_path] = replace_once(
        checklist,
        item,
        f"- [x] **License.** {license_id}, applied with `scripts/apply-license.py`.\n",
        "docs/CLI_RELEASE_CHECKLIST.md",
    )

    options_path = root / "docs" / "LICENSE_OPTIONS.md"
    options = options_path.read_text(encoding="utf-8")
    options = replace_once(
        options,
        "No license is applied. This is a comparison to decide from, not a decision; nothing here "
        "changes what license governs this repository.",
        f"{license_id} was chosen and applied (see `LICENSE`). This comparison is kept as the record "
        "of what was considered.",
        "docs/LICENSE_OPTIONS.md opening",
    )
    options = replace_once(
        options,
        "This is a recommendation, not an application. Nothing in this repository is licensed until a "
        "`LICENSE` file is actually added and the license classifier is added to each `pyproject.toml`.",
        f"{license_id} is now applied: see `LICENSE` and the `license` fields in the two published "
        "packages' `pyproject.toml` files.",
        "docs/LICENSE_OPTIONS.md closing",
    )
    changes[options_path] = options

    notes_path = root / "docs" / "RELEASE_NOTES_DRAFT.md"
    changes[notes_path] = replace_once(
        notes_path.read_text(encoding="utf-8"),
        "no license is chosen yet, the PyPI package name",
        f"the license is {license_id}, the PyPI package name",
        "docs/RELEASE_NOTES_DRAFT.md",
    )
    return changes


def show_diff(changes: dict[Path, str], root: Path) -> None:
    for path, new in changes.items():
        old = path.read_text(encoding="utf-8") if path.exists() else ""
        relative = path.relative_to(root).as_posix()
        diff = difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=f"a/{relative}" if old else "/dev/null",
            tofile=f"b/{relative}",
        )
        sys.stdout.writelines(diff)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--license", dest="license_id", required=True, choices=sorted(LICENSES))
    parser.add_argument("--holder", default="", help="Copyright holder name (required for MIT).")
    parser.add_argument("--year", type=int, default=datetime.date.today().year)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--dry-run", action="store_true", help="Print the diff; change nothing.")
    action.add_argument("--apply", action="store_true", help="Write the changes.")
    args = parser.parse_args(argv)

    try:
        changes = plan(args.license_id, args.holder, args.year)
    except PlanError as exc:
        print(f"apply-license: {exc}", file=sys.stderr)
        return 1

    if args.dry_run:
        show_diff(changes, REPOSITORY_ROOT)
        print(f"\n{len(changes)} files would change. Nothing was written.", file=sys.stderr)
        return 0

    for path, content in changes.items():
        path.write_text(content, encoding="utf-8")
    print(f"Applied {args.license_id}: wrote {len(changes)} files.")
    print("Next: python scripts/verify-governance-docs.py && ./scripts/verify.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
