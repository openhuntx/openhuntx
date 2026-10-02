# Releasing WebGuard

How a release goes from a merged `main` to two packages on PyPI, what each step proves, and what to do when an upload goes wrong. Nothing here has run against the real PyPI yet, so the first release is also the first real test of steps 5 through 7.

Two distributions are released together, at the same version: `openhuntx-webguard-contracts` (the dependency) and `openhuntx-webguard` (the CLI, which pins `openhuntx-webguard-contracts==<its own version>`). Contracts always uploads first, because a CLI on PyPI without its pinned dependency cannot be installed.

## The sequence

1. **Review and merge the release pull request.** Branch protection requires all eleven CI checks but no human review; a review is the owner's call. Use a merge commit so the history stays readable.
2. **Check CI on the resulting `main` commit.** The pull request's checks ran on the PR head, not on the merge commit. Open the push-to-`main` run for the merge commit and confirm every job is green.
3. **Choose a license and apply it, if you are going to.** Run `python scripts/apply-license.py --license <MIT|Apache-2.0> --holder "<name>" --dry-run`, read the diff, rerun with `--apply`, and merge that as its own pull request. Then repeat step 2 for that merge commit. Do this before the first upload: PyPI files are permanent, so a release published without a license cannot be corrected in place. Skipping it is also a decision, and the workflow does not require one.
4. **Register the two trusted publishers on PyPI.** See below. Each project gets its own publisher, with its own environment.
5. **Rehearse.** Actions, "Publish to PyPI", Run workflow, branch `main`, mode `dry-run` (the default). It runs all three jobs: the build job validates exactly the files that would be uploaded, and each publish job downloads them, re-verifies the manifest and checksums, stages only its own wheel, and queries PyPI. It never reaches an upload step. Read the build job's summary: it lists the commit and the SHA-256 of each wheel. Expect PyPI to report both versions `absent`.
6. **Publish, after explicit authorization.** Same workflow, mode `publish`, confirmation `publish`.
7. **Verify a fresh public install,** from a clean machine or container with no checkout and no `--find-links`:

   ```bash
   pipx install openhuntx-webguard
   webguard --version
   webguard doctor
   python3 -m http.server 8931 --bind 127.0.0.1 > /dev/null 2>&1 &
   webguard scan http://127.0.0.1:8931/ --lab --allow-host 127.0.0.1 --output demo.json
   kill $!
   ```

   Only after this passes can the README say the PyPI install path is verified. Until then it says it is not.

## The workflow

`.github/workflows/publish.yml` has three jobs, in order.

**`build-and-verify`** has no publishing permission. It builds both wheels with `SOURCE_DATE_EPOCH` set to the commit time, then runs `scripts/verify-release-artifacts.py` on exactly those files and uploads them, with a `SHA256SUMS` manifest, as one artifact (kept for 30 days). The same script runs in the pull-request `cli-packaging` job, so a packaging regression shows up before release day.

**`publish-contracts`** runs in the `pypi-contracts` environment. It downloads the artifact (a digest mismatch is a hard error), runs `scripts/release-publish.py stage`, and then uploads `openhuntx-webguard-contracts` only.

**`publish-webguard`** runs in the `pypi-webguard` environment, and only after `publish-contracts` succeeded. It does the same verification, then requires PyPI to already hold the contracts file with the verified name and SHA-256, and only then uploads `openhuntx-webguard`.

Both publish jobs get their wheels from the verified artifact and never rebuild. `id-token: write` exists only on those two jobs, and `scripts/verify-supply-chain-pins.py` fails if that changes.

What the validator and `stage` check, in order:

- The build directory holds exactly the two expected wheels and nothing else: no sdist, no checksum file, no subdirectory, no symlink.
- Each wheel's own METADATA has the right distribution name, a version matching its filename and the other wheel, and for the CLI, exactly one dependency: `openhuntx-webguard-contracts==<that version>`.
- Wheel contents are an allowlist: `.py` files under the package directory and the standard `dist-info` files (plus `licenses/` once a license is applied). The `webguard` console script is declared exactly once.
- Both wheels install into a fresh virtual environment from those files alone, with no index. `pip check` passes, the imports resolve inside that environment, the packages' `__version__` and `webguard --version` all report the wheel version, and the installed CLI completes a synthetic scan, a results listing, and a report render from outside the repository.
- In each publish job: the downloaded listing is exactly `SHA256SUMS`, `dist/`, and the two wheels; every wheel matches the manifest; the manifest matches the checksums the build job passed through job outputs (a channel separate from the artifact); the one assigned wheel is copied into an otherwise empty directory and checked again.

To check a published file later, check out the same commit, set `SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"`, run the two `pip wheel` commands from the workflow, and compare SHA-256 values with the build job's summary. A different Python or setuptools build can in principle produce different bytes, so a mismatch calls for a look, not an alarm.

## PyPI trusted publishers

Register both at <https://pypi.org/manage/account/publishing/> as pending publishers (neither project exists yet). The environment is what makes them distinct, and it has to be:

| Field | `openhuntx-webguard-contracts` | `openhuntx-webguard` |
|---|---|---|
| PyPI project name | `openhuntx-webguard-contracts` | `openhuntx-webguard` |
| Owner | `openhuntx` | `openhuntx` |
| Repository name | `openhuntx` | `openhuntx` |
| Workflow name | `publish.yml` | `publish.yml` |
| Environment name | `pypi-contracts` | `pypi-webguard` |

PyPI will not register two pending publishers whose owner, repository, workflow, and environment are all identical, because its uniqueness rule ignores the project name. A single pending publisher can also create only one project, since the first upload consumes it. That is why this design uses two environments and two publish jobs. Do not register the same environment twice, do not leave the environment blank on either, and do not work around this with an API token.

The GitHub side exists: `pypi-contracts` and `pypi-webguard`, each with a deployment-branch policy that allows only `main`. That server-side rule is the control that holds even if someone edits the workflow on another branch. An older `pypi-publish` environment from an earlier design is unused and can be deleted in the repository's environment settings. Two optional hardening steps are the owner's call: adding yourself as a required reviewer on each environment (the publish job then pauses for approval after the rehearsal-grade checks have run), and two-factor authentication on the PyPI account.

## When an upload goes wrong

PyPI never lets a filename be uploaded twice, even after the release is deleted, so none of the recovery paths below overwrite anything. A file already on PyPI counts as done only if PyPI reports exactly the expected filename and exactly the expected SHA-256 for that version, and no other file. Any difference stops the release.

- **Contracts upload fails.** Nothing is on PyPI, and the CLI job never starts. Fix the cause and use "Re-run failed jobs" on the same run.
- **Contracts uploads, the CLI upload fails.** PyPI has `openhuntx-webguard-contracts` and no CLI; nothing can install the CLI yet, so no user is affected. Open the original run and use "Re-run failed jobs". GitHub re-runs only the failed jobs, against the same commit and the same verified artifact the first attempt used, so nothing is rebuilt. The contracts job is not re-run unless it failed. If it is, it finds its file already on PyPI with a matching SHA-256, skips the upload, and passes. GitHub keeps a run re-runnable for 30 days, and the artifact is kept for 30 days.
- **An upload finished but the confirmation step timed out** (PyPI's JSON API can lag behind an upload). Re-run failed jobs. The check sees the file as verified, skips the upload, and passes.
- **A fresh dispatch after a partial publish.** This rebuilds from whatever `main` is now. Because builds are byte-reproducible from a commit, the contracts wheel matches the published one if `main` has not moved, and the run carries on. If `main` has moved, the hashes differ, the contracts job stops on the mismatch, and nothing is uploaded. Prefer re-running the original run.
- **The hashes differ and you need to rebuild.** The published file cannot change, so the version is spent. Follow the next section.

## Choosing versions when code changes require a rebuild

The two packages release in lockstep: the same version number, and the CLI pins `openhuntx-webguard-contracts==<same version>`. The release validator and `tests/unit/test_version_consistency.py` both enforce this. Once either file of a version has reached PyPI, that version is spent for that file.

If code changes after any file of version X is published, release a new pair at the next version Y (for example 0.1.0 to 0.1.1). Bump both packages, including the one whose code did not change, because the CLI's pin and the lockstep rule require it. Do not republish X. If the first release was defective and not merely incomplete, yank both X files on PyPI (yanking hides a release from installers without deleting it), because an installer still accepts a yanked file when it is pinned with an exact `==`. Yanking only contracts would therefore not stop the CLI from installing it through its pin, and yanking only the CLI would leave the defective contracts file installable by anyone who asks for it by version.

Every place that carries the version, which `tests/unit/test_version_consistency.py` will name if you miss one:

- `packages/contracts/python/pyproject.toml`: `version`
- `workers/scanner/pyproject.toml`: `version`, and the dependency `openhuntx-webguard-contracts==<Y>`
- `packages/contracts/python/src/webguard_contracts/__init__.py`: `__version__`
- `workers/scanner/src/webguard_scanner/__init__.py`: `__version__`
- `workers/scanner/src/webguard_scanner/passive_scan.py`: `ENGINE_VERSION`, which is what `webguard --version` prints
- `apps/api/pyproject.toml`: the two pins `openhuntx-webguard-contracts==<Y>` and `openhuntx-webguard==<Y>` (the archived API package; its pins have to follow or `pip install -r requirements-dev.txt` stops resolving)
- `tests/unit/test_cli.py`: the expected `webguard <version>` line in `test_version_uses_engine_version`
- `README.md` and `docs/RELEASE_NOTES_DRAFT.md`: the wheel filename in the source-install command

Then merge, check CI on `main`, and start again from step 5.

## What is not covered

Nothing in the workflow verifies that CI passed on the exact commit being published; step 2 of the sequence does that by hand. The publish jobs execute `scripts/release-publish.py` from the checked-out `main` commit while holding the OIDC permission, the same trust that the workflow file itself already carries. The build backend (`setuptools==83.0.0`) is pinned by version in each `pyproject.toml` but fetched from PyPI at build time without hash-pinning, as in every other build in this repository. And re-running failed jobs after a partial publish is GitHub's documented behavior that this repository has not yet exercised.
