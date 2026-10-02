# WebGuard CLI v1 release checklist

A finite list. When everything here is checked, v1 is ready to publish; nothing gets added to it to extend scope. [`docs/RELEASING.md`](RELEASING.md) has the step-by-step release sequence, [`docs/CASE_STUDY.md`](CASE_STUDY.md) explains why this project looks the way it does, and the root [README](../README.md) describes what the tool actually does.

CI results are not recorded in this file. A commit cannot contain its own CI result, so the state of the required checks is on the pull request and in the release handoff, and a result for one commit is never evidence for another.

## Where things stand

Implemented, and checked locally and in CI per commit. Not merged. Not published. In particular:

- **Source installation** (build both wheels, `pipx install`): works today. The exact `pipx` command was run by hand on macOS. In CI, the `cli-packaging` job builds the same two wheels and installs them with `pip` into a clean virtual environment on every pull request.
- **Public PyPI installation** (`pipx install openhuntx-webguard`): unverified until publication. What exists is a simulation: both wheels served from a local PEP 503 index, installed with no `--find-links`, with pip resolving `openhuntx-webguard-contracts==0.1.0` from the wheel's own metadata. That proves the mechanism, not the real index.
- **Platforms actually tested**: Linux (GitHub Actions `ubuntu-24.04`; unit tests on Python 3.11.15, 3.12.13, 3.13.14, 3.14.6, and the packaging job on 3.13.14) and macOS (Python 3.14.7, by hand). Windows is untested and not supported.
- **The publish workflow has never run.** `docs/RELEASING.md` says what its dry run rehearses and what only a real publish can prove.

## Engineering (done)

- [x] Terminal UX: `init`, `doctor`, `scan`, `authorization create/validate/inspect`, `report validate/inspect/render/compare/validate-comparison`, `results list/clean`, `--version`, and `--help` on every command
- [x] Fail-closed top-level exception boundary in `main()`; documented, stable exit codes `0` through `7`; Ctrl-C behavior documented and verified for both scan modes (single-page: exit 130, nothing written; crawl: exit 1, partial `cancelled` report, checkpoint saved and resumable)
- [x] No database or background service; local files only, `0600`/`0700` permissions, symlink-destination refusal
- [x] Scanner-engine hardening from `audit/checkpoint1-phase6-exception-network-safety` is this branch's base
- [x] A malformed, expired, confirmation-mismatched, or target-mismatched authorization is rejected before any DNS lookup; destination validation (resolution, private and reserved address rejection) still runs in full and still gates every connection
- [x] `results list` and `results clean` skip `*.authorization-audit.json`, so audit records are never listed as results or deleted
- [x] `init` prints next steps with the real flags, covered by a test
- [x] Version literals and dependency pins are covered by a unit test and by the release validator

What the authorization tests establish, so one result isn't read as covering another:

- A `--lab` scan runs the whole scan, report, and results pipeline over real sockets, but `--lab` skips the authorization machinery entirely. It says nothing about the normal path.
- `test_real_owned_scan_writes_audit_before_scanner_and_matches_report` runs a valid, exactly-matching authorization through the real `cli.main()` entry point with only DNS resolution and the HTTP scan replaced by fixtures. It shows authorization loading, preflight, confirmation matching, and audit-before-scan ordering work.
- `tests/unit/test_cli_authorization_dns_boundary.py` patches `socket.getaddrinfo`, the real resolver boundary, and runs the real validator. Expired, not-yet-valid, wrong-confirmation, target-mismatch, and plain-HTTP authorizations (and the expired case under `--preflight-only` and `--crawl`) never reach it. A malformed authorization file was always rejected before DNS, so that test guards against regression rather than proving a change. Two control tests show the instrument works: a valid authorization does reach the resolver, and one whose host resolves to a private address is still refused afterward. With the early gate disabled, seven of those cases fail.
- Outside the unit tests, rejections were run against the installed CLI using `*.invalid` hostnames (RFC 2606, guaranteed unresolvable). They finished in about 0.1 seconds with the correct error code, where an attempted lookup would have produced a DNS failure.
- The README's authorization walkthrough runs against `example.com` to `--preflight-only`: it reaches "Owned-target readiness: approved" and sends no HTTP request. Its one network activity is a DNS lookup.
- No scan of a real third-party target has been performed.

## Packaging and publishing (done)

- [x] `openhuntx-webguard-contracts` and `openhuntx-webguard` build as standalone wheels (the scanner package was renamed from `openhuntx-webguard-scanner` when it became the distributed product; the `webguard` command is unchanged)
- [x] `scripts/verify-release-artifacts.py` checks the exact files a release would upload: only the two wheels in the directory, correct names and a shared version in each wheel's own metadata, the contracts pin, a contents allowlist, a clean-environment install, `pip check`, the versions the installed packages and CLI report, a synthetic CLI scan, and unchanged checksums afterward. It runs in the `cli-packaging` pull-request job and in the publish workflow's build job
- [x] Wheels are built with `SOURCE_DATE_EPOCH` set to the commit time and are byte-reproducible from a commit on the same toolchain
- [x] `.github/workflows/publish.yml`: manual dispatch, defaults to a dry run. One build-and-verify job with no publishing permission; one publish job per project, each in its own environment (`pypi-contracts`, `pypi-webguard`), contracts first and the CLI only after it. Each publish job downloads the verified artifact without rebuilding, re-checks the manifest and checksums, and uploads only its own wheel. A file already on PyPI counts as done only when its name and SHA-256 match; a mismatch stops the release and nothing is ever overwritten
- [x] Both environments exist with a server-side deployment-branch policy that allows only `main`, read back and verified
- [x] `scripts/verify-supply-chain-pins.py` checks the workflow job by job (triggers, exact permissions, environments, job ordering, exact upload guards, `skip-existing: false`, no rebuild in a publish job, no `write-all`, every `uses:` and `- uses:` line SHA-pinned and reviewed) and was mutation-tested against 20 degraded variants of both workflows
- [x] `scripts/release-publish.py` (the stage, plan, and await logic) has its own unit tests, including the mismatch and partial-publication cases

## Documentation (done)

- [x] README: install (source now, PyPI later and unverified), a quick-start whose two blocks run verbatim, every command, exit codes and Ctrl-C behavior, storage model, authorization model (unsigned, fingerprinted), tested platforms, known limitations
- [x] `docs/RELEASING.md`, `docs/CLI_ARCHITECTURE.md` (including which modules each wheel contains and which the CLI reaches), `docs/LEGACY_PLATFORM.md`, `docs/CASE_STUDY.md`, `docs/LICENSE_OPTIONS.md`, `docs/RELEASE_NOTES_DRAFT.md`, `CONTRIBUTING.md`, `SECURITY.md`
- [x] `examples/`: a reproducible, synthetic, offline demo

## Repository (done)

- [x] Migrated to `openhuntx/openhuntx` with branch history preserved; the original repository is untouched
- [x] Secret scanning with push protection, Dependabot security updates, vulnerability alerts, and private vulnerability reporting enabled (the last one read back as enabled; `SECURITY.md` names that route and invents no email address)
- [x] Ruleset on `main`: eleven required checks, non-fast-forward and deletion protection, Actions SHA-pinning required
- [x] Issue and PR templates

## Review findings and dispositions

The release candidate was reviewed read-only by three independent AI reviewers (authorization ordering, the publish workflow, and the documentation and license preparation), and a separate skeptic tried to refute each finding. This is an automated review, not a GitHub approval. Of 22 findings, 20 were confirmed and 2 were not defects.

**Authorization ordering.** No security defect: an equivalence check on about 300,000 generated URLs and 3,851 authorization combinations found no behavior change in either validator, apart from which error appears when two things are wrong at once.

- Test evidence for the "before DNS" claim was weaker than the docs said (the tests patched the wrapper, not the resolver, and one of the three counted tests, the malformed one, was never DNS-ordered): **fixed.** The skeptic judged the second point not a defect in the code, since the behavior was always right, but the wording overstated what that test proved, so it is corrected too. The new resolver-boundary tests replace the old ones, and this file says what each test shows.
- No test pinned the early gate for `--preflight-only` or `--crawl`: **fixed.** `--resume-from` is **deferred**: the reviewer confirmed by experiment, with a real checkpoint, that no lookup happens, and an automated test needs a checkpoint fixture for a nit-level gain.

**Publish workflow.**

- The two pending trusted publishers could not both be registered with identical fields (PyPI's uniqueness rule ignores the project name), so a single publish run would have uploaded contracts and failed on the CLI: **was release-blocking, fixed** by the two-environment design. The PyPI registration itself is still an owner action.
- The webguard-only recovery mode never checked the contracts file on PyPI: **fixed**, and the mode is gone. The CLI job now verifies the contracts file by name and SHA-256 before uploading.
- The release check discarded the CLI's reported version, and the version-bump recovery omitted the hard-coded copies: **fixed** in the validator, in a unit test, and in `docs/RELEASING.md`.
- The pins check could be bypassed by `permissions: write-all`, ignored `- uses:` lines, and relied on loose substring tests with nothing enforcing the dry-run guards: **fixed**, with exact checks and a 20-variant mutation test.

**Documentation and license preparation.**

- `SECURITY.md` pointed at a disabled feature and gave no contact: **fixed** by enabling private vulnerability reporting and verifying it.
- The README overstated signing ("signed", "signature validation"): **fixed.** The authorization record is unsigned and SHA-256 fingerprinted.
- Exit code 130 was documented for all Ctrl-C, but a crawl exits 1 with a saved partial report: **fixed**, and the checkpoint behavior was verified by experiment.
- Any redirecting target is a failed scan: **fixed**, now a documented limitation.
- `results list` and `results clean` treated authorization audit records as scan results, so `clean` would delete them: **fixed in code, with a test.**
- The release notes said accounts and SOC or Compliance modules are not shipped, but the contracts wheel carries inert definitions from the retired platform: **fixed**, with the reachable and unreachable modules measured for both wheels. Trimming them is **deferred**: it would change a public package interface, and nothing in them runs unless imported.
- Yanking one release leaves an exactly pinned dependency installable; the partial-upload recovery assumed `main` had not moved; version-bump steps missed places; the license pull request left a `main` commit that step 2 never verified: **fixed** in `docs/RELEASING.md`.
- The README said the active-detection modules exist "only inside" `apps/api/`, and this checklist implied the `pipx` command is tested on Linux CI: **fixed.**
- `init` next steps print paths relative to the directory it ran in: **not a defect.** Both quick-start blocks run verbatim.
- `--lab --allow-host A http://B/` resolves B before reporting that B is not allowlisted: **deferred.** It is a lookup of a host the operator typed, which the README already describes, and it is outside this release's scope.

## Owner decisions (blocking publish, not engineering)

- [ ] **License.** Nothing in this repository is currently licensed for reuse. Pick one before any public "go ahead and use this" claim; see [`docs/LICENSE_OPTIONS.md`](LICENSE_OPTIONS.md) for the comparison and a recommendation (MIT), not applied. The change is prepared: `python scripts/apply-license.py --license <MIT|Apache-2.0> --holder "<name>" --dry-run` prints the exact diff, and `--apply` writes it. The only inputs are the license and, for MIT, the copyright holder's name.
- [ ] **Merge.** Pull request review and merge, then check CI on the resulting `main` commit.
- [ ] **PyPI trusted publishers.** Two pending publishers, one per project, with the distinct environments listed in [`docs/RELEASING.md`](RELEASING.md). Confirm both names are still unclaimed immediately beforehand.
- [ ] **Dry run, then publish.** Run the workflow in dry-run mode on `main`, read the summary, then authorize the `publish` run.
- [ ] **First GitHub release and tag.** Not cut. After a verified public install, tag `v0.1.0`, publish [`docs/RELEASE_NOTES_DRAFT.md`](RELEASE_NOTES_DRAFT.md) as the notes, and attach the built wheels.

## Explicitly out of scope for v1

- Active detection (XSS, SQLi, SSRF-callback, and the rest) wired into the CLI
- Windows support
- Any hosted or SaaS functionality (retired; see `docs/LEGACY_PLATFORM.md`)
