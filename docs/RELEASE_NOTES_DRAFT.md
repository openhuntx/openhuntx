# v0.1.0 (draft)

Not tagged yet. This is a draft to review and adjust once the open owner decisions in [`docs/CLI_RELEASE_CHECKLIST.md`](CLI_RELEASE_CHECKLIST.md) are settled, then publish as the actual GitHub release notes for the first tag.

## WebGuard: a terminal-only, authorized passive web security scanner

First release of WebGuard as a standalone CLI tool, pivoted from an earlier three-module hosted SaaS platform (see [`docs/CASE_STUDY.md`](CASE_STUDY.md) for that story).

### Install

```bash
pipx install openhuntx-webguard
```

This line belongs in the published notes only after the fresh public install check (step 7 of [`docs/RELEASING.md`](RELEASING.md)) has passed. To install from source instead:

```bash
git clone https://github.com/openhuntx/openhuntx.git
cd openhuntx
python3 -m pip wheel packages/contracts/python -w dist --no-deps
python3 -m pip wheel workers/scanner -w dist --no-deps
pipx install dist/openhuntx_webguard-0.1.0-py3-none-any.whl --pip-args="--no-index --find-links dist"
```

The [README](../README.md) quick-start runs as written against a local target.

### What's in it

- `webguard scan`: passive single-page and bounded same-origin crawl assessment (headers, cookies, CORS, TLS/certificate, disclosure checks)
- `webguard authorization create/validate/inspect`: self-attested, fingerprinted authorization records required before scanning an external target
- `webguard report validate/inspect/render/compare/validate-comparison`: deterministic findings, a professional HTML report, and remediation-comparison diffing
- `webguard init`, `webguard doctor`, `webguard results list/clean`: the local workspace and environment-diagnostic commands new in this release
- Stable, documented exit codes (`0` through `7`, `130`), including a fail-closed top-level exception boundary
- A malformed, expired, confirmation-mismatched, or out-of-scope authorization is rejected before any DNS lookup

### What's not in it

- Active detection (XSS, SQLi, SSRF-callback confirmation, etc.): present in the scanner library, not wired into the CLI yet
- Windows support: untested and not supported. Tested on Linux (CI, Python 3.11 to 3.14) and macOS (Python 3.14)
- The retired hosted SaaS platform (accounts, a web dashboard, the multi-tenant API, SOC and Compliance modules): archived and not shipped; see [`docs/LEGACY_PLATFORM.md`](LEGACY_PLATFORM.md). The two wheels do still contain inert code from it that the `webguard` command never uses: 13 active-detection library modules in `openhuntx-webguard`, and definitions for tenancy, compliance, scan jobs and schedules, permits, and safety receipts in `openhuntx-webguard-contracts`. [`docs/CLI_ARCHITECTURE.md`](CLI_ARCHITECTURE.md) lists exactly which modules the CLI reaches. Trimming them is planned for before 1.0

### Behavior worth knowing

- A target that answers with a redirect is reported as a failed scan (`request/redirect_blocked`, exit 1); WebGuard never follows redirects. Scan the final URL, with an authorization for that exact canonical URL
- Ctrl-C during a single-page scan exits 130 and writes nothing. During `--crawl` it stops the crawl, saves a partial report with status `cancelled` and the checkpoint if one was requested, and exits 1; `--resume-from` continues from that checkpoint
- The authorization record is unsigned and SHA-256 fingerprinted, not cryptographically signed

### Known gaps in this release

See [`docs/CLI_RELEASE_CHECKLIST.md`](CLI_RELEASE_CHECKLIST.md)'s "Owner decisions" section: no license is chosen yet, the PyPI package name is proposed but not confirmed, and the package isn't published yet.
