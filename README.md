# WebGuard

A terminal-only tool for authorized passive web security assessment: point it at a target you own or are authorized to test, and it checks HTTP headers, cookies, CORS, TLS/certificate configuration, and common disclosure issues, then writes a JSON report and a professional HTML write-up.

> **Status:** active development, pre-1.0. No hosted service, no account, no telemetry. Everything runs on your machine against targets you specify.

## Who this is for

Developers, freelance security practitioners, and small teams who want a quick, scriptable, authorized-only check of a web asset's passive security posture: from a terminal, in CI, or as a building block in a larger authorized assessment workflow, without standing up a server, a database, or an account anywhere.

This is **not** a vulnerability-exploitation tool, a SaaS platform, or a replacement for a full penetration test. It does not submit forms, run JavaScript, inject payloads, brute-force anything, or follow redirects during a scan.

## What it actually does today

WebGuard v1 is **passive-only**:

- fetches the target once (`scan`) or crawls bounded same-origin pages (`scan --crawl`)
- analyzes HTTP response headers (CSP, HSTS, X-Content-Type-Options, frame protection, Referrer-Policy, Server-header disclosure, cookie flags, CORS configuration)
- analyzes TLS/certificate configuration for HTTPS targets (protocol, cipher, chain, hostname match, expiry)
- produces a deterministic, fingerprint-stable findings report you can diff between runs (`report compare`) to prove remediation
- never submits forms, executes JavaScript, injects payloads, brute-forces, or follows redirects

The scanner library (`webguard_scanner`) also contains active-detection modules (reflected XSS, SQL error-based injection, SSRF callback confirmation, IDOR, login-workflow analysis), but as of this release they are **not wired into the CLI's `scan` command**. They ship in the `openhuntx-webguard` wheel as library code, and the only thing that calls them today is the archived multi-tenant SaaS orchestration layer (`apps/api/`, see [Project history](#project-history) below), which relied on a signed execution permit and a callback-receiving service that a local CLI doesn't have. The `webguard` command never reaches them. Exposing them from the CLI (for example behind an explicit `--active-check` flag, with its own authorization and callback-handling story) is tracked as the main piece of future work. See [Known limitations](#known-limitations--whats-next).

## Install

The distributed package is `openhuntx-webguard`; it installs a single `webguard` command. It depends on one other first-party package, `openhuntx-webguard-contracts` (shared data types, zero third-party dependencies of its own), and nothing else. Requires Python 3.11 through 3.14.

### From source (available now)

Nothing is on PyPI yet, so today you build the two wheels yourself and install them together. This is the sequence this repository's CI (`.github/workflows/ci.yml`, the `cli-packaging` job) runs on every pull request, and the one that was run through a real `pipx install` on macOS:

```bash
git clone https://github.com/openhuntx/openhuntx.git
cd openhuntx

python3 -m pip wheel packages/contracts/python -w dist --no-deps
python3 -m pip wheel workers/scanner -w dist --no-deps

pipx install dist/openhuntx_webguard-0.1.0-py3-none-any.whl \
  --pip-args="--no-index --find-links dist"
```

`--find-links dist` is what lets pip find `openhuntx-webguard-contracts` in the second wheel instead of on PyPI.

### From PyPI (not available yet, unverified)

Once both packages are published, installation is meant to be one command, with pip resolving the contracts dependency on its own:

```bash
pipx install openhuntx-webguard
```

Until publication that command fails with "no matching distribution", and it has never been run against the real PyPI. What has been verified is the mechanism it relies on: both wheels, served from a local PEP 503 package index, installed with no `--find-links`, and pip pulled in `openhuntx-webguard-contracts==0.1.0` from the wheel's own metadata. `docs/RELEASING.md` has the release sequence, including the fresh-install check that closes this gap after publication.

## Quickstart

Every command in these two blocks runs as written (they are executed verbatim as part of release verification), assuming `webguard` is installed. Nothing here touches a host you don't control.

### 1. Scan a local target

This sets up a throwaway web server on your own machine, scans it, renders a report, and diffs two scans. `--lab` with an explicit `--allow-host` is the supported way to scan a loopback or private-network target, and it needs no authorization document.

```bash
webguard init --directory webguard-demo
cd webguard-demo
webguard doctor

mkdir site
echo '<h1>demo</h1>' > site/index.html
python3 -m http.server 8931 --bind 127.0.0.1 --directory site > /dev/null 2>&1 &
SERVER_PID=$!
sleep 1

webguard scan http://127.0.0.1:8931/ --lab --allow-host 127.0.0.1 \
  --output scan-results/demo.json
webguard results list
webguard report render scan-results/demo.json \
  --output reports/demo.html --organization "Demo"

webguard scan http://127.0.0.1:8931/ --lab --allow-host 127.0.0.1 \
  --output scan-results/demo-rescan.json
webguard report compare scan-results/demo.json scan-results/demo-rescan.json \
  --output reports/demo-comparison.json

kill "$SERVER_PID"
webguard results clean --yes
```

### 2. The authorization flow for a real target

Scanning anything that is not a lab target needs an authorization document and an exact confirmation of its ID. Run this in the same shell, from the `webguard-demo` directory the first block left you in. It walks through that flow against `example.com`, IANA's reserved documentation domain, and stops at `--preflight-only`: it checks the authorization, the HTTPS requirement, and that the host resolves to public addresses, then prints "No HTTP request was sent." The one network activity is a DNS lookup of the hostname.

```bash
AUTH_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"

webguard authorization create https://example.com \
  --authorization-id "$AUTH_ID" \
  --organization "Example, Inc." \
  --authorized-by "you@example.com" \
  --purpose "Walkthrough of the authorization flow" \
  --output authorizations/example.json

webguard authorization validate authorizations/example.json

webguard scan https://example.com \
  --authorization-file authorizations/example.json \
  --confirm-authorization "$AUTH_ID" \
  --preflight-only
```

To scan for real, create the authorization for a site you own or are authorized to assess, then run the same `scan` command without `--preflight-only` and with `--output scan-results/your-site.json`. `webguard scan --help` lists the crawl, checkpoint, and limit options.

### Terminal demo

The first scan from the block above, as printed except that the seven `web.tls.*` skip lines are collapsed into one (the scan ID and timings differ on every run):

```
$ webguard scan http://127.0.0.1:8931/ --lab --allow-host 127.0.0.1 --output scan-results/demo.json
Scan ID: d90de307-8e25-4fbb-a8a3-522dd24e2406
Status: completed
Target: http://127.0.0.1:8931/
Engine: webguard-native 0.1.0
Connected addresses: 127.0.0.1
HTTP statuses: 200
Requests: 1 attempted, 1 succeeded
Coverage: 80.0%
Findings: 5
Errors: 0
- [LOW] Referrer-Policy header missing (web.headers.referrer_policy.missing)
- [MEDIUM] Content-Security-Policy header missing (web.headers.csp.missing)
- [LOW] Server header exposes software version information (web.disclosure.server.version)
- [MEDIUM] Clickjacking frame protection missing (web.headers.frame_protection.missing)
- [LOW] X-Content-Type-Options header missing (web.headers.x_content_type_options.missing)
- [SKIPPED] web.headers.hsts: HSTS applies only to HTTPS responses and was not evaluated for this HTTP target.
- [SKIPPED] web.tls.*: TLS and certificate analysis applies only to HTTPS targets (7 checks skipped).
- [ATTEMPT 1] succeeded: 127.0.0.1, HTTP 200, 2 ms
Saved report: scan-results/demo.json
```

A second, committed example lives in [`examples/`](examples/): a small synthetic server, the unedited JSON report a scan of it produced, and the rendered HTML. No paid infrastructure or external target is needed to reproduce it; see [`examples/README.md`](examples/README.md).

## Every command

```
webguard --version
webguard doctor    [--directory PATH]
webguard init      [--directory PATH]
webguard scan      <target-url> [--lab --allow-host HOST | --authorization-file PATH --confirm-authorization ID]
                    [--crawl] [--checkpoint PATH --checkpoint-key-file PATH] [--preflight-only] ...
webguard authorization create   <target-url> --organization ... --authorized-by ... --purpose ... --output PATH
webguard authorization validate <authorization-file>
webguard authorization inspect  <authorization-file> [--json]
webguard report validate  <report-file>
webguard report inspect   <report-file> [--json]
webguard report render    <report-file> --output PATH --organization NAME [--baseline PATH]
webguard report compare   <baseline-report> <current-report> --output PATH
webguard report validate-comparison <comparison-file>
webguard results list  [--directory PATH] [--json]
webguard results clean [--directory PATH] [--older-than-days N] [--yes]
```

Run `webguard <command> --help` or `webguard <command> <subcommand> --help` for the full flag reference; every destructive or scope-widening flag (`--lab`, `--confirm-authorization`, `--overwrite`, `results clean --yes`) requires an explicit, exact value, and there are no silent defaults that widen scope.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Scan failed, or a crawl was cancelled with Ctrl-C (the partial report is still saved) |
| `2` | Usage error (bad arguments) |
| `3` | Preflight failed (authorization/scope/policy rejected before any request was sent) |
| `4` | Report invalid (failed strict schema validation) |
| `5` | Output failed (couldn't write a file: permissions, existing file without `--overwrite`, disk full) |
| `6` | Unexpected error (an unhandled exception, reported with its type and message, never silently swallowed) |
| `7` | `doctor` found a problem with the local environment |
| `130` | Ctrl-C during a single-page scan (nothing is written) |

These are stable and intended to be scripted against.

Ctrl-C behaves differently in the two scan modes, on purpose. In a single-page scan there is nothing worth saving, so it prints `webguard: cancelled.`, writes no files, and exits `130`. During `--crawl` it stops the crawl cleanly instead: the partial report is saved with status `cancelled`, a `--checkpoint` file is saved too if you asked for one, and the exit code is `1`. Pass the same checkpoint and key file back with `--resume-from` to continue where the crawl stopped.

## How it stores things locally

There is no database, background service, or daemon. `webguard init` creates three plain-file directories (`authorizations/`, `scan-results/`, `reports/`) with `0700` permissions; every file `webguard` writes into them is created `0600` (owner read/write only, refusing to follow a symlink at the destination). `webguard results list`/`clean` just read and delete files in a directory you point it at: there's no hidden index to get out of sync. They skip `*.authorization-audit.json`, the evidence record a scan with an authorization writes beside its report, so `results clean` never deletes one.

The only network activity is a DNS lookup of the target's hostname and the HTTP(S) requests to that target (in crawl mode, to same-origin pages of it). There is no telemetry, no update check, and no account, and nothing is sent to any other host.

## Authorization model

Every scan against a real external target requires a self-attested authorization document (`webguard authorization create`): organization, authorized-by, purpose, allowed hosts, an expiry, and a set of effective limits, written out as fingerprinted JSON and re-validated (hostname canonicalization, expiry, exact ID confirmation) at scan time. It is **not cryptographically signed**: there's deliberately no PKI or central identity service behind it. For a tool one person runs locally against targets they assert they're authorized to test, an unsigned, SHA-256-fingerprinted local record that the scanner refuses to proceed without is the right amount of ceremony; a centrally-attested identity system is the right tool for a multi-tenant service brokering trust between strangers, which is what the archived SaaS layer in `apps/api/` built instead (see below). Don't read "self-attested" as "unenforced": the CLI still fails closed on a missing, expired, mismatched, or non-exact-match authorization before sending a single byte.

Isolated lab targets (`--lab --allow-host ...`, e.g. a local OWASP Juice Shop container) skip the authorization-document requirement entirely, since there is no second party whose authorization needs recording.

## Security decisions and trade-offs

- **Fail closed, not fail open.** Preflight (scope validation, authorization checks, policy limits) runs and can reject a scan *before* any network request is sent. `main()` now has a catch-all exception boundary (exit `6`) so an unexpected bug surfaces as a reported error, not a silent partial scan or a raw traceback.
- **Passive-only by design, not by accident.** v1 deliberately ships without active payload injection. The detection modules for that exist in the library (see above) and are deferred, not abandoned: shipping them requires designing a local callback-receiving story that doesn't depend on the archived SaaS layer's tenant-scoped callback broker.
- **Restrictive file permissions over access control.** Since this is a single-user local tool, authorization records, scan results, and reports are protected with filesystem permissions (`0600`/`0700`) rather than an application-level access-control layer, which would be the wrong tool for a single OS user.
- **No background service, no attack surface when idle.** `webguard` only runs when invoked and only makes outbound requests to the target you name.
- **Signed, resumable crawl checkpoints.** A crawl's progress checkpoint is HMAC-signed with a key you control, so a resumed crawl can't be tampered with or resumed against a different scan.

## Tested platforms

The wheels are pure Python (`py3-none-any`), but "pure Python" is not a test result. This is what has actually been run:

- **Linux** (GitHub Actions, `ubuntu-24.04`): the full unit suite on Python 3.11.15, 3.12.13, 3.13.14, and 3.14.6 on every pull request, plus the `cli-packaging` job on Python 3.13.14 only, which builds both wheels, installs them into a clean virtual environment, runs `pip check`, and drives the installed CLI through a synthetic scan.
- **macOS** (Darwin 25.6, Python 3.14.7, run by hand): a real `pipx install` from locally built wheels, then the quick-start above from outside the repository checkout.
- **Windows**: not tested, and not supported. Nothing in the scanner is deliberately POSIX-only, but the `0600`/`0700` file permissions and the symlink-refusal checks depend on POSIX file-mode behavior that Windows handles differently, and nobody has run it there.

No scan of a real third-party target has been performed as part of verifying this release. The authorization flow is covered by unit tests with the network edges replaced by fixtures, by rejection runs against unresolvable `.invalid` hostnames, and by the `--preflight-only` walkthrough above, which stops before any HTTP request.

## Known limitations / what's next

- Active detection (XSS, SQLi, SSRF-callback confirmation, IDOR, path traversal, command injection, and more) exists in `webguard_scanner` as a library but has no CLI command wiring it up yet.
- Authorization is self-attested and fingerprinted, not cryptographically signed: there is no delegated-authority verification proving the person running `authorization create` actually has the legal right to authorize testing of the target, only that they asserted it.
- A target that answers with a redirect is reported as a failed scan (`request/redirect_blocked`, exit `1`), because WebGuard never follows redirects. Scan the final URL, and create its authorization for that exact canonical URL.
- The wheels carry code the `webguard` command does not use: 13 active-detection library modules in the scanner wheel, and definitions for the retired platform (tenancy, compliance, scan jobs and schedules, permits, safety receipts) in the contracts wheel. They are inert and unsupported, and trimming them is deferred. `docs/CLI_ARCHITECTURE.md` lists exactly which modules are reachable.
- Not on PyPI yet, and the public `pipx install openhuntx-webguard` path is unverified until it is. See [Project status](#project-status--owner-decisions-still-needed).
- No license file yet. Same section.
- Windows is untested.
- `results clean --older-than-days` and `list` work on one flat directory; there's no cross-directory or recursive index.
- Solo-maintainer project: issue/PR response times are best-effort.

## Project history

WebGuard started as part of a three-module hosted SaaS platform (WebGuard + SOC + Compliance, a multi-tenant web application with its own PostgreSQL-backed API and React frontend). That direction has been **retired**. The hosted web app (`apps/web/`), the multi-tenant API's SaaS-specific layers (tenancy, billing-shaped entitlements, TrustScan permits, the SOC/Compliance modules) in `apps/api/`, and the deployment/infrastructure work under `infra/` are preserved in this repository's history as archived context. They are not deleted, not actively maintained, and not part of the distributed CLI package, but they are no longer the product. `docs/` still contains the platform-era design documents; see [`docs/LEGACY_PLATFORM.md`](docs/LEGACY_PLATFORM.md) for what's archived versus current.

The active product is exactly what's in `packages/contracts/` and `workers/scanner/`, installed as the single `openhuntx-webguard` package with its `webguard` entry point. See [`docs/CLI_ARCHITECTURE.md`](docs/CLI_ARCHITECTURE.md) for the architecture diagram and the reasoning behind that split, and [`docs/CASE_STUDY.md`](docs/CASE_STUDY.md) for a portfolio write-up of this pivot.

## Project status / owner decisions still needed

This is pre-release work, not a public release. Source installation works today; everything below is what stands between this and a published package.

- **No license chosen yet.** Nothing in this repository is currently licensed for reuse by anyone other than the copyright holder. This needs an explicit decision before any public use is invited; it is intentionally not silently defaulted here. See [`docs/LICENSE_OPTIONS.md`](docs/LICENSE_OPTIONS.md) for a comparison and a recommendation (MIT), neither of which has been applied. The exact file and metadata changes for either choice are prepared in `scripts/apply-license.py`; running it is the only step left once a license is picked.
- **Not published to PyPI.** `openhuntx-webguard` and `openhuntx-webguard-contracts` are the two project names the release needs, and both were unclaimed when last checked. Re-check immediately before publishing, since names can be claimed at any time. Publishing is a manual workflow (`.github/workflows/publish.yml`) that has never been run: a build job with no publishing permission, then one publish job per project, each in its own GitHub environment. [`docs/RELEASING.md`](docs/RELEASING.md) has the sequence, the two trusted-publisher configurations, and how to recover if only one package uploads.
- **No GitHub release has been cut.**

## Responsible use

Only run WebGuard against systems you own or have explicit, documented authorization to assess. A reachable hostname or working HTTP endpoint is not, by itself, permission to test it. This tool performs no exploitation, brute-forcing, or active payload injection in its current form, but authorization is still required for passive scanning, including header and TLS analysis.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Security issues: see [`SECURITY.md`](SECURITY.md); do not open a public issue with exploit details or target information.
