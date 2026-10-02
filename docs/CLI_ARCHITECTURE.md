# CLI architecture

## Diagram

```
                         your terminal
                              |
                              v
                      +---------------+
                      |  webguard CLI |   workers/scanner/src/webguard_scanner/cli.py
                      +---------------+
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
        scan / crawl    authorization     report
        (passive HTTP,  create/validate/  validate/inspect/
         TLS, headers)  inspect           render/compare
              |               |               |
              v               v               v
        safe_http.py    owned_target.py  professional_report.py
        scope_validator.py (scope/redirect/      report_loader.py (contracts)
        (SSRF-safe        private-range
         resolution)      enforcement)
              |
              v
      +-------------------+        +------------------------------+
      |  target you name  |        |  local filesystem only:      |
      |  (HTTP/HTTPS)     |        |  scan-results/, reports/,     |
      +-------------------+        |  authorizations/ (0700 dirs,  |
                                    |  0600 files)                  |
                                    +------------------------------+

      webguard_contracts  <-- shared data types (findings, scan results,
      (zero dependencies)      authorization documents, reports) used by
                                both the CLI above and the archived SaaS
                                layer below. No code flows the other way.

      ---------------------------------------------------------------
      archived, NOT part of the distributed CLI package, kept for history:

      apps/web/   (React SPA)  --calls-->  apps/api/  (multi-tenant API:
                                             accounts, PostgreSQL, TrustScan
                                             permits, SOC/Compliance modules)
                                                  |
                                                  v
                                          webguard_scanner  (same library,
                                          invoked via apps/api/executor.py,
                                          which also wires in the active-
                                          detection modules the CLI doesn't
                                          expose yet)
```

## Why this split

The monorepo already had three independent Python packages before this release:

| Package | Depends on | Ships in the CLI wheel? |
|---|---|---|
| `openhuntx-webguard-contracts` (`packages/contracts/python`) | nothing | yes |
| `openhuntx-webguard` (`workers/scanner`) | contracts only | yes, this *is* the CLI |
| `openhuntx-webguard-api` (`apps/api`) | contracts, scanner, PostgreSQL, KMS/HSM signing, Argon2, DNS | no |

`workers/scanner` already had zero import-time dependency on `apps/api` and already declared its own `webguard` console-script entry point (`workers/scanner/pyproject.toml`). Building and distributing `workers/scanner` on its own, rather than writing a new CLI from scratch or trying to strip the API package down, was the smallest change that produces a correct, complete, standalone tool: `pip wheel workers/scanner` naturally excludes every line of `apps/api` and `apps/web`, with no manual file-exclusion list to maintain or get wrong. The package itself is named `openhuntx-webguard` (renamed from the original `openhuntx-webguard-scanner` once it became a standalone product rather than one component among several); the `webguard` command name hasn't changed.

This also means the two products can't accidentally share a trust boundary. The CLI's authorization model (self-attested, fingerprinted, no central identity) and the archived SaaS layer's model (centrally issued accounts, cryptographic TrustScan permits) are different designs for different problems, and neither package can reach into the other's code to blur that line.

## What changed in this release

Everything below was added to `workers/scanner/src/webguard_scanner/cli.py`; nothing in the scan/authorization/report engine itself needed to change to become a CLI product, it already was one.

- `webguard init`: scaffolds `authorizations/`, `scan-results/`, `reports/` with `0700` permissions.
- `webguard doctor`: environment diagnostics (Python version, package versions, write access, free disk space) with **no network calls**; target reachability is intentionally left to each scan's own preflight, not duplicated here.
- `webguard results list` / `webguard results clean`: list or prune stored scan-result files in a directory, including graceful handling of unreadable/corrupt files and a dry-run-by-default delete.
- A fail-closed catch-all in `main()`: unhandled exceptions now exit `6` with the exception type and message instead of a raw traceback or (if ever introduced by a future bug) silently reporting success; `Ctrl-C` now exits `130` with a clean message instead of a stack trace.

See the root [README](../README.md) for the full command reference and [`docs/CASE_STUDY.md`](CASE_STUDY.md) for the reasoning behind the broader pivot from a hosted platform to a CLI tool.

## What the wheels contain

Measured by following imports from the `webguard` entry point (`workers/scanner/src/webguard_scanner/cli.py`), not by inspection of names.

The `openhuntx-webguard` wheel has 35 modules; the CLI reaches 21 of them. The other 13 are the active-detection library, which the CLI never calls: `active_candidate_discovery`, `active_detection`, `active_detector_registry`, `attack_surface`, `authorization_crawl`, `callback_broker`, `idor_authorization_detector`, `login_workflow`, `request_template`, `resource_graph`, `sqli_error_detector`, `ssrf_callback_detector`, and `xss_reflected_detector`. (`__main__` only forwards to the CLI.) Only the archived platform layer called them, and the `webguard` command exposes no way to run them.

The `openhuntx-webguard-contracts` wheel has 15 modules; the CLI-reachable code uses definitions from 7 of them: `crawl_checkpoints`, `crawl_scans`, `findings`, `owned_targets`, `report_loader`, `reporting`, and `scans`. The other 7 are definitions from the retired platform that the CLI never uses: `compliance`, `compliance_scope`, `safety_receipts`, `scan_jobs`, `scan_permits`, `scan_schedules`, and `tenancy`. The package's `__init__` imports and re-exports all of them, so they load at import time, but they are inert data types with no behavior the CLI invokes.

None of this is a release blocker: nothing in it runs unless someone imports it directly, and the README says so. Trimming both wheels is a reasonable change before 1.0, but it would reshape a public package interface, so it is deliberately not part of this release.
