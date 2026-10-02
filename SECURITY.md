# WebGuard Security Policy

## Product status

WebGuard is a local, terminal-only CLI tool under active pre-1.0 development. It is not a hosted service: there is no server, account, or network call besides the HTTP(S) request it sends to the target you name.

An archived, no-longer-maintained multi-tenant SaaS layer exists in this repository's history (`apps/api`, `apps/web`). See [`docs/LEGACY_PLATFORM.md`](docs/LEGACY_PLATFORM.md). This policy describes the active CLI product, not that archived layer.

## Supported versions

| Version or branch | Security support |
| --- | --- |
| Current `main` branch | Supported for active development and security fixes |
| Historical commits/tags | Not independently supported |

There is no formal backport policy yet; fixes land against `main`.

## Reporting a vulnerability

Do not open a public GitHub issue containing exploit details, credentials, target information, or scan artifacts.

Report privately through GitHub: open <https://github.com/openhuntx/openhuntx/security/advisories/new>, or use the "Report a vulnerability" button on the repository's Security tab. Private vulnerability reporting is enabled for this repository, and the report is visible only to the maintainers until they choose to publish an advisory. There is no separate security email address.

Include, if known:

- affected WebGuard version or commit;
- affected command or module;
- technical impact (e.g. scope bypass, SSRF, path traversal in local file handling, authorization-check bypass);
- reproducible steps or a minimal proof of concept;
- suggested remediation.

Do not include real target credentials, API keys, or any third party's data. Redact them first.

## Scope of authorized testing

WebGuard must only be used against targets the operator owns or is explicitly authorized to assess. A reachable hostname or working HTTP endpoint does not by itself establish permission to test it. The CLI's authorization document (`webguard authorization create`) is self-attested, fingerprinted, local record-keeping: it records what the operator asserted, not independently-verified legal permission.

Do not use testing WebGuard itself as a reason to send traffic to an unrelated third-party target. Use an isolated lab target (`--lab`) or a system you have explicit permission to test.

## Current security boundaries

- Fail-closed preflight: scope/authorization/policy checks run and can reject a scan before any request is sent.
- Scope validation and SSRF-safe target resolution (`scope_validator.py`, `safe_http.py`): rejects private/reserved address ranges outside explicit `--lab --allow-host` mode, blocks redirects during a scan, enforces bounded request/body/header limits.
- Locally stored authorization documents, scan results, and reports are written with `0600` file permissions inside `0700` directories, and refuse to follow a symlink at the destination path.
- HMAC-signed crawl checkpoints, so a resumed crawl can't be tampered with or resumed against a different scan.
- A fail-closed top-level exception boundary in `cli.py`'s `main()`: an unexpected error exits with a dedicated, documented code (`6`) and a visible message, rather than a silent partial result.
- No telemetry, no phone-home, no update check.

These controls reduce risk but do not prove a target is secure, and do not prove the operator has legal authority to test it.

## Secrets and sensitive local data

The following should never be committed to version control and are already covered by `.gitignore`:

- `authorizations/`, `scan-results/`, `reports/` (or any directory you pointed `webguard` at with `--output`/`--directory`);
- crawl-checkpoint signing keys;
- scan reports and findings, which may describe a real target's security posture.

If you believe a secret or sensitive scan artifact was accidentally committed, treat it as compromised, rotate/regenerate it, and report it as described above rather than opening a public issue about it.

## Security design documentation

- [`docs/CLI_ARCHITECTURE.md`](docs/CLI_ARCHITECTURE.md): current CLI architecture and package boundaries.
- [`README.md`](README.md): authorization model, security decisions and trade-offs, exit codes.
- [`docs/LEGACY_PLATFORM.md`](docs/LEGACY_PLATFORM.md): pointers into the archived SaaS platform's own (no-longer-current) threat model and architecture docs, for historical reference only.
