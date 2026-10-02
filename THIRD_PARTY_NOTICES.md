# OpenHuntX WebGuard Third-Party Notices

## Purpose

This file inventories third-party components directly referenced by the current repository configuration at the Checkpoint 1 baseline. It is an engineering notice, not a legal opinion and not a complete software bill of materials for every transitive component inside external container images or CI runner environments.

Release packaging must preserve all licence texts, notices, attribution, source-offer obligations, and other terms required by the actual distributed third-party components.

## Python packaging and runtime dependencies

| Component | Reviewed version | Role | Licence expression / licence |
| --- | --- | --- | --- |
| `pip` | `26.2.1` | Bootstrap installer used by the locked development/CI workflow | MIT |
| `setuptools` | `83.0.0` | Build backend for WebGuard Python packages | MIT |
| `cryptography` | `50.0.0` | Ed25519 signing and verification | Apache-2.0 OR BSD-3-Clause |
| `cffi` | `2.1.0` | Transitive dependency used by `cryptography` on supported platforms | MIT-0 |
| `pycparser` | `3.0` | Transitive dependency of `cffi` | BSD-3-Clause |
| `ruff` | `0.16.2` | Static Python security analysis in the CI security gate | MIT |

Runtime/build versions and artifact hashes are controlled by `requirements-bootstrap.lock` and `requirements-ci.lock`. Security-tool versions and reviewed platform hashes are controlled by `requirements-security.lock`.

## Authorised integration target

| Component | Reviewed reference | Role | Licence |
| --- | --- | --- | --- |
| OWASP Juice Shop | `v20.1.1` plus pinned OCI digest | Intentionally vulnerable local integration target | MIT |

OWASP Juice Shop is not part of the WebGuard production runtime. It is an explicitly enabled test target. The container image contains additional third-party components whose licences/notices are governed by the image/project distribution; this file does not attempt to enumerate the container's full transitive dependency tree.

## GitHub Actions used by CI

| Component | Pinning model | Role | Licence |
| --- | --- | --- | --- |
| `actions/checkout` | Immutable commit SHA | Repository checkout | MIT |
| `actions/setup-python` | Immutable commit SHA | Python/tool setup | MIT |

The exact reviewed commit SHAs are defined in `.github/workflows/ci.yml` and verified by `scripts/verify-supply-chain-pins.py`.

## OpenHuntX-owned packages

These packages are first-party WebGuard components and are not third-party notices:

- `openhuntx-webguard-contracts`;
- `openhuntx-webguard` (the CLI, the `workers/scanner` package; distributed under this name as of the CLI release, formerly `openhuntx-webguard-scanner`); and
- `openhuntx-webguard-api` (archived, see `docs/LEGACY_PLATFORM.md`).

Their distribution licence must be defined by OpenHuntX before an external source/binary distribution that requires such a licence declaration.

## Verification and release rule

Before a commercial release:

1. generate an SBOM or equivalent dependency inventory from the exact release build;
2. compare it with this notice and the reviewed lock files;
3. include required upstream licence texts/notices in the release package or distribution channel;
4. review licences of newly introduced dependencies before merge; and
5. treat container-image transitive dependencies separately rather than assuming this direct-dependency table is exhaustive.
