# Legacy platform documentation

This repository originally built a three-module hosted SaaS platform (WebGuard + SOC + Compliance): a multi-tenant web application, a PostgreSQL-backed API with cryptographic execution permits, and a React frontend. That direction is **retired**. The active product is the `webguard` CLI. See the root [README](../README.md) and [`docs/CLI_ARCHITECTURE.md`](CLI_ARCHITECTURE.md).

The documents below describe that retired platform. They are kept for historical and portfolio context (they describe real, tested engineering work, specifically around the archived `apps/api`/`apps/web` SaaS layer) but they are **not current** and do not describe the CLI:

- `ARCHITECTURE.md`, `ARCHITECTURE_DECISIONS.md`, `adr/`: SaaS system architecture and decision records
- `AUTHORIZATION_MODEL.md`: the SaaS platform's TrustScan permit and authorization-assignment model (the CLI's own authorization model is documented in the root README and is deliberately simpler; see "Authorization model" there)
- `CONNECTOR_CAPABILITIES.md`, `PLATFORM_SCOPE.md`, `PRODUCT_CHARTER.md`, `PRODUCT_VISION_TRACEABILITY.md`, `ROADMAP.md`: the three-module platform's product scope and roadmap
- `DATA_CLASSIFICATION.md`, `THREAT_MODEL.md`: SaaS multi-tenant data handling and threat model
- `IMPLEMENTATION_STATUS.md`, `PROJECT_EXECUTION_LEDGER.md`, `RELEASE_EVIDENCE.md`, `RELEASE_READINESS.md`, `NEXT_SESSION_HANDOFF.md`: the SaaS release's day-to-day execution record
- `CWE_COVERAGE.md`: written against the full active-detector set used by the archived SaaS orchestration layer (`apps/api/src/webguard_api/executor.py`), not the CLI's current passive-only scope

None of this material is deleted. `apps/web/`, the SaaS-specific parts of `apps/api/`, `infra/`, and these documents all remain in git history and on disk for traceability. They are simply out of scope for the CLI product going forward and are not part of the distributed `openhuntx-webguard` package.
