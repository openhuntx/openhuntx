# Case study: from a three-module SaaS platform to a CLI tool

## The problem this demonstrates

Most portfolio security tools are either a single script with no safety rails, or an abandoned attempt at a full SaaS platform that never shipped. This project went through the second path first, and the interesting engineering decision wasn't building the platform. It was recognizing when to stop building it and ship something smaller and finished instead.

## What was built first

The original direction was OpenHuntX: a multi-tenant hosted platform with three modules (WebGuard for web scanning, SOC for security operations, Compliance for control assurance), a PostgreSQL-backed API with row-level tenant isolation, cryptographically signed execution permits (TrustScan), account creation and team invitations, and a React frontend. That work is real and is preserved in this repository's history (see [`docs/LEGACY_PLATFORM.md`](LEGACY_PLATFORM.md)): tenant-isolation policies proven against a disposable PostgreSQL instance, signed crawl checkpoints, a fail-closed authorization/permit revalidation chain at every outbound request boundary, and an SSRF-safe scanning engine with redirect-blocking, scope validation, and bounded resource limits.

It also was, honestly, more surface area than one person could finish and responsibly operate: live multi-tenant infrastructure, billing-shaped entitlements, SOC connectors that needed real vendor tenant credentials nobody had, and a Compliance framework catalog that needed authoritative legal-text review before it could claim anything. None of that is needed to demonstrate the actual engineering skill underneath it: the scanning engine, the safety model, and the authorization discipline.

## The pivot

The decision: stop building the hosted platform, and ship the part that was already a complete, working, well-tested engine, `workers/scanner`, as a standalone CLI. Concretely:

- The scanner package already had zero import-time dependency on the multi-tenant API layer, and already declared its own `webguard` console-script entry point. That was discovered by reading the code, not assumed; see [`docs/CLI_ARCHITECTURE.md`](CLI_ARCHITECTURE.md) for what that investigation found.
- What the CLI was missing wasn't a scanning engine, it was terminal UX: a way to check your environment (`doctor`), scaffold a workspace (`init`), and manage locally stored results (`results list`/`clean`), plus a fail-closed top-level exception boundary that a one-person CLI tool needs and a supervised service process didn't.
- Active-detection capability (XSS, SQLi, SSRF-callback confirmation) that existed in the library but was wired only into the archived multi-tenant orchestration layer was explicitly left out of v1 rather than rushed into the CLI. It depends on a callback-receiving design the CLI doesn't have yet, and shipping it half-wired would have been worse than documenting it as a known gap.
- The hosted web app, the tenancy/billing/TrustScan-permit layers of the API, and the SOC/Compliance modules were retired from the active roadmap without deleting any of it, preserved as archived history rather than presented as part of the current product.

## What this demonstrates

- **Scope judgment**: recognizing that a smaller, finished, honestly-documented tool is worth more than a larger, partially-built platform, and making that call explicitly rather than letting scope drift.
- **Security-first defaults carried through, not bolted on**: fail-closed preflight, scope/redirect validation, restrictive file permissions, signed checkpoints, and a self-attested-but-still-enforced authorization model that fits a single-user CLI's actual trust boundary instead of copying a multi-tenant SaaS pattern that doesn't apply.
- **Honest limitation disclosure**: the README states plainly what's untested (Windows), what's deferred (active detection), and which decisions were left to the owner (license, package name) rather than presenting the tool as more finished than it is.

## On AI assistance

This repository's recent history, including the SaaS-to-CLI pivot documented here, was built with Claude Code (Anthropic's CLI agent) as a hands-on implementation collaborator, under direction from the project owner: the owner set the direction (including the decision to retire the hosted platform and ship a CLI), reviewed and directed the resulting architecture, and made the calls that needed human judgment (what to scope out, what to preserve, what to flag rather than silently decide, like the license choice and the package name). Claude Code wrote and tested a substantial share of the code, tests, CI changes, and documentation in this repository under that direction. This disclosure is here because an accurate account of how the work got built is part of being honest about what this project demonstrates, not because either part of that collaboration is hidden elsewhere in the repository.

No users, customers, deployments, or certifications are claimed anywhere in this repository. Where this document or the README describe something as tested, it means it was actually run and observed during this development process. See the "Tested platforms" section of the root README for exactly what that covered.
