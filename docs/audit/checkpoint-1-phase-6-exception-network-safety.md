# Audit Checkpoint 1 — Phase 6: Exception & Network Safety

## Status

Technical audit completed.

Phase 6 assessed WebGuard's exception-handling boundaries across the service
API, worker, scheduler, and job executor, together with the scanner's HTTP
wire-level network-safety controls: DNS pinning, redirect blocking, response
bounding, per-address fallback, and overall request timing.

Eighteen product findings were confirmed during this phase:

- **Medium — An unexpected service-handler exception returned a raw transport failure and a server-side traceback.**
- **P6-001 — Medium — A negative chunked-transfer chunk size bypassed the configured body-size limit.**
- **P6-002 — Low — A non-ASCII or excessively long `Content-Length` value raised an uncontrolled `ValueError`.**
- **C-1 — Low — A target-controlled response-header value could crash the whole scan via the Evidence contract's length limit.**
- **C-2 — Low — Another tenant's invalid authorization document name and content could leak into an unrelated lookup's error message.**
- **C-3 — Low — A target-validation failure disclosed the resolved private address in the job error message.**
- **C-4 — Low — An artifact-directory failure disclosed the operator's server-side filesystem path.**
- **C-5 — Medium — A corrupted persisted job or schedule row raised an uncontrolled contract-validation error instead of a store error.**
- **C-6 — Medium — Several identity-store reads were unwrapped against SQLite operational failures.**
- **C-7 — High — The worker and scheduler polling loops died permanently on the first exception their own `run_once` did not already convert.**
- **C-8 — High — Lease-recovery retry was completely and reproducibly broken by a job-id-only audit-artifact path.**
- **P6-003 — Medium — A non-ASCII URL path crashed the scan and permanently poisoned crawl-checkpoint resume.**
- **P6-004 — Low — An out-of-range HTTP status code (600–999) passed the wire layer unchecked and only failed the contract after the request had already run.**
- **P6-005 — Medium — The per-address connection fallback could silently send a second real request under one safety-hook accounting decision.**
- **P6-006 — Medium — No overall wall-clock deadline bounded a request; a byte-at-a-time response could stall it far past the configured timeout.**
- **P6-007 — Low — An unexpected scanner exception after real network traffic left no signed safety receipt.**
- **P6-009 — Low — A runtime permit-binding lookup failure during active scanning was unwrapped against store errors.**
- **C-9 — Low — The CLI `report compare` command raised a raw, uncaught exception when comparing a report against itself.**

All confirmed findings were remediated and regression-tested before Phase 6
technical closure.

Two High severity findings were identified during Phase 6 (C-7, C-8) — the
highest severity of any Checkpoint 1 phase to date. Both were fully broken,
100%-reproducible operational-safety guarantees rather than edge cases.

One finding was reviewed and dismissed rather than fixed, with justification:

- **P6-008 — Low/Info — The scanner CLI's `main()` has no catch-all for an unexpected handler bug**, symmetric with the same, already-accepted gap in the service CLI (`apps/api/src/webguard_api/cli.py`). Both are operator-only surfaces with shell access already; a raw traceback there is an ergonomics gap, not a tenant-visible disclosure. Left undisturbed for consistency with that earlier decision.

Three theoretical concerns raised during investigation were reviewed and
found not exploitable in the current codebase:

- **T-a** — `PRAGMA` statements executed outside the SQLite connect try/except in `identity.py` — the surrounding open already fails closed; unreachable in practice.
- **T-b** — the worker's per-job lease-monitor thread only catches `JobStoreError` from `is_cancellation_requested`/`renew_lease` — both underlying store methods were independently confirmed to wrap every SQLite failure into `JobStoreError` already (including by this phase's own C-5 fix), so no other exception type can reach that catch.
- **T-c** — `after_request` is skipped when a non-`SafeRequestError` exception aborts a scan — inconsequential because the scan itself terminates at the same point regardless.

No Critical severity findings were identified during Phase 6.

---

## Audit Scope

Phase 6 focused on two related surfaces: what happens when something goes
wrong, and what WebGuard actually sends over the network while it is
running.

Primary areas reviewed:

- HTTP API request-handler exception boundaries;
- worker and scheduler polling-loop resilience to an unhandled exception;
- job-executor error messages reaching a tenant-visible surface;
- persisted job/schedule/identity row deserialization under corruption;
- SQLite operational-error handling in the identity store;
- lease-recovery retry correctness;
- scanner analyzer crash safety against adversarial target content;
- `http.client` wire-level parsing of chunked transfer encoding, declared
  `Content-Length`, and HTTP status codes;
- DNS-pinning and TOCTOU safety across a crawl session and checkpoint resume;
- redirect-following enforcement;
- the multi-address connection-fallback loop's interaction with runtime
  safety-hook accounting (rate limiting, permit-attempt budget, circuit
  breaker);
- per-request wall-clock bounding;
- non-ASCII URL path handling;
- the scanner CLI's `report compare` command.

The audit used direct fault injection against real service handlers, real
raw-socket adversarial HTTP servers (malformed chunked encoding, malformed
`Content-Length`, out-of-range status codes, slow byte-at-a-time drips, and
post-send connection failures), `tracemalloc`-based memory measurement,
real SQLite lock contention (`BEGIN EXCLUSIVE`), `git stash`-based
fix-removal verification for every finding, and authorised OWASP Juice Shop
integration testing.

---

## Phase 6A — Service, Worker and Scheduler Exception Boundaries

### Finding (unlabeled) — HTTP API unexpected-exception disclosure

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** An unexpected service-handler exception returned a raw transport failure and a server-side traceback

#### Initial behaviour

`do_GET` and `do_POST` caught four specific service-exception types. Any
other exception — for example a bug inside `WebGuardJobService.me` or
`.issue_permit` — was left to CPython's default `socketserver` error
handler.

Direct fault injection confirmed the client received
`http.client.RemoteDisconnected: Remote end closed connection without
response` rather than any HTTP response, while the server printed a raw
Python traceback.

#### Security impact

An unexpected bug in any handler produced an unbounded, non-generic failure
mode and no stable error code for the caller to act on, violating this
project's own established "fail closed with a stable, generic error code"
invariant (Phase 3).

#### Remediation

`do_GET` and `do_POST` now each also catch `Exception` and return a fixed
`internal_server_error` / `500` response through the existing generic-error
helper, discarding the original exception's type and message — matching
`worker.py`'s own precedent for an unexpected internal error.

#### Result

**3/3 tests passed.**

---

### Finding C-7

**Severity:** High

**Status:** Confirmed and remediated

**Title:** The worker and scheduler polling loops died permanently on the first uncaught exception

#### Initial behaviour

`ScanJobWorker.run_forever` and `ScanScheduleCoordinator.run_forever` each
looped by calling their own `run_once`, with no exception handling around
the call itself. `run_once` already converts several known failure modes
into blocked/failed outcomes, but any exception it does not already convert
— for example a `JobStoreError` from a store call neither method's
`run_once` wraps — propagated out of `run_forever` and silently ended the
thread.

Both loops run as unsupervised daemon threads in serve mode. `/healthz` does
not check whether either thread is still alive.

Direct fault injection confirmed: with a single injected `RuntimeError` on
one `run_once` call, the loop thread died after exactly one iteration and
never polled again.

#### Security impact

A single transient failure permanently stopped all job execution or all
schedule materialization for the life of the process, with no operator
signal beyond the process silently doing nothing from then on.

#### Remediation

Both `run_forever` methods now wrap the `run_once` call in
`except Exception`, record `last_loop_error_type` / `last_loop_error_at` as
plain instance attributes (this codebase uses no logging framework
anywhere, by design), and continue polling.

#### Result

**3/3 tests passed** (1 worker, 2 scheduler).

---

## Phase 6B — Execution-Path Information Disclosure

### Finding C-2

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** Another tenant's invalid authorization document name and content could leak into an unrelated lookup's error message

#### Initial behaviour

The authorization repository scans a single shared directory to detect
duplicate authorizations. `_entries()` and `get()` interpolated the
directory path and each inspected filename directly into raised error
messages.

A lookup for one tenant's own valid authorization ID, while a second,
differently named, invalid document existed in the same shared directory,
raised an error whose message named and quoted the second tenant's
document.

#### Security impact

One tenant's authorization-document filename and validation-failure detail
could reach a different, unrelated tenant's job error message.

#### Remediation

All path and filename interpolation was removed from these error messages,
replaced with generic text (`"An authorization document is invalid."`, and
similarly for the directory-inspection, symlink, and permission checks).

#### Result

**1/1 test passed.**

---

### Finding C-3

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** A target-validation failure disclosed the resolved private address

#### Initial behaviour

The executor's `validate_target_url` exception handler passed `str(exc)`
directly into the job's error message. `TargetValidationError` messages
from `scope_validator.py` include the resolved address being rejected (for
example, a private-range address).

#### Security impact

A tenant probing addresses through repeated scan submissions could use the
job error message as a DNS/address oracle for internal network topology.

#### Remediation

The handler now raises a fixed, generic message
(`"The target could not be validated for this scan."`), discarding the
original exception text.

#### Result

**1/1 test passed.**

---

### Finding C-4

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** An artifact-directory failure disclosed the operator's server-side filesystem path

#### Initial behaviour

`_prepare_private_directory`, `_write_report`, and
`_write_signed_safety_receipt` each interpolated the operator-configured
artifact path into their error messages on an `OSError`.

#### Security impact

The operator's `--artifacts` path is server-local configuration, not
tenant-scoped data; a job error message that echoes it (including a
possible `~`-expanded path revealing the OS username) is a job-error-message
disclosure the same "fail closed, generic message" invariant already
applies to elsewhere in this module.

#### Remediation

All six interpolations were replaced with plain, generic messages (for
example `"Unable to write the scan report."`).

#### Result

**1/1 test passed.**

---

## Phase 6C — Persisted-State and Identity-Store Exception Safety

### Finding C-5

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** A corrupted persisted job or schedule row raised an uncontrolled contract-validation error

#### Initial behaviour

`_record_from_row` and `_schedule_from_row` already wrapped several
field-level constructions in `try/except (TypeError, ValueError)`, but each
function's *final* `ScanJobRecord(...)` / `ScanScheduleRecord(...)`
construction was left unwrapped.

Direct corruption of a persisted row (a control character written into a
persisted error-message or schedule-name column) reproduced an uncontrolled
`ScanJobValidationError` / `ScanScheduleValidationError` propagating past the
store boundary.

#### Security impact

A corrupted or tampered row could raise an exception type and message the
store's own callers do not expect, rather than the stable
`JobStoreError("job_store_persisted_state_invalid", ...)` this module uses
everywhere else for persisted-state corruption.

#### Remediation

Both final constructions are now wrapped in the same
`except (TypeError, ValueError)` pattern already used elsewhere in each
function.

#### Result

**2/2 tests passed.**

---

### Finding C-6

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** Several identity-store reads were unwrapped against SQLite operational failures

#### Initial behaviour

`_connect`, `get_organization`, `get_principal`, and
`authorization_is_assigned` had no `except sqlite3.Error` boundary — unlike
`authenticate_token`, which already fully wrapped its own reads.

A real SQLite `BEGIN EXCLUSIVE` lock (verified empirically to be the only
mode that blocks concurrent reads in rollback-journal mode — `BEGIN
IMMEDIATE` does not) reproduced a raw
`sqlite3.OperationalError: database is locked` from each of the three read
methods.

#### Security impact

A transient lock or corruption during any of these reads propagated a raw
SQLite exception type and message, rather than a controlled
`IdentityStoreError`, into callers that only expect the latter — this is the
same worker/scheduler-loop-killing risk C-7 addresses, one layer down.

#### Remediation

`_connect` now wraps `sqlite3.connect(...)` and raises
`IdentityStoreError("identity_store_open_failed", ...)`. The three read
methods each now catch `sqlite3.Error` and raise a stable, method-specific
`IdentityStoreError`.

#### Result

**3/3 tests passed.**

---

## Phase 6D — Lease-Recovery Retry Correctness

### Finding C-8

**Severity:** High

**Status:** Confirmed and remediated

**Title:** Lease-recovery retry was completely and reproducibly broken by a job-id-only audit-artifact path

#### Initial behaviour

`execute()` generates a fresh `scan_id` on every call, including a retry
after lease recovery — `record.job_id` is stable for a job's whole
lifetime, but `scan_id` is not. The private artifact `relative_directory`
was keyed only by `job_id`, not `scan_id`. The authorization-audit write
uses `overwrite=False` by deliberate design (a genuine safety property: two
concurrent attempts must never silently overwrite each other's audit file).

The combination meant: the first execution attempt wrote its audit file at
the job-id-keyed path; any subsequent attempt for the *same job* — which is
exactly what a lease-recovery retry is — collided with that now-stale file
and failed 100% of the time, every time, with no way to ever complete that
job.

Direct reproduction confirmed calling `execute()` twice on the same record
(simulating retry after lease loss) failed with `JobExecutionError` on the
second call, unconditionally.

#### Security impact

This broke an operational-safety guarantee Phase 3 explicitly established:
lease recovery after a lost worker must let the job actually complete on
retry. Under this bug it never could, for any job, once retried.

#### Remediation

`relative_directory` is now nested one level deeper, under the already-
fresh-per-attempt `scan_id`, preserving the `overwrite=False` audit-write
safety property exactly while giving each attempt its own artifact
namespace.

The pre-existing test that asserted the *old, broken* behaviour
(`JobExecutionError` raised on a second attempt) was replaced with one
proving two calls on the same record now both succeed, each with a distinct
`scan_id` and `audit_ref`.

#### Result

**1/1 test passed.**

---

## Phase 6E — Scanner-Content Crash Safety

### Finding C-1

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** A target-controlled response-header value could crash the whole scan

#### Initial behaviour

The "X-Content-Type-Options header is invalid" finding's evidence summary
joined the raw, unbounded observed header value(s) directly into
`Evidence(...)`. `Evidence.summary` itself rejects anything over 4096
characters or containing a null byte, but that check runs only after the
value has already been embedded — a target returning an oversized, control-
character-laden, or many-times-duplicated header value raised an
uncontrolled `ContractValidationError`, a type this analyzer's own
`HeaderAnalysisError` pipeline boundary does not cover, aborting the entire
scan over one response header from one page.

#### Security impact

A target under test — or an attacker controlling headers on it — could
abort an entire authorised scan by returning one adversarial header value.

#### Remediation

Added `_bounded_header_values_summary()`: strips non-printable characters,
truncates each value to 128 characters, caps to 10 values with a
`", and N more"` suffix, and caps the total rendered text to 1024
characters — comfortably inside Evidence's own 4096-character limit.

#### Result

**3/3 tests passed.**

---

### Finding P6-003

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** A non-ASCII URL path crashed the scan and permanently poisoned crawl-checkpoint resume

#### Initial behaviour

`_request_path` returns `urlsplit(...).path`/`.query` verbatim.
`urlsplit` performs no percent-encoding of its own, so a discovered link
containing a literal non-ASCII path segment (for example an unescaped
`café` in an `<a href>`) reached `http.client.HTTPConnection.putrequest`
unencoded. `putrequest` encodes the request line as strict ASCII and raised
an uncontrolled `UnicodeEncodeError`.

The severity here is not just the crash: a resumed crawl's checkpoint
already has this exact URL queued. Every resume attempt re-fetches the same
page and crashes identically — the crawl could never complete, permanently,
once it reached that page.

Direct reproduction against a real socket confirmed the exact
`UnicodeEncodeError: 'ascii' codec can't encode character '\xe9'` crash.

#### Security impact

A single adversarial or merely non-ASCII-linking page permanently blocked
completion of an authorised crawl, with no operator recourse other than
abandoning the checkpoint.

#### Remediation

`_request_path` now percent-encodes its final path+query string with
`urllib.parse.quote`, using a safe set covering RFC 3986's path/query
reserved characters plus `%` itself (so an already-percent-encoded sequence
is never double-escaped). This is the single choke point every outbound
request passes through, so the fix also resolves the checkpoint-poisoning
consequence: a resumed crawl now successfully re-fetches the same page
instead of crashing on it again.

Verified against a real socket server: the request line received on the
wire was confirmed to be the correctly percent-encoded
`GET /caf%C3%A9 HTTP/1.1`, and an already-encoded path (`/a%20b?x=1%2B1`) was
confirmed not to be double-encoded.

#### Result

**2/2 tests passed.**

---

## Phase 6F — HTTP Wire-Level Parsing Safety

### Finding P6-001

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** A negative chunked-transfer chunk size bypassed the configured body-size limit

#### Initial behaviour

`http.client`'s chunk-size parser (`_read_next_chunk_size`) accepts a
leading `-` and passes the resulting negative integer to `fp.read(n)`, where
a negative `n` means "read to EOF" — unboundedly, regardless of this
project's own `FetchPolicy.maximum_body_bytes`.

`tracemalloc` measurement against a real malicious response (`-1` chunk size
followed by 8MB of data, against a 1MB policy limit) confirmed 16.26MB peak
Python memory before the fix.

#### Security impact

A malicious or compromised target could exhaust scanner worker memory
regardless of the configured response-size policy.

#### Remediation

Added `_BoundedChunkHTTPResponse`, a subclass overriding
`_read_next_chunk_size` to reject a negative size immediately, wired in via
`http.client.HTTPConnection`'s own documented `response_class` extension
point rather than monkey-patching stdlib internals.

Post-fix measurement: 1.25MB peak against the same attack and policy limit.

#### Result

**2/2 tests passed** (rejection, plus a normal valid chunked response
still reading correctly).

---

### Finding P6-002

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** A non-ASCII or excessively long `Content-Length` raised an uncontrolled `ValueError`

#### Initial behaviour

`_declared_content_length` validated the header token with
`token.isdigit()`, which accepts Unicode decimal-digit characters (for
example the Latin-1 superscript-two byte) that `int()` cannot parse in base
10, and places no bound on token length — beyond Python's own
integer-string-conversion limit (~4300 digits), `int()` also raises
`ValueError`. Both reached `int(token)` directly and raised uncontrolled.

#### Remediation

Replaced the validation with a fixed-width regular expression
(`[0-9]{1,20}`, `fullmatch`), rejecting both cases with the existing
controlled `content_length_invalid` error.

#### Result

**2/2 tests passed.**

---

### Finding P6-004

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** An out-of-range HTTP status code passed the wire layer unchecked

#### Initial behaviour

`http.client` only requires a 3-digit status line; it places no upper bound
on the value. A status in 600–999 passed `fetch_once` unchecked, was
counted by the runtime safety hooks as a completed request, and only failed
later against `RequestAttempt`'s own `100–599` contract range check — after
the request had already run and been accounted for.

#### Remediation

Added an explicit `100 <= response.status <= 599` check in `_perform_request`
immediately after the response headers are read, raising a new controlled
`response_status_invalid` error before the redirect check or body read.

#### Result

**1/1 test passed.**

---

## Phase 6G — Runtime Safety-Accounting Integrity

### Finding P6-005

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** The per-address connection fallback could silently send a second real request under one safety-hook accounting decision

#### Initial behaviour

`fetch_once` tries each of a target's resolved addresses in turn, falling
back to the next on any `OSError` / `ssl.SSLError` /
`http.client.HTTPException`. The caller's `before_request` / `after_request`
safety hooks — which drive rate limiting, the permit request-attempt
budget, and the circuit breaker — are invoked exactly once per `fetch_once`
call, regardless of how many addresses it tries internally.

The fallback logic did not distinguish a connect-phase failure (the server
was never reached; falling back is correct) from a failure occurring after
the full request had already been sent to that address (for example a
malformed response mid-read). In the latter case, falling back silently sent
a second, complete, real HTTP request to a different address — never
counted by the one hook pair the caller already invoked for this attempt.

Reproduced with two real listening servers: the first accepted and fully
received a request, then failed mid-response; the old code fell back and
sent a fresh, complete request to the second server, which the test
confirmed by observing a connection it should never have received.

#### Security impact

Under a target with multiple resolved addresses, the actual number of real
requests sent could silently exceed the permit's rate limit and request-
attempt budget by up to the address count.

#### Remediation

`_perform_request` now tracks whether the request was fully sent
(immediately after `connection.endheaders()` succeeds — this project only
ever sends GET/HEAD, so no request body follows). Any failure after that
point is tagged onto the exception and, in `fetch_once`, raised immediately
as a terminal `SafeRequestError` instead of being treated as an eligible-
for-fallback connection failure.

#### Result

**1/1 test passed.**

---

### Finding P6-006

**Severity:** Medium

**Status:** Confirmed and remediated

**Title:** No overall wall-clock deadline bounded a request

#### Initial behaviour

`FetchPolicy.timeout_seconds` is applied as `http.client`'s socket timeout,
which bounds only each individual blocking socket operation — one `connect`,
one `recv`. A server that drips a response one byte at a time, with every
gap safely under that per-operation timeout, kept the whole call alive far
past the configured limit: every individual read succeeded, so nothing ever
timed out on its own.

Reproduced with a real server dripping 20 bytes at 0.05s intervals (1.0s
total) against a 0.5s configured timeout: the request succeeded in ~1.0s,
double the configured bound, before the fix.

#### Security impact

A slow or malicious target could pin a scanner worker thread for far longer
than any configured timeout, unbounded except by the response-size policy
itself — a denial-of-service vector against the scanner's own capacity.

#### Remediation

`_perform_request` now starts a daemon watchdog thread that waits up to
`timeout_seconds` and, if the request has not completed by then, calls
`socket.shutdown(SHUT_RDWR)` on the connection — not `close()`, since
closing a file descriptor from a different thread while the main thread may
be blocked reading it risks the descriptor number being reused before that
read notices; `shutdown()` safely wakes a blocked read with EOF without
invalidating the descriptor.

A plain Content-Length response does not raise on a short read at EOF the
way a chunked response does — `http.client` just returns what it already
had as if the body were complete. The fix therefore also checks the
watchdog's flag proactively before declaring success, converting a silently
truncated response into the correct `request_deadline_exceeded` error
instead of a falsely "successful" partial read.

Reproduced fixed: the same 1.0s drip against a 0.5s timeout now raises
`request_deadline_exceeded` in ~0.58s.

#### Result

**1/1 test passed.**

---

## Phase 6H — Scanner-Failure Forensic Trail

### Finding P6-007

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** An unexpected scanner exception after real network traffic left no signed safety receipt

#### Initial behaviour

`execute()`'s scanner-call `try` block caught only
`TrustScanRuntimeSafetyError`, writing a signed safety receipt before
converting it to a `JobExecutionError`. Any other exception — a genuine bug
in the scanner or crawler — propagated with no receipt written at all, even
though `before_request` may have already permitted, and the scanner may
have already sent, real network traffic against the authorised target.

Reproduced: a scanner raising `RuntimeError` after one permitted and
completed request propagated raw past this boundary, with no receipt
produced.

#### Security impact

The signed safety receipt is this project's forensic record of what was
actually done to an authorised target. Losing it on exactly the class of
failure most likely to leave real traffic unaccounted for defeats its
purpose.

#### Remediation

Added a second `except Exception` clause alongside the existing
`TrustScanRuntimeSafetyError` handler: writes a safety receipt
(`termination_reason="scanner_error"`) and raises a stable, generic
`JobExecutionError("scan_execution_failed", ...)` with the receipt attached
— discarding the original exception's type and message, matching every
other controlled boundary in this module.

#### Result

**1/1 test passed.**

---

### Finding P6-009

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** A runtime permit-binding lookup failure during active scanning was unwrapped against store errors

#### Initial behaviour

`revalidate_runtime_permission`'s own call to `get_job_permit_binding` —
made on every `before_request`, throughout the scan, unlike the one-time
call made before the scan starts — was not wrapped for `JobStoreError`, unlike
the sibling `get_scan_permit_scoped` call immediately below it in the same
function. `TrustScanRuntimeSafetyEngine._revalidate` only catches
`TrustScanPermitError`, so a `JobStoreError` here propagated raw past it.

Reproduced: after one permitted and completed request, a `JobStoreError`
injected on the second `before_request`'s binding lookup propagated raw.

#### Remediation

No separate source change was required: this call site sits inside the same
scanner-call `try` block P6-007 hardened. Confirmed by reproduction that the
P6-007 fix's broad `except Exception` clause now correctly converts this
failure into a `JobExecutionError("scan_execution_failed", ...)` with a
signed receipt attached, after a real permitted request.

#### Result

**1/1 test passed.**

---

## Phase 6I — CLI Report-Comparison Safety

### Finding C-9

**Severity:** Low

**Status:** Confirmed and remediated

**Title:** The CLI `report compare` command raised a raw, uncaught exception when comparing a report against itself

#### Initial behaviour

`build_report_comparison` (in `professional_report.py`) validates several
cross-field invariants — matching target, non-regressing completion order,
`generated_at` not preceding completion — each raising `ProfessionalReportError`,
before constructing a `ReportComparison` (a `webguard_contracts.reporting`
dataclass). That dataclass's own `__post_init__` separately rejects equal
baseline/current scan IDs by raising `ReportComparisonError` — a different
exception type, from a different module, that the CLI's
`_report_compare_command` does not catch (it catches only
`ProfessionalReportError`).

A crawl resumed from a checkpoint reuses its original `scan_id`, making a
report compared against itself a real, reachable case rather than a
theoretical one.

#### Remediation

Added the same scan-ID-equality check directly inside
`build_report_comparison`, before the `ReportComparison` construction,
raising `ProfessionalReportError("comparison_scan_ids_equal", ...)` —
consistent with every other cross-field check the function already makes,
so every caller of this function gets one uniform exception type rather
than one case leaking through as a different type from a different module.

#### Result

**1/1 test passed.**

---

## Reviewed, Not Fixed

### P6-008 — Scanner CLI `main()` has no catch-all

**Severity:** Low/Info

**Status:** Dismissed as accepted, symmetric with an existing decision

`workers/scanner/src/webguard_scanner/cli.py`'s `main()` catches only
`CliControlledError`; an unexpected handler bug produces a raw traceback on
stderr and Python's default exit code 1, which collides with this CLI's own
`EXIT_SCAN_FAILED = 1`. `apps/api/src/webguard_api/cli.py`'s `main()` has
the identical structure and the identical gap, and was reviewed and left
unfixed earlier in this same audit on the grounds that both CLIs are
operator-only surfaces (the operator already has shell access to the same
machine) with no cross-tenant blast radius. Fixing one and not the other
would be an inconsistent standard; both are dismissed together with that
reasoning documented here.

### T-a, T-b, T-c — Reviewed theoretical concerns

- **T-a:** `identity.py`'s `_connect` executes `PRAGMA` statements outside
  its own try/except. The connection open immediately before it already
  fails closed on `sqlite3.Error`; a `PRAGMA` failing independently of a
  successful open was not demonstrated to be reachable.
- **T-b:** the worker's per-job lease-monitor thread's `except JobStoreError`
  around `is_cancellation_requested` / `renew_lease` is narrower than
  `run_forever`'s own C-7 fix. Verified directly: both underlying store
  methods (`get`, and `renew_lease`'s own transaction) wrap every
  `sqlite3.Error` into `JobStoreError` already, including through this
  phase's own C-5 fix to the final record construction — no other exception
  type can reach this catch under the current implementation.
- **T-c:** `TrustScanRuntimeSafetyEngine.after_request` is not invoked when
  a non-`SafeRequestError` exception aborts a request mid-flight. The scan
  itself terminates at the same point either way (via P6-007's fix), so no
  additional, unaccounted request activity follows.

---

## Final Verification

### Dedicated Phase 6 test coverage

The final Phase 6 suite included the following files touched by this
phase's fixes:

- HTTP API transport-error handling: 32 tests;
- safe HTTP wire-level parsing and network safety: 24 tests;
- header analyzer crash safety: 12 tests;
- job executor: 14 tests;
- job worker: 6 tests;
- scheduler: 14 tests;
- authorization repository: 10 tests;
- SQLite lock and crash recovery: 16 tests;
- persisted scalar validation: 6 tests;
- professional report comparison: 23 tests.

All passed.

Every fix in this phase was verified individually with a `git stash`-based
removal: each new regression test was confirmed to fail, with the expected
uncontrolled exception or observable defect, against the pre-fix source
before the fix was restored.

### Full repository unit verification

**1103/1103 tests passed.**

### Integration behaviour

Integration tests remained opt-in during the standard verification gate
(14 tests skipped without `WEBGUARD_RUN_INTEGRATION=1`).

Authorized Juice Shop integration was then executed explicitly against the
supply-chain-pinned lab image
(`bkimminich/juice-shop@sha256:cd58d79c5cb4d82f22fbaf616f9ff43bbd04ba630cd6b448a9ed99cf652fcebf`)
at `http://127.0.0.1:3000/`, with the lab container torn down immediately
afterward.

Result:

**14/14 integration tests passed.**

### Security gates

- repository/generated-artifact/reachable-Git-history secret scan: passed (226 repository files, 27 generated artifact files, 1548 reachable Git blobs);
- Ruff static Python security analysis (`--select S`): passed;
- locked dependency advisory audit: passed (6 exact locked packages).

Final result:

**WebGuard security gates passed.**

### Supply-chain and governance verification

- supply-chain pin verification: passed;
- security-governance document verification: passed;
- `python -m compileall` across all source trees: passed.

### Repository hygiene

`git diff --check` completed without errors.

---

## Phase 6 Closure

Phase 6 identified and remediated weaknesses across:

- service, worker, and scheduler exception boundaries;
- execution-path information disclosure;
- persisted-state and identity-store exception safety;
- lease-recovery retry correctness;
- scanner-content crash safety;
- HTTP wire-level parsing safety;
- runtime safety-accounting integrity under connection fallback and
  request timing;
- the scanner's forensic safety-receipt trail;
- CLI report-comparison safety.

The highest-severity issues were C-7 and C-8: the worker/scheduler polling
loops could die permanently on a single unhandled exception, and lease-
recovery retry — a guarantee this same audit established in Phase 3 — was
100% broken for any job that was ever actually retried. Both are now fixed
and regression-tested.

All confirmed findings are remediated and covered by regression tests. One
low/info finding (P6-008) and three theoretical concerns (T-a, T-b, T-c)
were reviewed and dismissed with documented reasoning rather than fixed.

Phase 6 is therefore:

**COMPLETE**

This closes Checkpoint 1. Phases 2 through 6 — authentication and tenant
isolation, execution safety, persistence and recovery, secrets/keys/
artifacts, and exception/network safety — are all complete, remediated, and
regression-tested against the Checkpoint 1 snapshot (`5f9cb80`).

**Checkpoint 1 is COMPLETE.**
