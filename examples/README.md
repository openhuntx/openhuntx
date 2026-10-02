# Example: scan, report, reproduce

This directory contains real output from a real `webguard` scan, not hand-written sample JSON. The target is a tiny synthetic local HTTP server committed in this directory ([`synthetic_target/server.py`](synthetic_target/server.py)), not an external site, so the whole thing reproduces offline with no paid infrastructure, no account, and no authorization document (lab-mode local targets don't need one).

## What's here

- [`synthetic_target/server.py`](synthetic_target/server.py): a ~30-line `http.server` handler that deliberately sets a disclosing `Server` header and deliberately omits CSP, frame protection, `X-Content-Type-Options`, and `Referrer-Policy`, so the scan below reproduces a realistic, representative mix of findings.
- [`scan-results/sample-scan.json`](scan-results/sample-scan.json): the exact, unedited report `webguard scan` wrote.
- [`reports/sample-report.html`](reports/sample-report.html): the professional HTML report rendered from it. Open it directly in a browser.

## Reproduce it yourself

From a checkout with `webguard` installed (see the repository root [README](../README.md#install)):

```bash
python3 examples/synthetic_target/server.py 8931 &
SERVER_PID=$!

webguard scan http://127.0.0.1:8931/ --lab --allow-host 127.0.0.1 \
  --output /tmp/sample-scan.json

webguard report render /tmp/sample-scan.json \
  --output /tmp/sample-report.html \
  --organization "Example, Inc." \
  --title "WebGuard Demo Assessment"

kill $SERVER_PID
```

Findings will match in substance (missing CSP, missing clickjacking protection, missing `X-Content-Type-Options`, missing `Referrer-Policy`, a disclosing `Server` header) but `scan_id`, timestamps, and response timings will differ run to run. That's expected and is exactly what `report compare` is for when you re-scan the same target later to prove remediation.
