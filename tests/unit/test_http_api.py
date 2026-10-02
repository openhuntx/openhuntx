from __future__ import annotations

import http.client
import json
import tempfile
from datetime import timedelta
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from webguard_api import (
    ApiTokenAuthenticator,
    ApiTransportError,
    AuthorizationRepository,
    FixedWindowRateLimiter,
    ScanJobStore,
    WebGuardJobService,
    create_server,
)
from webguard_api.artifact_store import LocalArtifactStore
from webguard_contracts import OrganizationRole

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    TARGET,
    VIEWER_ID,
    VIEWER_TOKEN_ID,
    create_identity_fixture,
    create_trustscan_permit,
    write_authorization,
)


def submission() -> bytes:
    return json.dumps(
        {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
        }
    ).encode("utf-8")


def permit_submission() -> bytes:
    return json.dumps(
        {
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "permitted_modes": ["crawl", "single_page"],
            "allowed_http_methods": ["GET", "HEAD"],
            "not_before": NOW.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "expires_at": (NOW + timedelta(days=7)).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "maximum_request_attempts": 15,
            "maximum_requests_per_second": 1.0,
            "maximum_concurrency": 1,
            "active_checks": [],
            "authentication_context_id": None,
            "authorization_comparison_plan_id": None,
        }
    ).encode("utf-8")


def schedule_submission() -> bytes:
    starts_at = (NOW + timedelta(hours=1)).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    return json.dumps(
        {
            "name": "Daily passive crawl",
            "target": TARGET,
            "authorization_id": AUTH_ID,
            "confirm_authorization": AUTH_ID,
            "mode": "crawl",
            "interval_seconds": 86400,
            "starts_at": starts_at,
        }
    ).encode("utf-8")


class HttpApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        auth_dir = root / "authorizations"
        write_authorization(auth_dir)
        store = ScanJobStore(root / "jobs.sqlite3")
        identity, self.context, self.token = create_identity_fixture(store.path)
        self.permit = create_trustscan_permit(store)
        self.permit_id = self.permit.permit.claims.permit_id
        _, self.viewer_context, self.viewer_token = create_identity_fixture(
            store.path,
            role=OrganizationRole.VIEWER,
            principal_id=VIEWER_ID,
            token_id=VIEWER_TOKEN_ID,
        )
        self.service = WebGuardJobService(
            store=store,
            authorizations=AuthorizationRepository(auth_dir),
            identity=identity,
            clock=lambda: NOW,
        )
        self.server = create_server(
            "127.0.0.1",
            0,
            self.service,
            authenticator=ApiTokenAuthenticator(identity),
            rate_limiter=FixedWindowRateLimiter(requests=100, window_seconds=60),
            maximum_request_bytes=1024,
            clock=lambda: NOW,
            epoch_clock=lambda: 1000.0,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temporary.cleanup()

    def request(self, method, path, body=None, headers=None, *, token="owner", permit="default"):
        effective = dict(headers or {})
        if permit == "default" and method == "POST" and path in {"/v1/jobs", "/v1/schedules"}:
            effective.setdefault("TrustScan-Permit", self.permit_id)
        if token == "owner":
            effective.setdefault("Authorization", f"Bearer {self.token}")
        elif token == "viewer":
            effective.setdefault("Authorization", f"Bearer {self.viewer_token}")
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        connection.request(method, path, body=body, headers=effective)
        response = connection.getresponse()
        payload = response.read()
        response_headers = dict(response.getheaders())
        status = response.status
        connection.close()
        return status, response_headers, json.loads(payload)

    def test_create_server_rejects_public_binding(self) -> None:
        with self.assertRaisesRegex(ApiTransportError, "loopback"):
            create_server(
                "0.0.0.0",
                0,
                None,
                authenticator=None,
                rate_limiter=None,
                maximum_request_bytes=1024,
            )

    def test_health_endpoint_is_public(self) -> None:
        status, headers, payload = self.request("GET", "/healthz", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("X-Request-ID", headers)

    def test_health_alias_endpoint_is_public(self) -> None:
        status, _, payload = self.request("GET", "/health", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok"})

    def test_ready_endpoint_is_public_and_ready_by_default(self) -> None:
        status, _, payload = self.request("GET", "/ready", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ready", "reason": "ready"})

    def test_ready_endpoint_reflects_a_failing_dependency_check(self) -> None:
        original = self.service.readiness_check
        self.service.readiness_check = lambda: (_ for _ in ()).throw(
            RuntimeError("simulated dependency outage")
        )
        try:
            status, _, payload = self.request("GET", "/ready", token=None)
        finally:
            self.service.readiness_check = original
        self.assertEqual(status, 503)
        self.assertEqual(payload["status"], "not_ready")
        self.assertEqual(payload["reason"], "dependency_unavailable")
        self.assertNotIn("simulated dependency outage", json.dumps(payload))

    def test_trustscan_verification_key_is_public(self) -> None:
        status, _, payload = self.request(
            "GET", "/v1/trustscan/verification-key", token=None
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["algorithm"], "Ed25519")
        self.assertTrue(payload["key_id"].startswith("sha256:"))
        self.assertNotIn("private", json.dumps(payload).lower())

    def test_owner_can_issue_read_and_revoke_trustscan_permit(self) -> None:
        body = permit_submission()
        status, _, issued = self.request(
            "POST",
            "/v1/permits",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        self.assertEqual(status, 201)
        permit_id = issued["permit"]["claims"]["permit_id"]
        status, _, fetched = self.request("GET", f"/v1/permits/{permit_id}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["permit"]["claims"]["permit_id"], permit_id)
        status, _, revoked = self.request(
            "POST",
            f"/v1/permits/{permit_id}/revoke",
            body=b"",
            headers={"Content-Length": "0"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(revoked["state"], "revoked")

    def test_invalid_trustscan_permit_header_is_400(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "invalid-permit-http-1",
                "TrustScan-Permit": "NOT-A-PERMIT",
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "trustscan_permit_invalid")

    def test_missing_trustscan_permit_header_is_400(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "missing-permit-http-1",
            },
            permit=None,
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "trustscan_permit_required")

    def test_invalid_bearer_token_does_not_echo_secret(
        self,
    ) -> None:
        secret = "Phase5HttpSecret0123456789"

        invalid_token = (
            "wgt_"
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa_"
            f"{secret}"
        )

        status, headers, payload = self.request(
            "GET",
            "/v1/me",
            headers={
                "Authorization": (
                    f"Bearer {invalid_token}"
                )
            },
            token=None,
        )

        self.assertEqual(status, 401)

        serialized = json.dumps(
            {
                "headers": headers,
                "payload": payload,
            },
            sort_keys=True,
        )

        self.assertNotIn(
            invalid_token,
            serialized,
        )
        self.assertNotIn(
            secret,
            serialized,
        )

    def test_missing_bearer_token_is_401(self) -> None:
        status, headers, payload = self.request("GET", "/v1/me", token=None)
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "authorization_header_required")
        self.assertIn("Bearer", headers["WWW-Authenticate"])

    def test_me_returns_scoped_identity(self) -> None:
        status, _, payload = self.request("GET", "/v1/me")
        self.assertEqual(status, 200)
        self.assertEqual(payload["organization_id"], self.context.organization_id)
        self.assertEqual(payload["role"], "owner")

    def test_submit_get_and_cancel_job(self) -> None:
        body = submission()
        status, headers, created = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "internstack-http-1",
            },
        )
        self.assertEqual(status, 201)
        self.assertIn("RateLimit-Remaining", headers)
        job_id = created["job_id"]
        status, _, fetched = self.request("GET", f"/v1/jobs/{job_id}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["job_id"], job_id)
        status, _, cancelled = self.request(
            "POST",
            f"/v1/jobs/{job_id}/cancel",
            body=b"",
            headers={"Content-Length": "0"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(cancelled["state"], "cancelled")

    def test_viewer_cannot_submit(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "viewer-http-1",
            },
            token="viewer",
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "permission_denied")

    def test_idempotent_replay_returns_200(self) -> None:
        body = submission()
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Idempotency-Key": "internstack-http-2",
        }
        first = self.request("POST", "/v1/jobs", body=body, headers=headers)
        second = self.request("POST", "/v1/jobs", body=body, headers=headers)
        self.assertEqual(first[0], 201)
        self.assertEqual(second[0], 200)
        self.assertEqual(first[2]["job_id"], second[2]["job_id"])

    def test_result_not_ready_is_409(self) -> None:
        body = submission()
        status, _, created = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "internstack-http-3",
            },
        )
        self.assertEqual(status, 201)
        status, _, payload = self.request("GET", f"/v1/jobs/{created['job_id']}/result")
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"]["code"], "job_result_not_ready")

    def test_missing_idempotency_key_is_400(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "idempotency_key_required")

    def test_invalid_content_type_is_415(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "text/plain",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "internstack-http-4",
            },
        )
        self.assertEqual(status, 415)
        self.assertEqual(payload["error"]["code"], "content_type_invalid")

    def test_oversized_body_is_413(self) -> None:
        body = b"x" * 1025
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "internstack-http-5",
            },
        )
        self.assertEqual(status, 413)
        self.assertEqual(payload["error"]["code"], "request_body_too_large")

    def test_query_string_is_rejected(self) -> None:
        status, _, payload = self.request("GET", "/healthz?verbose=1", token=None)
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "request_query_not_allowed")

    def test_job_list_is_paginated_with_opaque_cursor(self) -> None:
        created_ids = []
        for index in range(3):
            body = submission()
            status, _, created = self.request(
                "POST",
                "/v1/jobs",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Idempotency-Key": f"pagination-http-{index}",
                },
            )
            self.assertEqual(status, 201)
            created_ids.append(created["job_id"])
        status, _, first = self.request("GET", "/v1/jobs?limit=2")
        self.assertEqual(status, 200)
        self.assertEqual(len(first["jobs"]), 2)
        cursor = first["page"]["next_cursor"]
        self.assertIsInstance(cursor, str)
        self.assertNotIn(self.context.organization_id, cursor)
        status, _, second = self.request(
            "GET", f"/v1/jobs?limit=2&cursor={cursor}"
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(second["jobs"]), 1)
        self.assertIsNone(second["page"]["next_cursor"])
        returned = [item["job_id"] for item in first["jobs"] + second["jobs"]]
        self.assertEqual(set(returned), set(created_ids))
        self.assertEqual(len(returned), len(set(returned)))

    def test_job_list_filters_are_bound_to_cursor(self) -> None:
        body = submission()
        for index in range(2):
            self.request(
                "POST",
                "/v1/jobs",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Idempotency-Key": f"filter-http-{index}",
                },
            )
        status, _, first = self.request(
            "GET", "/v1/jobs?limit=1&state=queued&mode=crawl"
        )
        self.assertEqual(status, 200)
        cursor = first["page"]["next_cursor"]
        status, _, payload = self.request(
            "GET", f"/v1/jobs?limit=1&state=running&mode=crawl&cursor={cursor}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "page_cursor_filter_mismatch")

    def test_tampered_cursor_is_rejected(self) -> None:
        body = submission()
        for index in range(2):
            self.request(
                "POST",
                "/v1/jobs",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Idempotency-Key": f"tamper-http-{index}",
                },
            )
        _, _, first = self.request("GET", "/v1/jobs?limit=1")
        cursor = first["page"]["next_cursor"]
        payload_segment, signature_segment = cursor.split(".", 1)
        replacement = "A" if signature_segment[0] != "A" else "B"
        tampered = (
            f"{payload_segment}.{replacement}{signature_segment[1:]}"
        )
        status, _, payload = self.request(
            "GET", f"/v1/jobs?limit=1&cursor={tampered}"
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "page_cursor_signature_invalid")

    def test_list_query_validation_rejects_duplicate_unknown_and_invalid_values(self) -> None:
        cases = (
            ("/v1/jobs?limit=1&limit=2", "page_query_parameter_duplicate"),
            ("/v1/jobs?unknown=1", "page_query_parameter_unknown"),
            ("/v1/jobs?limit=101", "page_limit_invalid"),
            ("/v1/jobs?state=other", "page_filter_invalid"),
        )
        for path, code in cases:
            with self.subTest(path=path):
                status, _, payload = self.request("GET", path)
                self.assertEqual(status, 400)
                self.assertEqual(payload["error"]["code"], code)

    def test_unknown_route_is_404(self) -> None:
        status, _, payload = self.request("GET", "/v1/unknown")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "route_not_found")

    def test_unsupported_method_is_405(self) -> None:
        status, _, payload = self.request("PUT", "/v1/jobs")
        self.assertEqual(status, 405)
        self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_submission_response_does_not_echo_secrets(self) -> None:
        body = submission()
        status, _, payload = self.request(
            "POST",
            "/v1/jobs",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Idempotency-Key": "internstack-http-6",
            },
        )
        self.assertEqual(status, 201)
        serialized = json.dumps(payload)
        self.assertNotIn("confirm_authorization", serialized)
        self.assertNotIn(self.token, serialized)

    def test_owner_can_read_audit_events(self) -> None:
        self.request("GET", "/v1/me")
        status, _, payload = self.request("GET", "/v1/audit-events")
        self.assertEqual(status, 200)
        self.assertTrue(payload["events"])

    def test_owner_can_list_and_get_findings(self) -> None:
        finding = self.service.finding_repository.record_finding(
            organization_id=self.context.organization_id,
            scan_id="11111111-1111-4111-8111-111111111111",
            fingerprint="fp-http-test-1",
            check_id="active.xss.reflected",
            scanner_version="1.0",
            title="Reflected XSS",
            severity="high",
            confidence="confirmed",
            asset="https://example.com",
            endpoint="/search",
            http_method="GET",
            now=NOW,
        )
        status, _, listing = self.request("GET", "/v1/findings")
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["findings"]), 1)
        self.assertEqual(listing["findings"][0]["finding_id"], finding.finding_id)
        self.assertEqual(listing["findings"][0]["status"], "open")

        status, _, fetched = self.request("GET", f"/v1/findings/{finding.finding_id}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["check_id"], "active.xss.reflected")

    def test_viewer_can_read_findings(self) -> None:
        self.service.finding_repository.record_finding(
            organization_id=self.context.organization_id,
            scan_id="11111111-1111-4111-8111-111111111111",
            fingerprint="fp-http-test-viewer",
            check_id="active.sqli.error",
            scanner_version="1.0",
            title="SQLi",
            severity="high",
            confidence="confirmed",
            asset="https://example.com",
            endpoint="/login",
            http_method="POST",
            now=NOW,
        )
        status, _, listing = self.request("GET", "/v1/findings", token="viewer")
        self.assertEqual(status, 200)
        self.assertTrue(listing["findings"])

    def test_findings_are_tenant_scoped(self) -> None:
        self.service.finding_repository.record_finding(
            organization_id="99999999-9999-4999-8999-999999999999",
            scan_id="11111111-1111-4111-8111-111111111111",
            fingerprint="fp-http-test-other-org",
            check_id="active.sqli.error",
            scanner_version="1.0",
            title="SQLi",
            severity="high",
            confidence="confirmed",
            asset="https://other.example",
            endpoint="/x",
            http_method="GET",
            now=NOW,
        )
        status, _, listing = self.request("GET", "/v1/findings")
        self.assertEqual(status, 200)
        self.assertEqual(listing["findings"], [])

    def test_owner_can_confirm_a_finding_with_a_reason_and_it_is_audited(self) -> None:
        finding = self.service.finding_repository.record_finding(
            organization_id=self.context.organization_id,
            scan_id="11111111-1111-4111-8111-111111111111",
            fingerprint="fp-http-lifecycle-1",
            check_id="active.xss.reflected",
            scanner_version="1.0",
            title="Reflected XSS",
            severity="high",
            confidence="confirmed",
            asset="https://example.com",
            endpoint="/search",
            http_method="GET",
            now=NOW,
        )
        status, _, updated = self.request(
            "POST",
            f"/v1/findings/{finding.finding_id}/status",
            body=json.dumps({"status": "confirmed", "reason": "Verified manually."}).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200, updated)
        self.assertEqual(updated["status"], "confirmed")

        status, _, events = self.request("GET", f"/v1/findings/{finding.finding_id}/events")
        self.assertEqual(status, 200, events)
        self.assertEqual(len(events["events"]), 1)
        self.assertEqual(events["events"][0]["previous_status"], "open")
        self.assertEqual(events["events"][0]["new_status"], "confirmed")
        self.assertEqual(events["events"][0]["reason"], "Verified manually.")
        self.assertEqual(events["events"][0]["changed_by"], self.context.principal_id)

    def test_repeating_the_identical_status_change_is_idempotent(self) -> None:
        finding = self.service.finding_repository.record_finding(
            organization_id=self.context.organization_id,
            scan_id="11111111-1111-4111-8111-111111111111",
            fingerprint="fp-http-lifecycle-idempotent",
            check_id="active.xss.reflected",
            scanner_version="1.0",
            title="Reflected XSS",
            severity="high",
            confidence="confirmed",
            asset="https://example.com",
            endpoint="/search",
            http_method="GET",
            now=NOW,
        )
        for _ in range(2):
            status, _, updated = self.request(
                "POST",
                f"/v1/findings/{finding.finding_id}/status",
                body=json.dumps({"status": "confirmed"}).encode(),
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(status, 200, updated)
        status, _, events = self.request("GET", f"/v1/findings/{finding.finding_id}/events")
        self.assertEqual(len(events["events"]), 1, "a repeated identical transition must not duplicate history")

    def test_client_cannot_set_reopened_directly(self) -> None:
        finding = self.service.finding_repository.record_finding(
            organization_id=self.context.organization_id,
            scan_id="11111111-1111-4111-8111-111111111111",
            fingerprint="fp-http-lifecycle-reopen",
            check_id="active.xss.reflected",
            scanner_version="1.0",
            title="Reflected XSS",
            severity="high",
            confidence="confirmed",
            asset="https://example.com",
            endpoint="/search",
            http_method="GET",
            now=NOW,
        )
        status, _, payload = self.request(
            "POST",
            f"/v1/findings/{finding.finding_id}/status",
            body=json.dumps({"status": "reopened"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400, payload)
        self.assertEqual(payload["error"]["code"], "finding_status_not_client_settable")

    def test_viewer_cannot_update_finding_status(self) -> None:
        finding = self.service.finding_repository.record_finding(
            organization_id=self.context.organization_id,
            scan_id="11111111-1111-4111-8111-111111111111",
            fingerprint="fp-http-lifecycle-viewer",
            check_id="active.xss.reflected",
            scanner_version="1.0",
            title="Reflected XSS",
            severity="high",
            confidence="confirmed",
            asset="https://example.com",
            endpoint="/search",
            http_method="GET",
            now=NOW,
        )
        status, _, payload = self.request(
            "POST",
            f"/v1/findings/{finding.finding_id}/status",
            body=json.dumps({"status": "confirmed"}).encode(),
            headers={"Content-Type": "application/json"},
            token="viewer",
        )
        self.assertEqual(status, 403, payload)

    def test_scans_list_and_get_are_tenant_scoped(self) -> None:
        scan = self.service.scan_repository.create_scan(
            organization_id=self.context.organization_id,
            job_id="22222222-2222-4222-8222-222222222222",
            target=TARGET,
            authorization_id=AUTH_ID,
            mode="single_page",
            scanner_version="1.0",
            now=NOW,
        )
        self.service.scan_repository.create_scan(
            organization_id="99999999-9999-4999-8999-999999999999",
            job_id="33333333-3333-4333-8333-333333333333",
            target="https://other.example/",
            authorization_id=AUTH_ID,
            mode="single_page",
            scanner_version="1.0",
            now=NOW,
        )
        status, _, listing = self.request("GET", "/v1/scans")
        self.assertEqual(status, 200, listing)
        self.assertEqual(len(listing["scans"]), 1)
        self.assertEqual(listing["scans"][0]["scan_id"], scan.scan_id)

        status, _, fetched = self.request("GET", f"/v1/scans/{scan.scan_id}")
        self.assertEqual(status, 200, fetched)
        self.assertEqual(fetched["target"], TARGET)

    def test_report_create_list_and_get(self) -> None:
        scan = self.service.scan_repository.create_scan(
            organization_id=self.context.organization_id,
            job_id="44444444-4444-4444-8444-444444444444",
            target=TARGET,
            authorization_id=AUTH_ID,
            mode="single_page",
            scanner_version="1.0",
            now=NOW,
        )
        report_path = Path(self.temporary.name) / "report.json"
        report_path.write_text('{"status": "completed"}', encoding="utf-8")
        self.service.scan_repository.complete_scan(
            scan.scan_id,
            organization_id=self.context.organization_id,
            status="completed",
            report_ref="report.json",
            finding_count=0,
            now=NOW,
        )
        self.service.artifact_store = LocalArtifactStore(Path(self.temporary.name))

        status, _, created = self.request(
            "POST", "/v1/reports", body=json.dumps({"scan_id": scan.scan_id}).encode(),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 201, created)
        self.assertEqual(len(created["checksum"]), 64)

        status, _, listing = self.request("GET", "/v1/reports")
        self.assertEqual(status, 200, listing)
        self.assertEqual(len(listing["reports"]), 1)

        status, _, fetched = self.request("GET", f"/v1/reports/{created['report_id']}")
        self.assertEqual(status, 200, fetched)
        self.assertEqual(fetched["checksum"], created["checksum"])

    def test_schedule_create_list_pause_and_resume(self) -> None:
        body = schedule_submission()
        status, _, created = self.request(
            "POST",
            "/v1/schedules",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        self.assertEqual(status, 201)
        schedule_id = created["schedule_id"]
        status, _, listing = self.request("GET", "/v1/schedules")
        self.assertEqual(status, 200)
        self.assertEqual(listing["schedules"][0]["schedule_id"], schedule_id)
        status, _, fetched = self.request("GET", f"/v1/schedules/{schedule_id}")
        self.assertEqual(status, 200)
        self.assertEqual(fetched["schedule_id"], schedule_id)
        status, _, paused = self.request(
            "POST",
            f"/v1/schedules/{schedule_id}/pause",
            body=b"",
            headers={"Content-Length": "0"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(paused["state"], "paused")
        status, _, resumed = self.request(
            "POST",
            f"/v1/schedules/{schedule_id}/resume",
            body=b"",
            headers={"Content-Length": "0"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(resumed["state"], "active")

    def test_viewer_can_list_schedules_but_cannot_create(self) -> None:
        body = schedule_submission()
        status, _, payload = self.request(
            "POST",
            "/v1/schedules",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            token="viewer",
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "permission_denied")
        status, _, listing = self.request("GET", "/v1/schedules", token="viewer")
        self.assertEqual(status, 200)
        self.assertEqual(listing["schedules"], [])
        self.assertEqual(listing["page"]["limit"], 50)
        self.assertIsNone(listing["page"]["next_cursor"])

    def test_schedule_state_body_is_rejected(self) -> None:
        body = schedule_submission()
        status, _, created = self.request(
            "POST",
            "/v1/schedules",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        self.assertEqual(status, 201)
        status, _, payload = self.request(
            "POST",
            f"/v1/schedules/{created['schedule_id']}/pause",
            body=b"x",
            headers={"Content-Length": "1"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "schedule_body_not_allowed")

    def test_viewer_cannot_read_audit_events(self) -> None:
        status, _, payload = self.request("GET", "/v1/audit-events", token="viewer")
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "permission_denied")

    def test_unexpected_exception_in_get_handler_returns_controlled_500(self) -> None:
        """An exception type the handler never anticipated (not one of
        ApiTransportError/ApiServiceError/AuthenticationError/RateLimitError)
        must still resolve to a stable, non-leaking error response rather
        than an unhandled exception that resets the client connection."""

        with patch.object(
            WebGuardJobService,
            "me",
            side_effect=RuntimeError("contains-canary-detail-should-not-leak"),
        ):
            status, _, payload = self.request("GET", "/v1/me")
        self.assertEqual(status, 500)
        self.assertEqual(payload["error"]["code"], "internal_server_error")
        self.assertNotIn("canary-detail", json.dumps(payload))
        self.assertNotIn("RuntimeError", json.dumps(payload))
        self.assertIn("request_id", payload["error"])

    def test_unexpected_exception_in_post_handler_returns_controlled_500(self) -> None:
        body = permit_submission()
        with patch.object(
            WebGuardJobService,
            "issue_permit",
            side_effect=KeyError("contains-canary-detail-should-not-leak"),
        ):
            status, _, payload = self.request(
                "POST",
                "/v1/permits",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
        self.assertEqual(status, 500)
        self.assertEqual(payload["error"]["code"], "internal_server_error")
        self.assertNotIn("canary-detail", json.dumps(payload))

    def test_server_remains_available_after_an_unexpected_exception(self) -> None:
        """One handler crashing must not take down the shared server: a
        normal request immediately afterward must still succeed."""

        with patch.object(
            WebGuardJobService, "me", side_effect=RuntimeError("boom")
        ):
            status, _, _ = self.request("GET", "/v1/me")
        self.assertEqual(status, 500)

        status, _, payload = self.request("GET", "/v1/me")
        self.assertEqual(status, 200)
        self.assertIn("principal_id", payload)


if __name__ == "__main__":
    unittest.main()
