from __future__ import annotations

import os
import stat
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from webguard_api import (
    AuthorizationRepository,
    JobExecutionError,
    JobStoreError,
    ScanJobExecutor,
    ScanJobStore,
)
from webguard_contracts import (
    ScanJobMode,
    ScanJobRequest,
    ScanJobState,
    load_signed_trustscan_safety_receipt_json,
)
from webguard_scanner import (
    CrawlCancellationToken,
    SafeHttpResponse,
    ValidatedTarget,
)

from tests.unit.service_test_support import (
    AUTH_ID,
    NOW,
    TARGET,
    authorization,
    completed_report,
    create_trustscan_permit,
    ORG_ID,
    OWNER_ID,
    trustscan_signer,
    write_authorization,
)


class ScanJobExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.auth_dir = self.root / "authorizations"
        self.auth_path = write_authorization(self.auth_dir)
        self.artifacts = self.root / "artifacts"
        self.store = ScanJobStore(self.root / "jobs.sqlite3")
        self.signer = trustscan_signer(self.store)
        self.permit = create_trustscan_permit(self.store)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def running_record(self, *, mode: ScanJobMode = ScanJobMode.CRAWL):
        auth = authorization()
        request = ScanJobRequest(
            idempotency_key=f"internstack-{mode.value}",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=mode,
            submitted_at=NOW,
        )
        queued, _ = self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=self.permit.permit.claims.permit_id,
            permit_sha256=self.permit.permit.fingerprint,
        )
        claimed = self.store.claim_next(now=NOW)
        assert claimed is not None
        return claimed

    @staticmethod
    def validated_target() -> ValidatedTarget:
        return ValidatedTarget(
            original_url=TARGET,
            normalised_url=TARGET,
            scheme="https",
            hostname="example.com",
            port=443,
            resolved_addresses=("204.69.207.1",),
        )

    @patch("webguard_api.executor.validate_target_url")
    def test_crawl_execution_writes_private_audit_and_report(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()
        observed = {}

        def fake_crawl(target, **kwargs):
            audit = (
                self.artifacts
                / "jobs"
                / record.job_id
                / kwargs["scan_id"]
                / "authorization-audit.json"
            )
            observed["audit_existed_before_scan"] = audit.is_file()
            observed["policy"] = kwargs["crawl_policy"]
            observed["token"] = kwargs["cancellation_token"]
            return completed_report(kwargs["scan_id"])

        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            crawl_scanner=fake_crawl,
        )
        token = CrawlCancellationToken()
        outcome = executor.execute(record, cancellation_token=token)
        report = self.artifacts / outcome.report_ref
        audit = self.artifacts / outcome.audit_ref
        safety_receipt = self.artifacts / outcome.safety_receipt_ref
        self.assertTrue(observed["audit_existed_before_scan"])
        self.assertIs(observed["token"], token)
        self.assertEqual(observed["policy"].maximum_pages, 10)
        self.assertTrue(report.is_file())
        self.assertTrue(audit.is_file())
        self.assertTrue(safety_receipt.is_file())
        loaded_receipt = load_signed_trustscan_safety_receipt_json(
            safety_receipt.read_text(encoding="utf-8")
        )
        self.signer.verify_safety_receipt(loaded_receipt)
        self.assertEqual(loaded_receipt.claims.job_id, record.job_id)
        self.assertEqual(loaded_receipt.claims.termination_reason, "completed")
        self.assertEqual(loaded_receipt.fingerprint, outcome.safety_receipt_sha256)
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(audit.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(safety_receipt.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(report.parent.stat().st_mode), 0o700)
        self.assertNotIn(str(self.artifacts), outcome.report_ref)

    @patch("webguard_api.executor.validate_target_url")
    def test_report_is_written_through_an_injected_artifact_store_not_local_disk(self, validate_mock) -> None:
        """Slice 17 requirement 7: when a real (non-Local) ArtifactStore
        is injected -- exactly how production wires ObjectStorageArtifactStore
        -- the completed report's bytes go through it, not the local
        filesystem. The audit file and safety receipt are unaffected
        (still local, unchanged -- this slice's object-storage
        migration is scoped to reports only)."""
        validate_mock.return_value = self.validated_target()
        record = self.running_record(mode=ScanJobMode.SINGLE_PAGE)

        class _FakeArtifactStore:
            def __init__(self) -> None:
                self.written: dict[str, bytes] = {}

            def put(self, reference: str, data: bytes) -> str:
                self.written[reference] = data
                return "fake-checksum"

            def get_reference(self, reference: str) -> bytes:
                return self.written[reference]

            def exists(self, reference: str) -> bool:
                return reference in self.written

            def delete(self, reference: str) -> None:
                self.written.pop(reference, None)

            def checksum(self, reference: str) -> str:
                return "fake-checksum"

        fake_store = _FakeArtifactStore()
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            single_scanner=lambda target, **kwargs: completed_report(kwargs["scan_id"]),
            artifact_store=fake_store,
        )
        outcome = executor.execute(record)
        self.assertIn(outcome.report_ref, fake_store.written)
        report_on_disk = self.artifacts / outcome.report_ref
        self.assertFalse(report_on_disk.exists(), "the report must not also land on local disk")
        # The audit file and safety receipt are untouched by this
        # slice's object-storage migration -- still local, as before.
        self.assertTrue((self.artifacts / outcome.audit_ref).is_file())
        self.assertTrue((self.artifacts / outcome.safety_receipt_ref).is_file())

    @patch("webguard_api.executor.validate_target_url")
    def test_runtime_permit_revocation_blocks_next_request_and_writes_receipt(
        self, validate_mock
    ) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()

        def fake_crawl(target, **kwargs):
            kwargs["before_request"](target, "GET")
            kwargs["after_request"](
                target,
                "GET",
                SafeHttpResponse(
                    status=200,
                    reason="OK",
                    headers=(),
                    body=b"",
                    connected_address="204.69.207.1",
                    elapsed_milliseconds=5,
                ),
                None,
            )
            self.store.revoke_scan_permit_scoped(
                self.permit.permit.claims.permit_id,
                ORG_ID,
                revoked_by=OWNER_ID,
                now=NOW,
            )
            kwargs["before_request"](target, "GET")
            raise AssertionError("revoked permit must block before the second request")

        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            crawl_scanner=fake_crawl,
        )
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "trustscan_permit_revoked")
        self.assertIsNotNone(caught.exception.safety_receipt_ref)
        receipt_path = self.artifacts / caught.exception.safety_receipt_ref
        loaded = load_signed_trustscan_safety_receipt_json(
            receipt_path.read_text(encoding="utf-8")
        )
        self.signer.verify_safety_receipt(loaded)
        self.assertEqual(loaded.claims.requests_permitted, 1)
        self.assertEqual(loaded.claims.requests_blocked, 1)
        self.assertEqual(loaded.claims.termination_reason, "safety_blocked")
        self.assertEqual(
            loaded.fingerprint,
            caught.exception.safety_receipt_sha256,
        )

    @patch("webguard_api.executor.validate_target_url")
    def test_unexpected_scanner_bug_still_writes_a_safety_receipt(
        self, validate_mock
    ) -> None:
        """P6-007: only TrustScanRuntimeSafetyError was converted into a
        JobExecutionError with a signed safety receipt attached; any
        other, genuinely unexpected scanner bug propagated raw, even
        though it could happen after before_request had already
        permitted real network traffic against the authorised target --
        losing the one forensic record of what was actually sent."""
        validate_mock.return_value = self.validated_target()
        record = self.running_record()

        def fake_crawl(target, **kwargs):
            kwargs["before_request"](target, "GET")
            kwargs["after_request"](
                target,
                "GET",
                SafeHttpResponse(
                    status=200,
                    reason="OK",
                    headers=(),
                    body=b"",
                    connected_address="204.69.207.1",
                    elapsed_milliseconds=5,
                ),
                None,
            )
            raise RuntimeError("a genuinely unexpected scanner bug")

        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            crawl_scanner=fake_crawl,
        )
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "scan_execution_failed")
        self.assertNotIn(
            "a genuinely unexpected scanner bug", caught.exception.message
        )
        self.assertIsNotNone(caught.exception.safety_receipt_ref)
        receipt_path = self.artifacts / caught.exception.safety_receipt_ref
        loaded = load_signed_trustscan_safety_receipt_json(
            receipt_path.read_text(encoding="utf-8")
        )
        self.signer.verify_safety_receipt(loaded)
        self.assertEqual(loaded.claims.requests_permitted, 1)
        self.assertEqual(loaded.claims.termination_reason, "scanner_error")
        self.assertEqual(
            loaded.fingerprint,
            caught.exception.safety_receipt_sha256,
        )

    @patch("webguard_api.executor.validate_target_url")
    def test_runtime_permit_binding_lookup_failure_still_writes_a_receipt(
        self, validate_mock
    ) -> None:
        """P6-009: revalidate_runtime_permission's own call to
        get_job_permit_binding -- made on every before_request, unlike
        the one-time call before the scan starts -- was not wrapped for
        JobStoreError the way the sibling get_scan_permit_scoped call
        right below it already was. A JobStoreError there used to
        propagate raw past TrustScanRuntimeSafetyEngine's own
        TrustScanPermitError-only handling; confirms the P6-007 safety
        net now covers it too, after a real permitted request."""
        validate_mock.return_value = self.validated_target()
        record = self.running_record()

        real_get_job_permit_binding = self.store.get_job_permit_binding
        calls = {"count": 0}

        def flaky_get_job_permit_binding(job_id):
            calls["count"] += 1
            if calls["count"] >= 3:
                raise JobStoreError(
                    "job_store_lookup_failed",
                    "Unable to read the job permit binding.",
                )
            return real_get_job_permit_binding(job_id)

        def fake_crawl(target, **kwargs):
            kwargs["before_request"](target, "GET")
            kwargs["after_request"](
                target,
                "GET",
                SafeHttpResponse(
                    status=200,
                    reason="OK",
                    headers=(),
                    body=b"",
                    connected_address="204.69.207.1",
                    elapsed_milliseconds=5,
                ),
                None,
            )
            kwargs["before_request"](target, "GET")
            raise AssertionError(
                "must not reach a second request after the binding "
                "lookup failed"
            )

        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            crawl_scanner=fake_crawl,
        )
        with patch.object(
            self.store,
            "get_job_permit_binding",
            side_effect=flaky_get_job_permit_binding,
        ):
            with self.assertRaises(JobExecutionError) as caught:
                executor.execute(record)
        self.assertEqual(caught.exception.code, "scan_execution_failed")
        self.assertIsNotNone(caught.exception.safety_receipt_ref)
        receipt_path = self.artifacts / caught.exception.safety_receipt_ref
        loaded = load_signed_trustscan_safety_receipt_json(
            receipt_path.read_text(encoding="utf-8")
        )
        self.signer.verify_safety_receipt(loaded)
        self.assertEqual(loaded.claims.requests_permitted, 1)
        self.assertEqual(loaded.claims.termination_reason, "scanner_error")
        self.assertEqual(
            loaded.fingerprint,
            caught.exception.safety_receipt_sha256,
        )

    @patch("webguard_api.executor.validate_target_url")
    def test_single_page_uses_single_scanner(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record(mode=ScanJobMode.SINGLE_PAGE)
        observed = {}

        def fake_single(target, **kwargs):
            observed.update(kwargs)
            return completed_report(kwargs["scan_id"])

        def unexpected_crawl(*_args, **_kwargs):
            raise AssertionError("crawl scanner must not be called")

        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            single_scanner=fake_single,
            crawl_scanner=unexpected_crawl,
        )
        outcome = executor.execute(record)
        self.assertIn("fetch_policy", observed)
        self.assertNotIn("crawl_policy", observed)
        self.assertEqual(outcome.report.status.value, "completed")

    @patch("webguard_api.executor.validate_target_url")
    def test_target_validation_failure_does_not_disclose_the_resolved_address(
        self, validate_mock
    ) -> None:
        """Phase 6 C-3: scope_validator.py's TargetValidationError messages
        interpolate the specific address DNS actually returned for the
        tenant's own authorized hostname (e.g. "Commercial scans cannot
        target '10.1.2.3'."), not anything the tenant supplied. Before
        this test's fix, that address reached job.error_message, a
        tenant-visible field -- a tenant who controls their own
        hostname's DNS could read one internal address per job, an
        oracle into the scanning host's network. Only the stable code
        should be preserved; the address itself must not be."""
        from webguard_scanner import TargetValidationError

        internal_address = "10.200.1.55"
        validate_mock.side_effect = TargetValidationError(
            "non_public_address",
            f"Commercial scans cannot target {internal_address!r}.",
        )
        record = self.running_record()
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "non_public_address")
        self.assertNotIn(internal_address, caught.exception.message)

    @patch("webguard_api.executor.validate_target_url")
    def test_artifact_directory_failure_does_not_disclose_the_server_path(
        self, validate_mock
    ) -> None:
        """Phase 6 C-4: these messages interpolated the operator's own
        --artifacts directory (expanded from wherever they configured it,
        e.g. a "~/..." value becomes an absolute path revealing the OS
        username), into job.error_message, a tenant-visible field --
        never anything the requesting tenant supplied. Only the stable
        code is meaningful to a caller; the literal server path is not."""
        validate_mock.return_value = self.validated_target()
        record = self.running_record()
        # A file where the executor expects to create a directory makes
        # Path.mkdir(parents=True, exist_ok=True) raise a real OSError
        # (NotADirectoryError, a real OSError subclass), exercising the
        # real artifact_directory_create_failed path end to end rather
        # than mocking the exception away.
        self.artifacts.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts.write_text("not a directory", encoding="utf-8")
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "artifact_directory_create_failed")
        self.assertNotIn(str(self.artifacts), caught.exception.message)

    @patch("webguard_api.executor.validate_target_url")
    def test_authorization_changed_after_submission_is_rejected(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()
        changed = authorization(purpose="Changed purpose")
        self.auth_path.unlink()
        write_authorization(self.auth_dir, changed)
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(JobExecutionError, "changed"):
            executor.execute(record)
        self.assertFalse(self.artifacts.exists())

    @patch("webguard_api.executor.validate_target_url")
    def test_pre_cancelled_token_writes_no_artifacts(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()
        token = CrawlCancellationToken()
        token.cancel()
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(JobExecutionError, "cancelled"):
            executor.execute(record, cancellation_token=token)
        self.assertFalse(self.artifacts.exists())

    @patch("webguard_api.executor.validate_target_url")
    def test_retry_after_lease_recovery_does_not_collide_with_prior_attempts_audit_file(
        self, validate_mock
    ) -> None:
        """Phase 6 C-8: write_owned_target_audit_file runs with
        overwrite=False, deliberately, so an existing audit record is
        never silently replaced. Before this test's fix, the audit path
        was keyed only by record.job_id, which is fixed for a job's whole
        lifetime; a job requeued after any interruption (a crash, a
        restart, a lost lease) reused the exact same path its own,
        already-written first attempt had left behind, so every retry of
        a job that had gotten that far failed with owned_target_file_exists,
        unconditionally. Each call to execute() generates a fresh scan_id
        (this test's own fake_single closure below proves the two
        attempts get different ones), and the artifact directory now
        nests under it, so this scenario -- an execution attempt for a
        job whose own job_id directory already holds a prior attempt's
        files -- must now succeed rather than always failing."""

        validate_mock.return_value = self.validated_target()
        record = self.running_record(mode=ScanJobMode.SINGLE_PAGE)
        observed_scan_ids: list[str] = []

        def fake_single(target, **kwargs):
            observed_scan_ids.append(kwargs["scan_id"])
            return completed_report(kwargs["scan_id"])

        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
            single_scanner=fake_single,
        )

        first_outcome = executor.execute(record)
        self.assertTrue((self.artifacts / first_outcome.audit_ref).is_file())

        # Simulate the job being requeued and re-executed after a lost
        # lease: the same job record, a second call to execute().
        second_outcome = executor.execute(record)
        self.assertTrue((self.artifacts / second_outcome.audit_ref).is_file())

        self.assertEqual(len(observed_scan_ids), 2)
        self.assertNotEqual(observed_scan_ids[0], observed_scan_ids[1])
        self.assertNotEqual(first_outcome.audit_ref, second_outcome.audit_ref)
        job_dir = self.artifacts / "jobs" / record.job_id
        self.assertEqual(
            len(list(job_dir.iterdir())),
            2,
            "each attempt should get its own scan_id subdirectory",
        )

    def test_non_running_record_is_rejected(self) -> None:
        auth = authorization()
        request = ScanJobRequest(
            idempotency_key="internstack-queued",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )
        queued, _ = self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
            permit_id=self.permit.permit.claims.permit_id,
            permit_sha256=self.permit.permit.fingerprint,
        )
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(JobExecutionError, "running"):
            executor.execute(queued)

    def test_unbound_legacy_job_fails_closed_before_network(self) -> None:
        auth = authorization()
        request = ScanJobRequest(
            idempotency_key="legacy-unbound-job",
            target=TARGET,
            authorization_id=AUTH_ID,
            authorization_sha256=auth.fingerprint,
            mode=ScanJobMode.CRAWL,
            submitted_at=NOW,
        )
        self.store.submit(
            request,
            organization_id=ORG_ID,
            submitted_by=OWNER_ID,
        )
        record = self.store.claim_next(now=NOW)
        assert record is not None
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "trustscan_permit_missing")
        self.assertFalse(self.artifacts.exists())

    def test_revoked_permit_fails_closed_before_network(self) -> None:
        record = self.running_record()
        self.store.revoke_scan_permit_scoped(
            self.permit.permit.claims.permit_id,
            ORG_ID,
            revoked_by=OWNER_ID,
            now=NOW,
        )
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW,
        )
        with self.assertRaises(JobExecutionError) as caught:
            executor.execute(record)
        self.assertEqual(caught.exception.code, "trustscan_permit_revoked")
        self.assertFalse(self.artifacts.exists())

    @patch("webguard_api.executor.validate_target_url")
    def test_authorization_expiry_is_revalidated_at_execution(self, validate_mock) -> None:
        validate_mock.return_value = self.validated_target()
        record = self.running_record()
        executor = ScanJobExecutor(
            authorizations=AuthorizationRepository(self.auth_dir),
            store=self.store,
            trustscan_signer=self.signer,
            artifact_directory=self.artifacts,
            clock=lambda: NOW + timedelta(days=60),
        )
        with self.assertRaisesRegex(JobExecutionError, "expired"):
            executor.execute(record)


if __name__ == "__main__":
    unittest.main()
