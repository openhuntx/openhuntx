"""Tests for passive HTTP security-header analysis."""

from __future__ import annotations

import unittest
from dataclasses import replace

from webguard_contracts import Severity

from webguard_scanner import (
    HeaderAnalysisError,
    SafeHttpResponse,
    ValidatedTarget,
    analyze_security_headers,
)


def target(
    *,
    scheme: str = "https",
    url: str = "https://example.com/login",
    port: int = 443,
) -> ValidatedTarget:
    return ValidatedTarget(
        original_url=url,
        normalised_url=url,
        scheme=scheme,
        hostname="example.com",
        port=port,
        resolved_addresses=("93.184.216.34",),
    )


def response(
    *headers: tuple[str, str],
) -> SafeHttpResponse:
    return SafeHttpResponse(
        status=200,
        reason="OK",
        headers=tuple(headers),
        body=b"<html></html>",
        connected_address="93.184.216.34",
        elapsed_milliseconds=5,
    )


class HeaderAnalyzerTests(unittest.TestCase):
    """Verify passive header checks and normalized output."""

    def test_reports_expected_missing_headers_on_https(self) -> None:
        findings = analyze_security_headers(
            target(),
            response(),
        )

        self.assertEqual(
            {item.identity.rule_id for item in findings},
            {
                "web.headers.csp.missing",
                "web.headers.frame_protection.missing",
                "web.headers.hsts.missing",
                "web.headers.referrer_policy.missing",
                "web.headers.x_content_type_options.missing",
            },
        )

    def test_does_not_require_hsts_on_http(self) -> None:
        findings = analyze_security_headers(
            target(
                scheme="http",
                url="http://example.com/",
                port=80,
            ),
            response(),
        )

        self.assertNotIn(
            "web.headers.hsts.missing",
            {item.identity.rule_id for item in findings},
        )

    def test_secure_header_set_produces_no_findings(self) -> None:
        findings = analyze_security_headers(
            target(),
            response(
                (
                    "Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains",
                ),
                (
                    "X-Content-Type-Options",
                    "nosniff",
                ),
                (
                    "Content-Security-Policy",
                    "default-src 'self'; frame-ancestors 'none'",
                ),
                (
                    "Referrer-Policy",
                    "strict-origin-when-cross-origin",
                ),
            ),
        )

        self.assertEqual(findings, ())

    def test_header_names_are_case_insensitive(self) -> None:
        findings = analyze_security_headers(
            target(),
            response(
                (
                    "sTrIcT-TrAnSpOrT-SeCuRiTy",
                    "max-age=31536000",
                ),
                (
                    "x-CoNtEnT-tYpE-oPtIoNs",
                    "NoSnIfF",
                ),
                (
                    "CONTENT-SECURITY-POLICY",
                    "frame-ancestors 'self'",
                ),
                (
                    "REFERRER-POLICY",
                    "no-referrer",
                ),
            ),
        )

        self.assertEqual(findings, ())

    def test_invalid_nosniff_value_is_reported(self) -> None:
        findings = analyze_security_headers(
            target(),
            response(
                (
                    "Strict-Transport-Security",
                    "max-age=31536000",
                ),
                (
                    "X-Content-Type-Options",
                    "invalid",
                ),
                (
                    "Content-Security-Policy",
                    "frame-ancestors 'none'",
                ),
                (
                    "Referrer-Policy",
                    "no-referrer",
                ),
            ),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].identity.rule_id,
            "web.headers.x_content_type_options.invalid",
        )

    def test_oversized_header_value_does_not_crash_the_analyzer(self) -> None:
        """Phase 6 C-1: this header's value reached Evidence(...) directly,
        unbounded. Evidence itself rejects anything over 4096 characters,
        but that check happened after the value was already embedded, so
        a target returning a header this long raised an uncontrolled
        ContractValidationError instead of HeaderAnalysisError -- the one
        this analyzer's own pipeline entry actually isolates -- aborting
        the whole scan over one response header."""
        findings = analyze_security_headers(
            target(),
            response(
                (
                    "X-Content-Type-Options",
                    "a" * 5000,
                ),
            ),
        )
        matches = [
            item for item in findings
            if item.identity.rule_id == "web.headers.x_content_type_options.invalid"
        ]
        self.assertEqual(len(matches), 1)
        self.assertLessEqual(len(matches[0].evidence[0].summary), 4096)

    def test_control_character_in_header_value_does_not_crash_the_analyzer(
        self,
    ) -> None:
        """Evidence itself also rejects a null byte; the same unbounded
        embedding meant a header value containing one raised the same
        uncontrolled exception."""
        findings = analyze_security_headers(
            target(),
            response(
                (
                    "X-Content-Type-Options",
                    "nosniff\x00",
                ),
            ),
        )
        matches = [
            item for item in findings
            if item.identity.rule_id == "web.headers.x_content_type_options.invalid"
        ]
        self.assertEqual(len(matches), 1)
        self.assertNotIn("\x00", matches[0].evidence[0].summary)

    def test_many_duplicated_header_values_do_not_crash_the_analyzer(self) -> None:
        findings = analyze_security_headers(
            target(),
            response(
                *(("X-Content-Type-Options", "invalid-value-" + str(i)) for i in range(100)),
            ),
        )
        matches = [
            item for item in findings
            if item.identity.rule_id == "web.headers.x_content_type_options.invalid"
        ]
        self.assertEqual(len(matches), 1)
        self.assertLessEqual(len(matches[0].evidence[0].summary), 4096)

    def test_x_frame_options_can_provide_frame_fallback(self) -> None:
        findings = analyze_security_headers(
            target(),
            response(
                (
                    "Strict-Transport-Security",
                    "max-age=31536000",
                ),
                (
                    "X-Content-Type-Options",
                    "nosniff",
                ),
                (
                    "Content-Security-Policy",
                    "default-src 'self'",
                ),
                (
                    "X-Frame-Options",
                    "DENY",
                ),
                (
                    "Referrer-Policy",
                    "no-referrer",
                ),
            ),
        )

        self.assertEqual(findings, ())

    def test_findings_use_normalized_contract(self) -> None:
        findings = analyze_security_headers(
            target(),
            response(),
        )

        for item in findings:
            self.assertEqual(
                item.identity.asset,
                "https://example.com",
            )
            self.assertEqual(
                item.identity.path,
                "/login",
            )
            self.assertEqual(
                item.identity.method,
                "GET",
            )
            self.assertEqual(
                item.source,
                "webguard-passive",
            )
            self.assertEqual(
                item.confidence.value,
                "confirmed",
            )
            self.assertEqual(len(item.fingerprint), 64)

    def test_hsts_finding_has_medium_severity(self) -> None:
        findings = analyze_security_headers(
            target(),
            response(),
        )

        hsts = next(
            item
            for item in findings
            if item.identity.rule_id
            == "web.headers.hsts.missing"
        )

        self.assertIs(
            hsts.severity,
            Severity.MEDIUM,
        )

    def test_rejects_inconsistent_target_fields(self) -> None:
        inconsistent = replace(
            target(),
            hostname="different.example",
        )

        with self.assertRaises(
            HeaderAnalysisError
        ) as context:
            analyze_security_headers(
                inconsistent,
                response(),
            )

        self.assertEqual(
            context.exception.code,
            "validated_target_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
