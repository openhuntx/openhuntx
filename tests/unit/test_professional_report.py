from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from webguard_contracts import (
    Confidence,
    CrawlLinkSkip,
    CrawlPageScanResult,
    CrawlScanPolicy,
    CrawlScanResult,
    Evidence,
    FindingIdentity,
    NormalizedFinding,
    RequestAttempt,
    RequestAttemptOutcome,
    ScanCoverage,
    ScanResult,
    ScanStatus,
    Severity,
    SkippedCheck,
)
from webguard_scanner import (
    ProfessionalReportError,
    ProfessionalReportProfile,
    build_report_comparison,
    render_professional_html,
)


BASE = datetime(2026, 8, 5, 12, 0, tzinfo=timezone.utc)


def finding(
    rule: str,
    *,
    severity: Severity = Severity.MEDIUM,
    title: str = "Security finding",
    description: str = "Description",
    remediation: str = "Remediate it.",
) -> NormalizedFinding:
    return NormalizedFinding(
        identity=FindingIdentity(
            rule_id=rule,
            asset="https://example.com",
            path="/login",
        ),
        source="webguard-native",
        title=title,
        description=description,
        severity=severity,
        confidence=Confidence.HIGH,
        remediation=remediation,
        detected_at=BASE,
        evidence=(Evidence("Header was absent."),),
        references=("https://example.org/reference",),
        tags=("passive",),
    )


def report(
    scan_id: str,
    *,
    completed_offset: int,
    findings: tuple[NormalizedFinding, ...] = (),
    target: str = "https://example.com/",
) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        scan_type="passive-http-response",
        status=ScanStatus.COMPLETED,
        target=target,
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=BASE + timedelta(minutes=completed_offset - 1),
        completed_at=BASE + timedelta(minutes=completed_offset),
        coverage=ScanCoverage(
            planned_checks=("web.test.check",),
            executed_checks=("web.test.check",),
            requests_attempted=1,
            requests_succeeded=1,
        ),
        findings=findings,
        connected_addresses=("93.184.216.34",),
        http_statuses=(200,),
    )


def crawl_report() -> CrawlScanResult:
    page = CrawlPageScanResult(
        url="http://127.0.0.1:3000/",
        depth=0,
        parent_url=None,
        status=ScanStatus.COMPLETED,
        coverage=ScanCoverage(
            planned_checks=("web.headers.csp", "web.headers.hsts"),
            executed_checks=("web.headers.csp",),
            skipped_checks=(
                SkippedCheck(
                    "web.headers.hsts",
                    "HSTS applies only to HTTPS.",
                ),
            ),
            requests_attempted=1,
            requests_succeeded=1,
        ),
        request_attempts=(
            RequestAttempt(
                attempt_number=1,
                started_at=BASE,
                completed_at=BASE + timedelta(milliseconds=10),
                outcome=RequestAttemptOutcome.SUCCEEDED,
                connected_address="127.0.0.1",
                http_status=200,
            ),
        ),
        content_type="text/html",
        connected_address="127.0.0.1",
        http_status=200,
    )
    return CrawlScanResult(
        scan_id="33333333-3333-4333-8333-333333333333",
        scan_type="passive-http-crawl",
        status=ScanStatus.COMPLETED,
        target="http://127.0.0.1:3000/",
        engine="webguard-native",
        engine_version="0.1.0",
        started_at=BASE,
        completed_at=BASE + timedelta(seconds=1),
        policy=CrawlScanPolicy(
            maximum_pages=2,
            maximum_depth=1,
            maximum_links_per_page=25,
            maximum_url_length=2048,
            minimum_delay_seconds=0,
            query_mode="drop",
            allowed_content_types=("text/html",),
            blocked_path_segments=("delete", "logout"),
        ),
        pages=(page,),
        skipped_links=(CrawlLinkSkip("external_origin", 1),),
    )


def profile(**kwargs) -> ProfessionalReportProfile:
    values = {
        "organization": "Example Ltd",
        "generated_at": BASE + timedelta(hours=2),
    }
    values.update(kwargs)
    return ProfessionalReportProfile(**values)


class ProfessionalReportProfileTests(unittest.TestCase):
    def test_accepts_valid_profile(self) -> None:
        item = profile()
        self.assertEqual(item.organization, "Example Ltd")

    def test_trims_fields(self) -> None:
        item = profile(organization=" Example Ltd ", prepared_by=" Team ")
        self.assertEqual(item.organization, "Example Ltd")
        self.assertEqual(item.prepared_by, "Team")

    def test_rejects_empty_organization(self) -> None:
        with self.assertRaises(ProfessionalReportError):
            profile(organization=" ")

    def test_rejects_long_classification(self) -> None:
        with self.assertRaises(ProfessionalReportError):
            profile(classification="x" * 65)

    def test_rejects_naive_generated_at(self) -> None:
        with self.assertRaisesRegex(ProfessionalReportError, "timezone-aware"):
            profile(generated_at=datetime(2026, 1, 1))


class ReportComparisonBuilderTests(unittest.TestCase):
    def test_classifies_new_remaining_and_fixed(self) -> None:
        old = finding("web.old")
        remaining = finding("web.remaining")
        new = finding("web.new")
        baseline = report(
            "11111111-1111-4111-8111-111111111111",
            completed_offset=1,
            findings=(old, remaining),
        )
        current = report(
            "22222222-2222-4222-8222-222222222222",
            completed_offset=2,
            findings=(remaining, new),
        )
        result = build_report_comparison(
            baseline,
            current,
            generated_at=BASE + timedelta(hours=1),
        )
        self.assertEqual(result.new_count, 1)
        self.assertEqual(result.remaining_count, 1)
        self.assertEqual(result.fixed_count, 1)

    def test_detects_presentation_change(self) -> None:
        baseline_finding = finding("web.same", title="Old title")
        current_finding = finding("web.same", title="New title")
        result = build_report_comparison(
            report(
                "11111111-1111-4111-8111-111111111111",
                completed_offset=1,
                findings=(baseline_finding,),
            ),
            report(
                "22222222-2222-4222-8222-222222222222",
                completed_offset=2,
                findings=(current_finding,),
            ),
            generated_at=BASE + timedelta(hours=1),
        )
        self.assertTrue(result.remaining_findings[0].presentation_changed)

    def test_ignores_detected_at_change(self) -> None:
        original = finding("web.same")
        newer = replace(original, detected_at=BASE + timedelta(hours=1))
        result = build_report_comparison(
            report(
                "11111111-1111-4111-8111-111111111111",
                completed_offset=1,
                findings=(original,),
            ),
            report(
                "22222222-2222-4222-8222-222222222222",
                completed_offset=2,
                findings=(newer,),
            ),
            generated_at=BASE + timedelta(hours=1),
        )
        self.assertFalse(result.remaining_findings[0].presentation_changed)

    def test_rejects_target_mismatch(self) -> None:
        with self.assertRaisesRegex(ProfessionalReportError, "same canonical target"):
            build_report_comparison(
                report(
                    "11111111-1111-4111-8111-111111111111",
                    completed_offset=1,
                ),
                report(
                    "22222222-2222-4222-8222-222222222222",
                    completed_offset=2,
                    target="https://other.example/",
                ),
            )

    def test_rejects_current_before_baseline(self) -> None:
        with self.assertRaisesRegex(ProfessionalReportError, "must not complete"):
            build_report_comparison(
                report(
                    "11111111-1111-4111-8111-111111111111",
                    completed_offset=2,
                ),
                report(
                    "22222222-2222-4222-8222-222222222222",
                    completed_offset=1,
                ),
            )

    def test_rejects_comparing_a_scan_against_itself(self) -> None:
        """C-9: a crawl resumed from a checkpoint reuses its original
        scan_id, so a report ends up compared against itself with a
        real, reachable frequency -- previously this reached the
        ReportComparison contract directly, which raises
        ReportComparisonError, a type the CLI's own except clause for
        this command does not catch."""
        with self.assertRaisesRegex(
            ProfessionalReportError, "must not be the same scan"
        ):
            build_report_comparison(
                report(
                    "11111111-1111-4111-8111-111111111111",
                    completed_offset=1,
                ),
                report(
                    "11111111-1111-4111-8111-111111111111",
                    completed_offset=2,
                ),
            )

    def test_rejects_generated_before_current(self) -> None:
        with self.assertRaisesRegex(ProfessionalReportError, "generated_at"):
            build_report_comparison(
                report(
                    "11111111-1111-4111-8111-111111111111",
                    completed_offset=1,
                ),
                report(
                    "22222222-2222-4222-8222-222222222222",
                    completed_offset=2,
                ),
                generated_at=BASE,
            )


class HtmlRenderingTests(unittest.TestCase):
    def test_renders_complete_document(self) -> None:
        html = render_professional_html(
            report(
                "22222222-2222-4222-8222-222222222222",
                completed_offset=2,
            ),
            profile(),
        )
        self.assertTrue(html.startswith("<!doctype html>"))
        self.assertIn("</html>", html)

    def test_contains_no_javascript(self) -> None:
        html = render_professional_html(
            report(
                "22222222-2222-4222-8222-222222222222",
                completed_offset=2,
            ),
            profile(),
        )
        self.assertNotIn("<script", html.lower())
        self.assertIn("default-src 'none'", html)

    def test_escapes_customer_metadata(self) -> None:
        html = render_professional_html(
            report(
                "22222222-2222-4222-8222-222222222222",
                completed_offset=2,
            ),
            profile(organization="Example <script>alert(1)</script>"),
        )
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_escapes_finding_content(self) -> None:
        risky = finding(
            "web.escape",
            title="<img src=x onerror=alert(1)>",
            description="A & B",
        )
        html = render_professional_html(
            report(
                "22222222-2222-4222-8222-222222222222",
                completed_offset=2,
                findings=(risky,),
            ),
            profile(),
        )
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)
        self.assertIn("A &amp; B", html)

    def test_renders_severity_counts(self) -> None:
        findings = (
            finding("web.critical", severity=Severity.CRITICAL),
            finding("web.high", severity=Severity.HIGH),
            finding("web.medium", severity=Severity.MEDIUM),
            finding("web.low", severity=Severity.LOW),
            finding("web.info", severity=Severity.INFORMATIONAL),
        )
        html = render_professional_html(
            report(
                "22222222-2222-4222-8222-222222222222",
                completed_offset=2,
                findings=findings,
            ),
            profile(),
        )
        for label in ("Critical", "High", "Medium", "Low", "Informational"):
            self.assertIn(label, html)

    def test_orders_critical_before_low(self) -> None:
        low = finding("web.low", severity=Severity.LOW, title="Low issue")
        critical = finding(
            "web.critical",
            severity=Severity.CRITICAL,
            title="Critical issue",
        )
        html = render_professional_html(
            report(
                "22222222-2222-4222-8222-222222222222",
                completed_offset=2,
                findings=(low, critical),
            ),
            profile(),
        )
        self.assertLess(html.index("Critical issue"), html.index("Low issue"))

    def test_renders_empty_findings_message(self) -> None:
        html = render_professional_html(
            report(
                "22222222-2222-4222-8222-222222222222",
                completed_offset=2,
            ),
            profile(),
        )
        self.assertIn("No findings were recorded", html)

    def test_renders_scope_and_limitations(self) -> None:
        html = render_professional_html(
            report(
                "22222222-2222-4222-8222-222222222222",
                completed_offset=2,
            ),
            profile(),
        )
        self.assertIn("Assessment scope", html)
        self.assertIn("does not submit forms", html)
        self.assertIn("does not prove", html)

    def test_renders_crawl_report_with_page_level_skipped_checks(self) -> None:
        html = render_professional_html(
            crawl_report(),
            profile(),
        )
        self.assertIn("Passive same-origin crawl", html)
        self.assertIn("web.headers.hsts", html)
        self.assertIn("HSTS applies only to HTTPS.", html)
        self.assertIn("http://127.0.0.1:3000/", html)
        self.assertIn("1 checks were skipped", html)

    def test_renders_comparison_section(self) -> None:
        baseline = report(
            "11111111-1111-4111-8111-111111111111",
            completed_offset=1,
            findings=(finding("web.fixed", title="Fixed item"),),
        )
        current = report(
            "22222222-2222-4222-8222-222222222222",
            completed_offset=2,
            findings=(finding("web.new", title="New item"),),
        )
        comparison = build_report_comparison(
            baseline,
            current,
            generated_at=BASE + timedelta(hours=1),
        )
        html = render_professional_html(
            current,
            profile(),
            comparison=comparison,
        )
        self.assertIn("Remediation verification", html)
        self.assertIn("Fixed item", html)
        self.assertIn("New item", html)

    def test_rejects_comparison_for_other_current_scan(self) -> None:
        baseline = report(
            "11111111-1111-4111-8111-111111111111",
            completed_offset=1,
        )
        current = report(
            "22222222-2222-4222-8222-222222222222",
            completed_offset=2,
        )
        comparison = build_report_comparison(
            baseline,
            current,
            generated_at=BASE + timedelta(hours=1),
        )
        other = report(
            "33333333-3333-4333-8333-333333333333",
            completed_offset=3,
        )
        with self.assertRaisesRegex(ProfessionalReportError, "does not match"):
            render_professional_html(other, profile(), comparison=comparison)


if __name__ == "__main__":
    unittest.main()
