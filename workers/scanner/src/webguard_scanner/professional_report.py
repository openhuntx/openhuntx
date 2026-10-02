"""Professional, self-contained HTML reporting for WebGuard scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from typing import Iterable, Tuple
from urllib.parse import urlsplit

from webguard_contracts import (
    ComparedFinding,
    CrawlScanResult,
    FindingDisposition,
    NormalizedFinding,
    ReportComparison,
    ScanResult,
    Severity,
    WebGuardReport,
)


DEFAULT_REPORT_CLASSIFICATION = "Confidential"
DEFAULT_REPORT_TITLE = "Web Application Security Assessment"
MAXIMUM_REPORT_TEXT_LENGTH = 256

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


class ProfessionalReportError(ValueError):
    """Controlled failure raised during report comparison or rendering."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _text(value: object, name: str, maximum: int = MAXIMUM_REPORT_TEXT_LENGTH) -> str:
    if not isinstance(value, str):
        raise ProfessionalReportError(
            f"{name}_invalid",
            f"{name} must be text.",
        )
    cleaned = value.strip()
    if not cleaned or len(cleaned) > maximum or "\x00" in cleaned:
        raise ProfessionalReportError(
            f"{name}_invalid",
            f"{name} is empty, too long, or contains a null byte.",
        )
    return cleaned


def _aware_utc(value: datetime, name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ProfessionalReportError(
            f"{name}_invalid",
            f"{name} must be timezone-aware.",
        )
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class ProfessionalReportProfile:
    """Customer-facing presentation metadata."""

    organization: str
    report_title: str = DEFAULT_REPORT_TITLE
    prepared_by: str = "OpenHuntX"
    classification: str = DEFAULT_REPORT_CLASSIFICATION
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "organization",
            _text(self.organization, "organization"),
        )
        object.__setattr__(
            self,
            "report_title",
            _text(self.report_title, "report_title"),
        )
        object.__setattr__(
            self,
            "prepared_by",
            _text(self.prepared_by, "prepared_by"),
        )
        object.__setattr__(
            self,
            "classification",
            _text(self.classification, "classification", 64),
        )
        object.__setattr__(
            self,
            "generated_at",
            _aware_utc(self.generated_at, "generated_at"),
        )


def _completed_at(report: WebGuardReport) -> datetime:
    completed = report.completed_at
    if completed is None:
        raise ProfessionalReportError(
            "report_not_complete",
            "Professional reporting requires a terminal report with completed_at.",
        )
    return completed


def _presentation_signature(finding: NormalizedFinding) -> tuple[object, ...]:
    return (
        finding.title,
        finding.description,
        finding.severity.value,
        finding.confidence.value,
        finding.remediation,
        tuple((item.namespace, item.value) for item in finding.identifiers),
        tuple((item.summary, item.artifact_reference) for item in finding.evidence),
        finding.references,
        finding.tags,
    )


def build_report_comparison(
    baseline: WebGuardReport,
    current: WebGuardReport,
    *,
    generated_at: datetime | None = None,
) -> ReportComparison:
    """Compare compatible reports using stable finding fingerprints."""

    if not isinstance(baseline, (ScanResult, CrawlScanResult)) or not isinstance(
        current, (ScanResult, CrawlScanResult)
    ):
        raise ProfessionalReportError(
            "comparison_report_invalid",
            "Both values must be validated WebGuard reports.",
        )
    if baseline.target != current.target:
        raise ProfessionalReportError(
            "comparison_target_mismatch",
            "Baseline and current reports must have the same canonical target.",
        )
    if baseline.scan_id == current.scan_id:
        # C-9: a crawl resumed from a checkpoint reuses its original
        # scan_id, so comparing such a report against itself is a real,
        # reachable case, not a theoretical one. Without this check, the
        # ReportComparison contract below raises ReportComparisonError,
        # a type from a different module the CLI's own except clause
        # here does not catch -- caught here instead, alongside every
        # other cross-field check this function already makes, so every
        # caller gets one consistent exception type.
        raise ProfessionalReportError(
            "comparison_scan_ids_equal",
            "Baseline and current reports must not be the same scan.",
        )
    baseline_completed = _completed_at(baseline)
    current_completed = _completed_at(current)
    if current_completed < baseline_completed:
        raise ProfessionalReportError(
            "comparison_scan_order_invalid",
            "Current report must not complete before the baseline report.",
        )

    generated = (
        datetime.now(timezone.utc)
        if generated_at is None
        else _aware_utc(generated_at, "generated_at")
    )
    if generated < current_completed:
        raise ProfessionalReportError(
            "comparison_generated_at_invalid",
            "generated_at must not precede current report completion.",
        )

    baseline_by_fingerprint = {
        item.fingerprint: item for item in baseline.findings
    }
    current_by_fingerprint = {
        item.fingerprint: item for item in current.findings
    }

    new = tuple(
        ComparedFinding(FindingDisposition.NEW, current_by_fingerprint[key])
        for key in sorted(current_by_fingerprint.keys() - baseline_by_fingerprint.keys())
    )
    fixed = tuple(
        ComparedFinding(FindingDisposition.FIXED, baseline_by_fingerprint[key])
        for key in sorted(baseline_by_fingerprint.keys() - current_by_fingerprint.keys())
    )
    remaining = tuple(
        ComparedFinding(
            FindingDisposition.REMAINING,
            current_by_fingerprint[key],
            presentation_changed=(
                _presentation_signature(current_by_fingerprint[key])
                != _presentation_signature(baseline_by_fingerprint[key])
            ),
        )
        for key in sorted(current_by_fingerprint.keys() & baseline_by_fingerprint.keys())
    )

    return ReportComparison(
        baseline_scan_id=baseline.scan_id,
        current_scan_id=current.scan_id,
        target=current.target,
        baseline_completed_at=baseline_completed,
        current_completed_at=current_completed,
        generated_at=generated,
        new_findings=new,
        remaining_findings=remaining,
        fixed_findings=fixed,
    )


def _severity_counts(findings: Iterable[NormalizedFinding]) -> dict[Severity, int]:
    counts = {severity: 0 for severity in Severity}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def _highest_severity(findings: Tuple[NormalizedFinding, ...]) -> str:
    if not findings:
        return "No findings"
    return min(findings, key=lambda item: _SEVERITY_ORDER[item.severity]).severity.value.title()


def _format_timestamp(value: datetime | None) -> str:
    if value is None:
        return "Not available"
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _affected_location(finding: NormalizedFinding) -> str:
    origin = finding.identity.asset.rstrip("/")
    return origin + finding.identity.path


def _risk_summary(findings: Tuple[NormalizedFinding, ...]) -> str:
    counts = _severity_counts(findings)
    if counts[Severity.CRITICAL] or counts[Severity.HIGH]:
        return (
            "Prioritise critical and high-severity remediation before expanding "
            "the assessment scope."
        )
    if counts[Severity.MEDIUM]:
        return (
            "No critical or high-severity findings were recorded. Medium-severity "
            "security-hardening work should be scheduled and verified."
        )
    if counts[Severity.LOW]:
        return (
            "The recorded issues are low-severity hardening opportunities. They "
            "should still be tracked to closure."
        )
    if counts[Severity.INFORMATIONAL]:
        return (
            "Only informational observations were recorded in the assessed scope."
        )
    return "No findings were recorded in the assessed scope."


def _scope_rows(report: WebGuardReport) -> list[tuple[str, str]]:
    coverage = report.coverage
    rows = [
        ("Canonical target", report.target),
        ("Scan ID", report.scan_id),
        ("Engine", f"{report.engine} {report.engine_version}"),
        ("Status", report.status.value),
        ("Started", _format_timestamp(report.started_at)),
        ("Completed", _format_timestamp(report.completed_at)),
        ("Coverage", f"{coverage.completion_percent}%" if coverage.completion_percent is not None else "Not applicable"),
        ("Requests", f"{coverage.requests_attempted} attempted / {coverage.requests_succeeded} succeeded"),
    ]
    if isinstance(report, CrawlScanResult):
        rows.extend(
            [
                ("Assessment mode", "Passive same-origin crawl"),
                ("Termination", report.termination.reason.value),
                (
                    "Pages",
                    f"{coverage.pages_attempted} attempted / "
                    f"{coverage.pages_succeeded} succeeded / "
                    f"{coverage.pages_failed} failed / "
                    f"{coverage.pages_pending} pending",
                ),
            ]
        )
    else:
        rows.append(("Assessment mode", "Passive single-page response analysis"))
    return rows


def _skipped_check_entries(
    report: WebGuardReport,
) -> tuple[tuple[str, str, str | None], ...]:
    """Return skipped checks with optional page context."""

    if isinstance(report, CrawlScanResult):
        return tuple(
            (item.check_id, item.reason, page.url)
            for page in report.pages
            for item in page.coverage.skipped_checks
        )

    return tuple(
        (item.check_id, item.reason, None)
        for item in report.coverage.skipped_checks
    )


def _limitations(report: WebGuardReport) -> tuple[str, ...]:
    base = [
        "The assessment is passive and does not submit forms, execute JavaScript, brute-force credentials, or send exploit payloads.",
        "Coverage applies only to responses successfully fetched within the recorded scope, policy, and execution limits.",
        "A finding-free result does not prove that the application is free from vulnerabilities.",
        "Client-side routes and authenticated functionality may require separately authorised assessment methods.",
    ]
    if isinstance(report, CrawlScanResult) and report.coverage.pages_attempted <= 1:
        base.append(
            "Only one page was fetched; JavaScript-rendered navigation may have limited crawl discovery."
        )
    skipped_check_count = len(_skipped_check_entries(report))
    if skipped_check_count:
        base.append(
            f"{skipped_check_count} checks were skipped because they were not applicable or could not be executed."
        )
    return tuple(base)


def _render_rows(rows: Iterable[tuple[str, str]]) -> str:
    return "".join(
        f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>"
        for label, value in rows
    )


def _render_finding(finding: NormalizedFinding, index: int) -> str:
    identifiers = "".join(
        f"<li>{escape(item.namespace)}: {escape(item.value)}</li>"
        for item in finding.identifiers
    ) or "<li>None recorded</li>"
    evidence = "".join(
        f"<li>{escape(item.summary)}</li>" for item in finding.evidence
    ) or "<li>No additional evidence summary recorded</li>"
    references = "".join(
        f'<li><a href="{escape(item, quote=True)}" rel="noreferrer">{escape(item)}</a></li>'
        for item in finding.references
    ) or "<li>None recorded</li>"
    tags = ", ".join(finding.tags) if finding.tags else "None"
    severity = finding.severity.value
    return f"""
<article class="finding" id="finding-{escape(finding.fingerprint)}">
  <div class="finding-head">
    <div><span class="index">{index:02d}</span><h3>{escape(finding.title)}</h3></div>
    <span class="severity severity-{escape(severity)}">{escape(severity.upper())}</span>
  </div>
  <table class="details">
    <tr><th>Rule</th><td><code>{escape(finding.identity.rule_id)}</code></td></tr>
    <tr><th>Affected location</th><td><code>{escape(_affected_location(finding))}</code></td></tr>
    <tr><th>Method</th><td>{escape(finding.identity.method)}</td></tr>
    <tr><th>Confidence</th><td>{escape(finding.confidence.value.title())}</td></tr>
    <tr><th>Fingerprint</th><td><code>{escape(finding.fingerprint)}</code></td></tr>
    <tr><th>Tags</th><td>{escape(tags)}</td></tr>
  </table>
  <h4>Description</h4><p>{escape(finding.description)}</p>
  <h4>Evidence</h4><ul>{evidence}</ul>
  <h4>Recommended remediation</h4><p>{escape(finding.remediation)}</p>
  <h4>Identifiers</h4><ul>{identifiers}</ul>
  <h4>References</h4><ul>{references}</ul>
</article>"""


def _comparison_section(comparison: ReportComparison | None) -> str:
    if comparison is None:
        return ""

    def entries(items: Tuple[ComparedFinding, ...]) -> str:
        if not items:
            return "<li>None</li>"
        return "".join(
            "<li>"
            f"<strong>{escape(item.finding.title)}</strong> "
            f"<code>{escape(item.finding.identity.rule_id)}</code>"
            + (" <em>(presentation changed)</em>" if item.presentation_changed else "")
            + "</li>"
            for item in items
        )

    return f"""
<section>
  <h2>Remediation verification</h2>
  <div class="metrics comparison">
    <div><span>{comparison.new_count}</span><small>New</small></div>
    <div><span>{comparison.remaining_count}</span><small>Remaining</small></div>
    <div><span>{comparison.fixed_count}</span><small>Fixed</small></div>
    <div><span>{comparison.changed_count}</span><small>Changed</small></div>
  </div>
  <p>Baseline scan <code>{escape(comparison.baseline_scan_id)}</code> was compared with current scan <code>{escape(comparison.current_scan_id)}</code> using stable finding fingerprints.</p>
  <div class="compare-grid">
    <div><h3>New findings</h3><ul>{entries(comparison.new_findings)}</ul></div>
    <div><h3>Remaining findings</h3><ul>{entries(comparison.remaining_findings)}</ul></div>
    <div><h3>Fixed findings</h3><ul>{entries(comparison.fixed_findings)}</ul></div>
  </div>
</section>"""


def render_professional_html(
    report: WebGuardReport,
    profile: ProfessionalReportProfile,
    *,
    comparison: ReportComparison | None = None,
) -> str:
    """Render one self-contained, JavaScript-free professional HTML report."""

    if not isinstance(report, (ScanResult, CrawlScanResult)):
        raise ProfessionalReportError(
            "report_invalid",
            "report must be a validated WebGuard report.",
        )
    if not isinstance(profile, ProfessionalReportProfile):
        raise ProfessionalReportError(
            "report_profile_invalid",
            "profile must be a ProfessionalReportProfile.",
        )
    _completed_at(report)
    if comparison is not None:
        if not isinstance(comparison, ReportComparison):
            raise ProfessionalReportError(
                "comparison_invalid",
                "comparison must be a ReportComparison.",
            )
        if comparison.current_scan_id != report.scan_id:
            raise ProfessionalReportError(
                "comparison_current_scan_mismatch",
                "Comparison current scan does not match the rendered report.",
            )

    findings = tuple(
        sorted(
            report.findings,
            key=lambda item: (
                _SEVERITY_ORDER[item.severity],
                item.identity.rule_id,
                item.fingerprint,
            ),
        )
    )
    counts = _severity_counts(findings)
    findings_html = "".join(
        _render_finding(finding, index)
        for index, finding in enumerate(findings, start=1)
    ) or '<div class="empty">No findings were recorded in the assessed scope.</div>'
    limitation_items = "".join(
        f"<li>{escape(item)}</li>" for item in _limitations(report)
    )
    error_items = "".join(
        f"<li><code>{escape(error.stage)}/{escape(error.code)}</code>: {escape(error.message)}</li>"
        for error in report.errors
    ) or "<li>None</li>"
    skipped_items = "".join(
        "<li>"
        f"<code>{escape(check_id)}</code>"
        + (
            f" on <code>{escape(page_url)}</code>"
            if page_url is not None
            else ""
        )
        + f": {escape(reason)}</li>"
        for check_id, reason, page_url in _skipped_check_entries(report)
    ) or "<li>None</li>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
<title>{escape(profile.report_title)} - {escape(profile.organization)}</title>
<style>
:root{{--ink:#111827;--muted:#5f6b7a;--line:#d7dce2;--paper:#ffffff;--soft:#f5f7f9;--red:#b42318;--amber:#b54708;--blue:#175cd3;}}
*{{box-sizing:border-box}}body{{margin:0;background:#eef1f4;color:var(--ink);font-family:Inter,Arial,sans-serif;line-height:1.55}}main{{max-width:1080px;margin:32px auto;background:var(--paper);box-shadow:0 12px 40px #0f172a18}}header{{padding:56px 64px;background:#101828;color:white;border-bottom:6px solid #e31b23}}header .brand{{letter-spacing:.12em;text-transform:uppercase;font-weight:700;color:#fda29b}}h1{{font-size:38px;line-height:1.15;margin:18px 0 8px}}header p{{margin:4px 0;color:#d0d5dd}}section{{padding:34px 64px;border-bottom:1px solid var(--line)}}h2{{font-size:25px;margin:0 0 20px}}h3{{display:inline;font-size:19px}}h4{{margin:22px 0 7px}}p{{white-space:normal}}code{{overflow-wrap:anywhere}}table{{border-collapse:collapse;width:100%}}th,td{{text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid var(--line)}}th{{width:220px;color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.04em}}.metrics{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:18px 0}}.metrics div{{background:var(--soft);padding:18px;border-top:4px solid #667085}}.metrics span{{display:block;font-size:30px;font-weight:700}}.metrics small{{text-transform:uppercase;color:var(--muted)}}.comparison{{grid-template-columns:repeat(4,1fr)}}.finding{{border:1px solid var(--line);border-radius:8px;padding:24px;margin:18px 0;break-inside:avoid}}.finding-head{{display:flex;justify-content:space-between;gap:20px;align-items:center}}.index{{display:inline-block;margin-right:12px;color:var(--muted);font-weight:700}}.severity{{padding:5px 10px;border-radius:999px;font-size:12px;font-weight:800}}.severity-critical,.severity-high{{background:#fee4e2;color:#b42318}}.severity-medium{{background:#fef0c7;color:#b54708}}.severity-low{{background:#dbeafe;color:#175cd3}}.severity-informational{{background:#e4e7ec;color:#344054}}.compare-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}}.compare-grid>div{{background:var(--soft);padding:18px}}.empty{{padding:24px;background:var(--soft);border-left:5px solid #667085}}footer{{padding:24px 64px;color:var(--muted);font-size:12px}}@media(max-width:760px){{main{{margin:0}}header,section,footer{{padding:28px 22px}}.metrics,.comparison,.compare-grid{{grid-template-columns:1fr 1fr}}th{{width:130px}}}}@media print{{body{{background:white}}main{{margin:0;max-width:none;box-shadow:none}}a{{color:inherit}}}}
</style>
</head>
<body>
<main>
<header>
  <div class="brand">OpenHuntX WebGuard</div>
  <h1>{escape(profile.report_title)}</h1>
  <p>{escape(profile.organization)}</p>
  <p>Prepared by {escape(profile.prepared_by)} · {escape(profile.classification)}</p>
  <p>Generated {_format_timestamp(profile.generated_at)}</p>
</header>
<section>
  <h2>Executive summary</h2>
  <p>{escape(_risk_summary(findings))}</p>
  <p><strong>Highest recorded severity:</strong> {escape(_highest_severity(findings))}</p>
  <div class="metrics">
    <div><span>{counts[Severity.CRITICAL]}</span><small>Critical</small></div>
    <div><span>{counts[Severity.HIGH]}</span><small>High</small></div>
    <div><span>{counts[Severity.MEDIUM]}</span><small>Medium</small></div>
    <div><span>{counts[Severity.LOW]}</span><small>Low</small></div>
    <div><span>{counts[Severity.INFORMATIONAL]}</span><small>Informational</small></div>
  </div>
</section>
{_comparison_section(comparison)}
<section><h2>Assessment scope</h2><table>{_render_rows(_scope_rows(report))}</table></section>
<section><h2>Technical findings</h2>{findings_html}</section>
<section><h2>Coverage and limitations</h2><ul>{limitation_items}</ul><h3>Skipped checks</h3><ul>{skipped_items}</ul><h3>Execution errors</h3><ul>{error_items}</ul></section>
<footer>This report contains security-sensitive information. Distribution should follow the stated classification. WebGuard results describe only the recorded scope and execution conditions.</footer>
</main>
</body>
</html>
"""


__all__ = [
    "DEFAULT_REPORT_CLASSIFICATION",
    "DEFAULT_REPORT_TITLE",
    "MAXIMUM_REPORT_TEXT_LENGTH",
    "ProfessionalReportError",
    "ProfessionalReportProfile",
    "build_report_comparison",
    "render_professional_html",
]
