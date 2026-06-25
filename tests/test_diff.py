from sentineldeck.diff import diff_reports
from sentineldeck.models import Finding, ScanReport
from sentineldeck.reporters.diff_report import render_diff_report


def finding(id: str, severity: str = "medium", title: str | None = None, confidence: str = "confirmed") -> Finding:
    return Finding(
        id=id,
        title=title or id.replace("-", " ").title(),
        severity=severity,
        description="d",
        recommendation="r",
        confidence=confidence,
    )


def report(
    target: str,
    score: int,
    grade: str,
    findings: list[Finding],
    when: str = "2026-06-01T00:00:00+00:00",
) -> ScanReport:
    return ScanReport(
        target=target,
        generated_at=when,
        risk_score=score,
        grade=grade,
        checks={},
        findings=findings,
    )


def test_diff_partitions_new_resolved_and_persisting():
    previous = report("example.com", 17, "A", [finding("caa-missing", "low"), finding("dmarc-missing")])
    current = report("example.com", 29, "B", [finding("dmarc-missing"), finding("tls-expired", "high")])

    delta = diff_reports(previous, current)

    assert {f.id for f in delta.new_findings} == {"tls-expired"}
    assert {f.id for f in delta.resolved_findings} == {"caa-missing"}
    assert {f.id for f in delta.persisting_findings} == {"dmarc-missing"}


def test_diff_computes_score_delta_and_direction():
    previous = report("example.com", 17, "A", [])
    current = report("example.com", 29, "B", [finding("dmarc-missing")])

    delta = diff_reports(previous, current)

    assert delta.score_delta == 12
    assert delta.direction == "regressed"
    assert delta.regressed is True


def test_diff_direction_improved_when_score_drops():
    previous = report("example.com", 29, "B", [finding("dmarc-missing")])
    current = report("example.com", 12, "A", [])

    delta = diff_reports(previous, current)

    assert delta.score_delta == -17
    assert delta.direction == "improved"
    assert delta.regressed is False


def test_diff_direction_changed_when_score_flat_but_findings_churn():
    previous = report("example.com", 12, "A", [finding("caa-missing", "low")])
    current = report("example.com", 12, "A", [finding("no-security-txt", "low")])

    delta = diff_reports(previous, current)

    assert delta.score_delta == 0
    assert delta.direction == "changed"


def test_diff_direction_unchanged_when_identical():
    findings = [finding("dmarc-missing")]
    delta = diff_reports(report("example.com", 12, "A", findings), report("example.com", 12, "A", list(findings)))

    assert delta.direction == "unchanged"
    assert delta.regressed is False
    assert delta.new_findings == []
    assert delta.resolved_findings == []


def test_diff_detects_severity_escalation():
    previous = report("example.com", 5, "A", [finding("spf-weak-policy", "low")])
    current = report("example.com", 12, "A", [finding("spf-weak-policy", "medium")])

    delta = diff_reports(previous, current)

    assert len(delta.severity_changes) == 1
    change = delta.severity_changes[0]
    assert change.id == "spf-weak-policy"
    assert change.previous_severity == "low"
    assert change.current_severity == "medium"
    assert change.escalated is True


def test_alerting_findings_are_new_high_or_critical_and_exclude_indeterminate():
    previous = report("example.com", 0, "A", [])
    current = report(
        "example.com",
        50,
        "C",
        [
            finding("tls-expired", "high"),
            finding("dns-unresolved", "high", confidence="indeterminate"),
            finding("dmarc-missing", "medium"),
        ],
    )

    delta = diff_reports(previous, current)

    assert {f.id for f in delta.alerting_findings} == {"tls-expired"}
    assert delta.regressed is True


def test_regressed_true_on_new_critical_even_if_score_capped():
    # Both scores hit the 100 cap, so score_delta is 0, but a brand-new critical
    # finding must still be treated as a regression for monitoring.
    previous = report("example.com", 100, "F", [finding("a", "critical"), finding("b", "critical")])
    current = report("example.com", 100, "F", [finding("a", "critical"), finding("c", "critical")])

    delta = diff_reports(previous, current)

    assert delta.score_delta == 0
    assert {f.id for f in delta.alerting_findings} == {"c"}
    assert delta.regressed is True


def test_diff_preserves_mismatched_targets():
    delta = diff_reports(report("old.com", 0, "A", []), report("new.com", 0, "A", []))

    assert delta.previous_target == "old.com"
    assert delta.target == "new.com"


def test_diff_to_dict_is_json_serialisable_and_complete():
    previous = report("example.com", 5, "A", [finding("spf-weak-policy", "low")])
    current = report("example.com", 25, "B", [finding("spf-weak-policy", "medium"), finding("tls-expired", "high")])

    data = diff_reports(previous, current).to_dict()

    assert data["direction"] == "regressed"
    assert data["score_delta"] == 20
    assert data["regressed"] is True
    assert [f["id"] for f in data["new_findings"]] == ["tls-expired"]
    assert data["severity_changes"][0]["escalated"] is True


def test_new_findings_sorted_by_severity():
    previous = report("example.com", 0, "A", [])
    current = report(
        "example.com",
        60,
        "D",
        [finding("low-one", "low"), finding("crit", "critical"), finding("med", "medium")],
    )

    delta = diff_reports(previous, current)

    assert [f.id for f in delta.new_findings] == ["crit", "med", "low-one"]


def test_render_diff_report_shows_headline_and_sections():
    previous = report("example.com", 5, "A", [finding("caa-missing", "low")])
    current = report("example.com", 30, "B", [finding("tls-expired", "high")])

    html = render_diff_report(diff_reports(previous, current))

    assert "SentinelDeck Change Report" in html
    assert "example.com" in html
    assert "Posture regressed" in html
    assert "New findings" in html
    assert "Resolved" in html
    assert "tls-expired" in html
    assert "caa-missing" in html


def test_render_diff_report_escapes_user_content():
    previous = report("example.com", 0, "A", [])
    current = report("example.com", 25, "B", [finding("xss", "high", title="<script>alert(1)</script>")])

    html = render_diff_report(diff_reports(previous, current))

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
