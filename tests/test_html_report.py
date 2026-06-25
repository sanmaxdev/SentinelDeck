from sentineldeck.models import Finding, ScanReport
from sentineldeck.reporters.html_report import render_html_report, write_html_report


def sample_report() -> ScanReport:
    return ScanReport(
        target="example.com",
        generated_at="2026-06-24T21:00:00+00:00",
        risk_score=42,
        grade="C",
        checks={"dns": {"resolved": True}},
        findings=[
            Finding(
                id="missing-content-security-policy",
                title="Missing content-security-policy header",
                severity="medium",
                description="The HTTPS response does not include content-security-policy.",
                recommendation="Add a Content-Security-Policy.",
                evidence={"checked_header": "content-security-policy"},
            ),
            Finding(
                id="dmarc-monitor-only",
                title="DMARC is monitor-only",
                severity="low",
                description="The domain publishes DMARC but does not request enforcement.",
                recommendation="Move DMARC to quarantine or reject after monitoring.",
                evidence={"policy": "none"},
            ),
        ],
    )


def test_render_html_report_contains_executive_summary_and_severity_sections():
    html = render_html_report(sample_report())

    assert "SentinelDeck Security Report" in html
    assert "example.com" in html
    assert "Risk Score" in html
    assert "42/100" in html
    assert "Grade C" in html
    assert "Executive Summary" in html
    assert "Medium Findings" in html
    assert "Low Findings" in html
    assert "Missing content-security-policy header" in html
    assert "DMARC is monitor-only" in html


def test_render_html_report_escapes_user_controlled_content():
    report = sample_report()
    report.target = "evil.example<script>alert(1)</script>"
    report.findings[0].title = "<script>alert(1)</script>"

    html = render_html_report(report)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_render_html_report_includes_simulator_and_copy_paste_fixes():
    html = render_html_report(sample_report())

    assert "Remediation Simulator" in html
    assert 'id="sim-list"' in html
    assert "Apply quick wins" in html
    # The CSP finding carries a concrete header fix snippet.
    assert "Content-Security-Policy: default-src" in html
    assert "FIX" in html


def test_render_html_report_shows_attack_surface():
    report = sample_report()
    report.checks["subdomains"] = {
        "status": "ok",
        "source": "crt.sh",
        "count": 2,
        "subdomains": ["dev.example.com", "www.example.com"],
        "sensitive": ["dev.example.com"],
    }

    html = render_html_report(report)

    assert "Attack Surface" in html
    assert "dev.example.com" in html
    assert "host-sensitive" in html


def test_render_html_report_moves_suppressed_findings_to_accepted():
    report = sample_report()
    report.findings[0].suppressed = True  # accept the CSP finding

    html = render_html_report(report)

    assert "Accepted" in html
    assert report.findings[0].id in html
    # The accepted finding is dropped from its severity section.
    assert "Medium Findings" not in html


def test_write_html_report_creates_parent_directory(tmp_path):
    output = tmp_path / "reports" / "example.html"

    path = write_html_report(sample_report(), output)

    assert path == output
    assert output.exists()
    assert "SentinelDeck Security Report" in output.read_text(encoding="utf-8")
