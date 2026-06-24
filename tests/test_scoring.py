from sentineldeck.models import Finding
from sentineldeck.risk.scoring import build_findings, grade, score_findings


def test_score_findings_caps_at_100():
    findings = [Finding("x", "x", "critical", "x", "x") for _ in range(4)]
    assert score_findings(findings) == 100


def test_grade_boundaries():
    assert grade(0) == "A"
    assert grade(20) == "B"
    assert grade(40) == "C"
    assert grade(60) == "D"
    assert grade(80) == "F"


def test_build_findings_flags_infrastructure_failures():
    checks = {
        "dns": {"resolved": False},
        "http": {"reachable": False, "error": "timed out"},
        "tls": {"valid": False, "error": "handshake failed"},
    }

    finding_ids = {finding.id for finding in build_findings(checks)}

    assert "dns-unresolved" in finding_ids
    assert "https-unreachable" in finding_ids
    assert "tls-invalid" in finding_ids


def test_build_findings_flags_expired_certificate_over_expiring():
    checks = {
        "http": {"reachable": True, "headers": {}},
        "tls": {"valid": True, "expired": True, "days_remaining": -3},
    }

    finding_ids = {finding.id for finding in build_findings(checks)}

    assert "tls-expired" in finding_ids
    assert "tls-expiring-soon" not in finding_ids


def test_build_findings_flags_missing_security_headers():
    checks = {
        "http": {"reachable": True, "headers": {}},
        "missing_security_headers": {
            "strict-transport-security": "Add HSTS.",
            "referrer-policy": "Add Referrer-Policy.",
        },
    }

    findings = {finding.id: finding for finding in build_findings(checks)}

    assert findings["missing-strict-transport-security"].severity == "medium"
    assert findings["missing-referrer-policy"].severity == "low"
