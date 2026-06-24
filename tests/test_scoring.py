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


def test_build_findings_classifies_tls_failure_reason():
    checks = {"tls": {"valid": False, "reason": "self-signed", "error": "self-signed certificate"}}

    findings = {finding.id: finding for finding in build_findings(checks)}

    assert "tls-self-signed" in findings
    assert "self-signed" in findings["tls-self-signed"].title.lower()


def test_build_findings_flags_outdated_tls_protocol():
    checks = {"tls": {"valid": True, "protocol": "TLSv1", "protocol_outdated": True}}

    finding_ids = {finding.id for finding in build_findings(checks)}

    assert "tls-outdated-protocol" in finding_ids


def test_build_findings_flags_missing_https_redirect():
    checks = {"http": {"reachable": True, "headers": {}, "https_redirect": False, "http_status": 200}}

    finding_ids = {finding.id for finding in build_findings(checks)}

    assert "no-https-redirect" in finding_ids


def test_build_findings_passes_through_header_issues():
    checks = {
        "http": {"reachable": True, "headers": {"strict-transport-security": "max-age=0"}},
        "header_issues": [{
            "id": "hsts-ineffective",
            "title": "HSTS is present but disabled",
            "severity": "medium",
            "description": "max-age=0",
            "recommendation": "Set a real max-age.",
            "evidence": {},
        }],
    }

    finding_ids = {finding.id for finding in build_findings(checks)}

    assert "hsts-ineffective" in finding_ids


def test_score_findings_ignores_indeterminate_findings():
    findings = [
        Finding("a", "a", "high", "a", "a"),
        Finding("b", "b", "high", "b", "b", confidence="indeterminate"),
    ]

    assert score_findings(findings) == 25


def test_build_findings_flags_weak_tls_key():
    finding_ids = {f.id for f in build_findings({"tls": {"valid": True, "key_type": "RSA", "key_bits": 1024}})}

    assert "tls-weak-key" in finding_ids


def test_build_findings_flags_weak_tls_signature():
    finding_ids = {f.id for f in build_findings({"tls": {"valid": True, "signature_algorithm": "sha1"}})}

    assert "tls-weak-signature" in finding_ids


def test_build_findings_flags_missing_security_txt():
    checks = {"http": {"reachable": True, "headers": {}, "security_txt": {"present": False, "url": "u"}}}

    finding_ids = {f.id for f in build_findings(checks)}

    assert "no-security-txt" in finding_ids
