from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.tls_config import analyze_tls_config, grade_config


def test_grade_config_classifies_protocol_sets():
    assert grade_config({"TLSv1": True, "TLSv1.2": True}) == "old"
    assert grade_config({"TLSv1.2": True, "TLSv1.3": True}) == "intermediate"
    assert grade_config({"TLSv1.3": True, "TLSv1.2": False}) == "modern"


def test_analyze_tls_config_flags_weak_protocols():
    protocols = {"TLSv1": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": True}
    out = analyze_tls_config("e.com", prober=lambda d, p, t: protocols)

    assert out["status"] == "ok"
    assert out["weak_protocols"] == ["TLSv1", "TLSv1.1"]
    assert out["grade"] == "old"


def test_analyze_tls_config_modern_has_no_weak():
    out = analyze_tls_config("e.com", prober=lambda d, p, t: {"TLSv1.2": True, "TLSv1.3": True})
    assert out["weak_protocols"] == []


def test_weak_tls_protocol_finding():
    checks = {"tls_config": {"status": "ok", "weak_protocols": ["TLSv1"]}}
    findings = {f.id: f for f in build_findings(checks)}

    assert "weak-tls-protocol" in findings
    assert findings["weak-tls-protocol"].severity == "medium"
