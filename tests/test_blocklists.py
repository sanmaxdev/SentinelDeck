from sentineldeck.risk.scoring import build_findings, compute_passes
from sentineldeck.scanners.blocklists import _is_blocked, check_blocklists


def test_is_blocked_detects_nxdomain_and_sinkhole():
    assert _is_blocked({"Status": 3}) is True
    assert _is_blocked({"Status": 0, "Answer": [{"type": 1, "data": "0.0.0.0"}]}) is True
    assert _is_blocked({"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]}) is False
    assert _is_blocked(None) is None


def test_check_blocklists_flags_security_filters():
    def query(endpoint, domain, timeout=8):
        return {"Status": 3} if "quad9" in endpoint else {"Status": 0, "Answer": [{"type": 1, "data": "1.2.3.4"}]}

    out = check_blocklists("bad.example", query=query)

    assert out["status"] == "ok"
    assert "Quad9" in out["blocked_security"]
    assert "Google DNS" not in out["blocked_security"]


def test_blocklist_finding_is_medium():
    findings = {f.id: f for f in build_findings({"blocklists": {"status": "ok", "blocked_security": ["Quad9"]}})}

    assert "domain-on-dns-blocklist" in findings
    assert findings["domain-on-dns-blocklist"].severity == "medium"


def test_compute_passes_lists_good_configuration():
    checks = {
        "tls": {"valid": True, "forward_secrecy": True},
        "dns_hygiene": {"dnssec": {"enabled": True}, "caa": {"present": True}},
        "email_security": {"spf": {"present": True}, "dmarc": {"policy": "reject"}},
    }
    passes = compute_passes(checks)

    assert "TLS certificate valid and trusted" in passes
    assert "DNSSEC enabled" in passes
    assert "DMARC is enforced" in passes
