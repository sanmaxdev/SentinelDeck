from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.reputation import check_reputation


def test_check_reputation_listed():
    data = {"query_status": "ok", "urls": [{"url": "x"}, {"url": "y"}]}
    out = check_reputation("bad.example", fetcher=lambda d, timeout=10: data)

    assert out["listed"] is True
    assert out["url_count"] == 2
    assert out["sources"] == ["URLhaus"]


def test_check_reputation_clean():
    out = check_reputation("good.example", fetcher=lambda d, timeout=10: {"query_status": "no_results"})
    assert out["listed"] is False


def test_check_reputation_handles_failure():
    assert check_reputation("x.example", fetcher=lambda d, timeout=10: None)["status"] == "error"


def test_domain_listed_malicious_finding_is_high():
    checks = {"reputation": {"status": "ok", "listed": True, "sources": ["URLhaus"]}}
    findings = {f.id: f for f in build_findings(checks)}

    assert "domain-listed-malicious" in findings
    assert findings["domain-listed-malicious"].severity == "high"
