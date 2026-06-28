from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners import ports as ports_mod
from sentineldeck.scanners.ports import scan_ports


def test_scan_ports_reports_open_and_risky(monkeypatch):
    # Pretend 22 (SSH) and 6379 (Redis, risky) are open.
    monkeypatch.setattr(ports_mod, "_connect", lambda domain, port, timeout: port in (22, 6379))
    out = scan_ports("e.com", ports={22: "SSH", 80: "HTTP", 6379: "Redis"})

    opened = {p["port"]: p for p in out["open"]}
    assert set(opened) == {22, 6379}
    assert opened[6379]["risky"] is True
    assert opened[22]["risky"] is False


def test_exposed_risky_ports_finding():
    checks = {"ports": {"status": "ok", "open": [{"port": 3306, "service": "MySQL", "risky": True}]}}
    findings = {f.id: f for f in build_findings(checks)}

    assert "exposed-risky-ports" in findings
    assert findings["exposed-risky-ports"].severity == "medium"


def test_no_finding_when_only_safe_ports_open():
    checks = {"ports": {"status": "ok", "open": [{"port": 443, "service": "HTTPS", "risky": False}]}}
    assert "exposed-risky-ports" not in {f.id for f in build_findings(checks)}
