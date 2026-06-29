from sentineldeck.scanner import scan_ip, scan_target


def _stub_ip_probes(monkeypatch):
    """Patch every IP-scan probe to a benign offline default."""
    p = "sentineldeck.scanner."
    monkeypatch.setattr(p + "Resolver", lambda *a, **k: (lambda name, rtype: []))
    monkeypatch.setattr(
        p + "fetch_headers",
        lambda ip, timeout=10: {"reachable": True, "headers": {}, "cookies": [], "status": 200},
    )
    monkeypatch.setattr(p + "check_http_redirect", lambda ip, timeout=10: {})
    monkeypatch.setattr(p + "check_security_txt", lambda ip, timeout=10: {})
    monkeypatch.setattr(
        p + "inspect_tls",
        lambda ip, timeout=10: {"reachable": True, "valid": True, "protocol": "TLSv1.3"},
    )
    monkeypatch.setattr(p + "analyze_tls_config", lambda ip: {"status": "ok", "grade": "modern", "weak_protocols": []})
    monkeypatch.setattr(p + "fetch_page", lambda ip, timeout=10: {"reachable": True, "headers": {}, "body": ""})
    monkeypatch.setattr(p + "trace_redirects", lambda ip, timeout=10: {"hops": [], "count": 0, "downgrade": False})
    monkeypatch.setattr(
        p + "analyze_ip_intel",
        lambda ip, timeout=10: {"status": "ok", "ip": ip, "city": "Toronto", "country": "Canada", "asn": 13335},
    )
    monkeypatch.setattr(
        p + "analyze_ip_rdap",
        lambda ip: {"status": "ok", "cidr": "1.1.1.0/24", "abuse_email": "abuse@test.net"},
    )
    monkeypatch.setattr(p + "reverse_ip", lambda ip: {"status": "ok", "count": 2, "domains": ["a.com", "b.com"]})
    monkeypatch.setattr(p + "check_reputation", lambda ip: {"status": "ok", "listed": False})
    monkeypatch.setattr(p + "analyze_web_content", lambda host, page: {"status": "ok"})
    monkeypatch.setattr(
        p + "analyze_internetdb",
        lambda ip, timeout=10: {"status": "ok", "ports": [443], "vulns": ["CVE-2021-44228"]},
    )


def test_scan_ip_builds_ip_report(monkeypatch):
    _stub_ip_probes(monkeypatch)
    report = scan_ip("1.1.1.1")

    assert report.target == "1.1.1.1"
    assert report.checks["target_type"] == "ip"
    assert report.checks["ip_rdap"]["abuse_email"] == "abuse@test.net"
    assert report.checks["reverse_ip"]["count"] == 2
    # InternetDB CVEs are KEV-flagged and raise a scored finding
    assert report.checks["internetdb"]["kev"] == ["CVE-2021-44228"]
    assert any(f.id == "known-cves-on-host" and f.severity == "high" for f in report.findings)
    # domain-only surfaces are not part of an IP report
    assert "subdomains" not in report.checks
    assert "email_security" not in report.checks
    # an IP is its own address, never flagged "unresolved"
    assert not any(f.id == "dns-unresolved" for f in report.findings)
    assert report.grade in {"A", "B", "C", "D", "F"}


def test_scan_ip_skips_internet_sources_for_private_ip(monkeypatch):
    _stub_ip_probes(monkeypatch)
    called = {"rdap": False}
    monkeypatch.setattr(
        "sentineldeck.scanner.analyze_ip_rdap",
        lambda ip: called.__setitem__("rdap", True) or {"status": "ok"},
    )

    report = scan_ip("192.168.1.10")

    assert called["rdap"] is False  # private IP: internet data sources skipped
    assert report.checks["ip_rdap"]["status"] == "skipped"
    assert report.checks["reverse_ip"]["status"] == "skipped"
    assert report.checks["ip_intel"]["status"] == "skipped"


def test_scan_target_dispatches_to_ip(monkeypatch):
    _stub_ip_probes(monkeypatch)
    report = scan_target("https://1.1.1.1/x")
    assert report.checks.get("target_type") == "ip"
    assert report.target == "1.1.1.1"
