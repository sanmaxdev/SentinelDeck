from sentineldeck.scanner import scan_domain


def test_scan_domain_includes_email_security(monkeypatch):
    dns = {"resolved": True, "addresses": []}
    http = {"reachable": True, "headers": {}}
    tls = {"valid": True, "days_remaining": 90}
    email = {
        "mx": {"present": True, "records": ["10 mail.example.com."]},
        "spf": {"present": True, "records": ["v=spf1 mx -all"], "policy": "-all"},
        "dmarc": {"present": True, "records": ["v=DMARC1; p=reject"], "policy": "reject"},
    }

    redirect = {"https_redirect": True, "http_status": 301}

    monkeypatch.setattr("sentineldeck.scanner.resolve_domain", lambda domain: dns)
    monkeypatch.setattr("sentineldeck.scanner.fetch_headers", lambda domain, timeout=10: http)
    monkeypatch.setattr("sentineldeck.scanner.check_http_redirect", lambda domain, timeout=10: redirect)
    monkeypatch.setattr("sentineldeck.scanner.check_security_txt", lambda domain, timeout=10: {"present": True})
    monkeypatch.setattr("sentineldeck.scanner.inspect_tls", lambda domain, timeout=10: tls)
    monkeypatch.setattr("sentineldeck.scanner.analyze_email_security", lambda domain, resolver=None: email)
    monkeypatch.setattr(
        "sentineldeck.scanner.analyze_dns_hygiene",
        lambda domain, resolver=None: {"caa": {"present": True}, "dnssec": {"enabled": True}},
    )
    monkeypatch.setattr("sentineldeck.scanner.analyze_domain_intel", lambda domain, timeout=10: {"status": "error"})
    monkeypatch.setattr(
        "sentineldeck.scanner.discover_subdomains",
        lambda domain, timeout=10, host_fetcher=None: {"status": "error"},
    )
    monkeypatch.setattr(
        "sentineldeck.scanner.fetch_page", lambda domain, timeout=10: {"reachable": False, "body": ""}
    )
    monkeypatch.setattr(
        "sentineldeck.scanner.trace_redirects",
        lambda domain, timeout=10: {"hops": [], "count": 0, "downgrade": False},
    )
    monkeypatch.setattr("sentineldeck.scanner.analyze_web_content", lambda domain, page: {"status": "error"})
    monkeypatch.setattr("sentineldeck.scanner.analyze_ip_intel", lambda ip, timeout=10: {"status": "error"})
    monkeypatch.setattr(
        "sentineldeck.scanner.detect_typosquats",
        lambda domain, resolver=None: {"status": "ok", "registered": []},
    )
    monkeypatch.setattr("sentineldeck.scanner.check_reputation", lambda domain: {"status": "error", "listed": False})
    monkeypatch.setattr("sentineldeck.scanner.archive_history", lambda domain: {"status": "ok", "snapshots": 0})
    monkeypatch.setattr(
        "sentineldeck.scanner.analyze_tls_config",
        lambda domain: {"status": "error", "weak_protocols": []},
    )
    monkeypatch.setattr(
        "sentineldeck.scanner.check_blocklists",
        lambda domain: {"status": "ok", "results": [], "blocked_security": []},
    )

    report = scan_domain("example.com")

    assert report.checks["email_security"]["dmarc"]["policy"] == "reject"


def test_scan_domain_reports_progress(monkeypatch):
    monkeypatch.setattr("sentineldeck.scanner.resolve_domain", lambda domain: {"status": "ok"})
    monkeypatch.setattr(
        "sentineldeck.scanner.fetch_headers",
        lambda domain, timeout=10: {"reachable": True, "headers": {}, "cookies": []},
    )
    monkeypatch.setattr("sentineldeck.scanner.check_http_redirect", lambda domain, timeout=10: {})
    monkeypatch.setattr("sentineldeck.scanner.check_security_txt", lambda domain, timeout=10: {})
    monkeypatch.setattr("sentineldeck.scanner.inspect_tls", lambda domain, timeout=10: {"valid": True})
    monkeypatch.setattr(
        "sentineldeck.scanner.analyze_email_security",
        lambda domain, resolver=None: {"mx": {"present": False}},
    )
    monkeypatch.setattr("sentineldeck.scanner.analyze_dns_hygiene", lambda domain, resolver=None: {})
    monkeypatch.setattr("sentineldeck.scanner.analyze_domain_intel", lambda domain, timeout=10: {"status": "error"})
    monkeypatch.setattr(
        "sentineldeck.scanner.discover_subdomains",
        lambda domain, timeout=10, host_fetcher=None: {"status": "skipped", "subdomains": []},
    )
    monkeypatch.setattr(
        "sentineldeck.scanner.fetch_page",
        lambda domain, timeout=10: {"reachable": True, "headers": {}, "body": ""},
    )
    monkeypatch.setattr(
        "sentineldeck.scanner.trace_redirects",
        lambda domain, timeout=10: {"hops": [], "count": 0, "downgrade": False},
    )
    monkeypatch.setattr("sentineldeck.scanner.analyze_web_content", lambda domain, page: {"status": "ok"})
    monkeypatch.setattr("sentineldeck.scanner.analyze_ip_intel", lambda ip, timeout=10: {"status": "ok"})
    monkeypatch.setattr(
        "sentineldeck.scanner.detect_typosquats",
        lambda domain, resolver=None: {"status": "ok", "registered": []},
    )
    monkeypatch.setattr("sentineldeck.scanner.check_reputation", lambda domain: {"status": "ok", "listed": False})
    monkeypatch.setattr("sentineldeck.scanner.archive_history", lambda domain: {"status": "ok", "snapshots": 0})
    monkeypatch.setattr(
        "sentineldeck.scanner.analyze_tls_config",
        lambda domain: {"status": "error", "weak_protocols": []},
    )
    monkeypatch.setattr(
        "sentineldeck.scanner.check_blocklists",
        lambda domain: {"status": "ok", "results": [], "blocked_security": []},
    )

    labels: list[str] = []
    scan_domain("example.com", progress=labels.append)

    # Labels now carry a " :: <summary>" suffix, so match on the stage prefix.
    assert any(lbl.startswith("DNS resolution") for lbl in labels)
    assert any(lbl.startswith("Technology fingerprint") for lbl in labels)
    assert any(lbl.startswith("IP intelligence (geo, ASN)") for lbl in labels)
    assert len(labels) >= 10


def _stub_all_probes(monkeypatch):
    """Patch every probe to a benign offline default; tests override what they need."""
    p = "sentineldeck.scanner."
    monkeypatch.setattr(p + "resolve_domain", lambda domain: {"resolved": True, "addresses": []})
    monkeypatch.setattr(
        p + "fetch_headers",
        lambda domain, timeout=10: {"reachable": True, "headers": {}, "cookies": []},
    )
    monkeypatch.setattr(p + "check_http_redirect", lambda domain, timeout=10: {})
    monkeypatch.setattr(p + "check_security_txt", lambda domain, timeout=10: {})
    monkeypatch.setattr(p + "inspect_tls", lambda domain, timeout=10: {"valid": True})
    monkeypatch.setattr(p + "analyze_email_security", lambda domain, resolver=None: {"mx": {"present": False}})
    monkeypatch.setattr(p + "analyze_dns_hygiene", lambda domain, resolver=None: {})
    monkeypatch.setattr(p + "analyze_domain_intel", lambda domain, timeout=10: {"status": "error"})
    monkeypatch.setattr(
        p + "discover_subdomains",
        lambda domain, timeout=10, host_fetcher=None: {"status": "skipped", "subdomains": []},
    )
    monkeypatch.setattr(p + "fetch_page", lambda domain, timeout=10: {"reachable": True, "headers": {}, "body": ""})
    monkeypatch.setattr(p + "trace_redirects", lambda domain, timeout=10: {"hops": [], "count": 0, "downgrade": False})
    monkeypatch.setattr(p + "detect_typosquats", lambda domain, resolver=None: {"status": "ok", "registered": []})
    monkeypatch.setattr(p + "check_reputation", lambda domain: {"status": "error", "listed": False})
    monkeypatch.setattr(p + "archive_history", lambda domain: {"status": "ok", "snapshots": 0})
    monkeypatch.setattr(p + "analyze_tls_config", lambda domain: {"status": "error", "weak_protocols": []})
    monkeypatch.setattr(p + "check_blocklists", lambda domain: {"status": "ok", "results": [], "blocked_security": []})
    monkeypatch.setattr(p + "analyze_web_content", lambda domain, page: {"status": "ok"})
    monkeypatch.setattr(p + "analyze_ip_intel", lambda ip, timeout=10: {"status": "error"})
    monkeypatch.setattr(p + "analyze_internetdb", lambda ip, timeout=10: {"status": "ok", "ports": [], "vulns": []})
    monkeypatch.setattr(p + "analyze_asn", lambda ip, timeout=12: {"status": "ok", "asn": None, "prefix_count": 0})


def test_scan_survives_a_probe_that_raises(monkeypatch):
    _stub_all_probes(monkeypatch)

    def boom(domain, timeout=10):
        raise RuntimeError("tls exploded")

    monkeypatch.setattr("sentineldeck.scanner.inspect_tls", boom)

    report = scan_domain("example.com")  # must not raise

    assert report.checks["tls"] == {"status": "error", "error": "tls exploded"}
    assert "email_security" in report.checks
    assert report.grade in {"A", "B", "C", "D", "F"}


def test_scan_survives_a_post_step_that_raises(monkeypatch):
    _stub_all_probes(monkeypatch)

    def boom(domain, page):
        raise RuntimeError("web content exploded")

    monkeypatch.setattr("sentineldeck.scanner.analyze_web_content", boom)

    report = scan_domain("example.com")  # must not raise

    assert report.checks["web_content"] == {"status": "error"}
