from sentineldeck.scanner import scan_domain


def test_scan_domain_includes_email_security(monkeypatch):
    dns = {"resolved": True, "addresses": ["127.0.0.1"]}
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

    labels: list[str] = []
    scan_domain("example.com", progress=labels.append)

    assert "DNS resolution" in labels
    assert "TLS certificate" in labels
    assert "Technology fingerprint" in labels
    assert len(labels) >= 9
