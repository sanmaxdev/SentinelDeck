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
    monkeypatch.setattr("sentineldeck.scanner.analyze_email_security", lambda domain: email)
    monkeypatch.setattr(
        "sentineldeck.scanner.analyze_dns_hygiene",
        lambda domain: {"caa": {"present": True}, "dnssec": {"enabled": True}},
    )
    monkeypatch.setattr("sentineldeck.scanner.analyze_domain_intel", lambda domain, timeout=10: {"status": "error"})

    report = scan_domain("example.com")

    assert report.checks["email_security"]["dmarc"]["policy"] == "reject"
