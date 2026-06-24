from sentineldeck.scanner import scan_domain


def test_scan_domain_includes_email_security(monkeypatch):
    monkeypatch.setattr("sentineldeck.scanner.resolve_domain", lambda domain: {"resolved": True, "addresses": ["127.0.0.1"]})
    monkeypatch.setattr("sentineldeck.scanner.fetch_headers", lambda domain: {"reachable": True, "headers": {}})
    monkeypatch.setattr("sentineldeck.scanner.inspect_tls", lambda domain: {"valid": True, "days_remaining": 90})
    monkeypatch.setattr(
        "sentineldeck.scanner.analyze_email_security",
        lambda domain: {
            "mx": {"present": True, "records": ["10 mail.example.com."]},
            "spf": {"present": True, "records": ["v=spf1 mx -all"], "policy": "-all"},
            "dmarc": {"present": True, "records": ["v=DMARC1; p=reject"], "policy": "reject"},
        },
    )

    report = scan_domain("example.com")

    assert report.checks["email_security"]["dmarc"]["policy"] == "reject"
