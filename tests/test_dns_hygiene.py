from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.dns_hygiene import analyze_dns_hygiene


def resolver(records, status="ok"):
    return lambda name, record_type: (list(records.get(record_type, [])), status)


def test_analyze_dns_hygiene_reports_presence():
    out = analyze_dns_hygiene(
        "example.com",
        resolver=resolver({"CAA": ['0 issue "letsencrypt.org"'], "DNSKEY": ["256 3 13 AAAA"]}),
    )

    assert out["caa"]["present"] is True
    assert out["dnssec"]["enabled"] is True


def test_dns_hygiene_findings_flag_absences():
    out = analyze_dns_hygiene("example.com", resolver=resolver({}))

    finding_ids = {f.id for f in build_findings({"dns_hygiene": out})}

    assert "caa-missing" in finding_ids
    assert "dnssec-disabled" in finding_ids


def test_dns_hygiene_findings_indeterminate_on_resolver_error():
    out = analyze_dns_hygiene("example.com", resolver=resolver({}, status="error"))

    findings = {f.id: f for f in build_findings({"dns_hygiene": out})}

    assert findings["caa-missing"].confidence == "indeterminate"
