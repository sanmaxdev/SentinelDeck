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


def test_single_nameserver_flagged_but_two_are_fine():
    one = analyze_dns_hygiene("example.com", resolver=resolver({"NS": ["ns1.example.com."]}))
    assert "single-nameserver" in {f.id for f in build_findings({"dns_hygiene": one})}

    two = analyze_dns_hygiene("example.com", resolver=resolver({"NS": ["ns1.x.", "ns2.x."]}))
    assert "single-nameserver" not in {f.id for f in build_findings({"dns_hygiene": two})}


def test_no_ipv6_flagged_unless_aaaa_present():
    none = analyze_dns_hygiene("example.com", resolver=resolver({}))
    assert "no-ipv6" in {f.id for f in build_findings({"dns_hygiene": none})}

    has = analyze_dns_hygiene("example.com", resolver=resolver({"AAAA": ["2001:db8::1"]}))
    assert "no-ipv6" not in {f.id for f in build_findings({"dns_hygiene": has})}


def test_dane_missing_only_when_dnssec_is_enabled():
    signed = analyze_dns_hygiene("example.com", resolver=resolver({"DNSKEY": ["256 3 13 AAAA"]}))
    assert "dane-missing" in {f.id for f in build_findings({"dns_hygiene": signed})}

    unsigned = analyze_dns_hygiene("example.com", resolver=resolver({}))
    assert "dane-missing" not in {f.id for f in build_findings({"dns_hygiene": unsigned})}


def test_dns_hygiene_findings_indeterminate_on_resolver_error():
    out = analyze_dns_hygiene("example.com", resolver=resolver({}, status="error"))

    findings = {f.id: f for f in build_findings({"dns_hygiene": out})}

    assert findings["caa-missing"].confidence == "indeterminate"
