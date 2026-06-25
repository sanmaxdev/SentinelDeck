from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.dns_lookup import parse_mx_records, parse_txt_records
from sentineldeck.scanners.email_security import analyze_email_security, count_spf_lookups


def make_resolver(records_by_key, status="ok"):
    def resolver(name, record_type):
        return list(records_by_key.get((name, record_type), [])), status

    return resolver


def test_parse_txt_records_joins_split_segments():
    output = '"v=spf1 include:_spf.example.com " "-all"\n"other=value"\n'

    assert parse_txt_records(output) == ["v=spf1 include:_spf.example.com -all", "other=value"]


def test_parse_mx_records_preserves_null_mx():
    assert parse_mx_records("0 .\n") == ["0 ."]


def test_count_spf_lookups_counts_dns_mechanisms():
    record = "v=spf1 include:a.com include:b.com a mx ip4:1.2.3.4 ~all"

    assert count_spf_lookups(record) == 4


def test_analyze_email_security_detects_present_controls():
    resolver = make_resolver({
        ("example.com", "MX"): ["10 mail.example.com."],
        ("example.com", "TXT"): ["v=spf1 mx -all"],
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"],
    })

    result = analyze_email_security("example.com", resolver=resolver)

    assert result["mx"]["present"] is True
    assert result["spf"]["present"] is True
    assert result["spf"]["policy"] == "-all"
    assert result["dmarc"]["present"] is True
    assert result["dmarc"]["policy"] == "reject"
    assert result["dmarc"]["rua"] == "mailto:dmarc@example.com"


def test_analyze_email_security_handles_missing_records():
    result = analyze_email_security("example.com", resolver=make_resolver({}))

    assert result["mx"]["present"] is False
    assert result["spf"]["present"] is False
    assert result["dmarc"]["present"] is False
    assert result["dkim"]["present"] is False


def test_analyze_email_security_flags_multiple_spf_records():
    resolver = make_resolver({
        ("example.com", "TXT"): ["v=spf1 include:a.com ~all", "v=spf1 include:b.com -all"],
    })

    result = analyze_email_security("example.com", resolver=resolver)

    assert result["spf"]["multiple"] is True


def test_build_findings_flags_missing_dmarc_and_weak_spf():
    checks = {
        "email_security": {
            "mx": {"present": True, "records": ["10 mail.example.com."]},
            "spf": {"present": True, "records": ["v=spf1 include:mail.example.com ~all"], "policy": "~all"},
            "dmarc": {"present": False, "records": [], "policy": None},
        }
    }

    finding_ids = {finding.id for finding in build_findings(checks)}

    assert "dmarc-missing" in finding_ids
    assert "spf-weak-policy" in finding_ids


def test_analyze_detects_mta_sts_tls_rpt_and_bimi():
    resolver = make_resolver({
        ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=20260101"],
        ("_smtp._tls.example.com", "TXT"): ["v=TLSRPTv1; rua=mailto:t@example.com"],
        ("default._bimi.example.com", "TXT"): ["v=BIMI1; l=https://example.com/logo.svg"],
    })

    out = analyze_email_security("example.com", resolver=resolver)

    assert out["mta_sts"]["present"] is True
    assert out["tls_rpt"]["present"] is True
    assert out["bimi"]["present"] is True


def test_findings_flag_missing_email_hardening_when_mx_present():
    checks = {"email_security": {
        "mx": {"present": True, "records": ["10 mail.example.com."]},
        "spf": {"present": True, "records": ["v=spf1 -all"], "policy": "-all"},
        "dmarc": {"present": True, "records": ["v=DMARC1; p=reject"], "policy": "reject"},
        "mta_sts": {"present": False, "status": "ok"},
        "tls_rpt": {"present": False, "status": "ok"},
        "bimi": {"present": False, "status": "ok"},
    }}

    ids = {f.id for f in build_findings(checks)}

    assert {"mta-sts-missing", "tls-rpt-missing", "bimi-missing"} <= ids


def test_email_hardening_not_flagged_without_mx():
    checks = {"email_security": {
        "mx": {"present": False, "records": []},
        "dmarc": {"present": False, "policy": None},
        "mta_sts": {"present": False, "status": "ok"},
        "tls_rpt": {"present": False, "status": "ok"},
        "bimi": {"present": False, "status": "ok"},
    }}

    ids = {f.id for f in build_findings(checks)}

    assert "mta-sts-missing" not in ids
    assert "tls-rpt-missing" not in ids


def test_bimi_not_flagged_without_dmarc_enforcement():
    checks = {"email_security": {
        "mx": {"present": True, "records": ["10 m.example.com."]},
        "dmarc": {"present": True, "policy": "none"},
        "mta_sts": {"present": True},
        "tls_rpt": {"present": True},
        "bimi": {"present": False, "status": "ok"},
    }}

    assert "bimi-missing" not in {f.id for f in build_findings(checks)}


def test_email_findings_are_indeterminate_when_dns_errors():
    email = analyze_email_security("example.com", resolver=make_resolver({}, status="error"))

    findings = {finding.id: finding for finding in build_findings({"email_security": email})}

    assert findings["spf-missing"].confidence == "indeterminate"
    assert findings["dmarc-missing"].confidence == "indeterminate"
