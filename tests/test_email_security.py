import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.dns_lookup import parse_mx_records, parse_txt_records
from sentineldeck.scanners.email_security import (
    analyze_email_security,
    count_spf_lookups,
    dkim_key_bits,
    fetch_mta_sts_policy,
)


def _dkim_record(bits):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}"


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
    policy = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800"

    out = analyze_email_security("example.com", resolver=resolver, http_fetcher=lambda url: policy)

    assert out["mta_sts"]["present"] is True
    assert out["mta_sts"]["policy"] == {"fetched": True, "mode": "enforce", "valid": True}
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


def test_dkim_key_bits_decodes_the_key_size():
    assert dkim_key_bits(_dkim_record(2048)) == 2048
    assert dkim_key_bits("v=DKIM1; k=rsa; p=") is None


def test_dkim_weak_key_finding_flags_under_2048():
    email = {
        "mx": {"present": True}, "dmarc": {"policy": "none"},
        "dkim": {"present": True, "key_bits": 1024, "found_selectors": ["s1"]},
    }
    findings = {f.id: f for f in build_findings({"email_security": email})}

    assert "dkim-weak-key" in findings
    assert findings["dkim-weak-key"].severity == "low"


def test_strong_dkim_key_is_not_flagged():
    email = {"mx": {"present": True}, "dmarc": {}, "dkim": {"present": True, "key_bits": 2048}}

    assert "dkim-weak-key" not in {f.id for f in build_findings({"email_security": email})}


def test_fetch_mta_sts_policy_parses_and_validates():
    body = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800"

    assert fetch_mta_sts_policy("example.com", lambda url: body) == {
        "fetched": True, "mode": "enforce", "valid": True,
    }
    assert fetch_mta_sts_policy("example.com", lambda url: None) == {
        "fetched": False, "mode": None, "valid": False,
    }


def test_mta_sts_policy_invalid_and_not_enforced_findings():
    invalid = {"email_security": {"mx": {"present": True}, "dmarc": {},
               "mta_sts": {"present": True, "policy": {"fetched": False, "mode": None, "valid": False}}}}
    assert "mta-sts-policy-invalid" in {f.id for f in build_findings(invalid)}

    testing = {"email_security": {"mx": {"present": True}, "dmarc": {},
               "mta_sts": {"present": True, "policy": {"fetched": True, "mode": "testing", "valid": True}}}}
    assert "mta-sts-not-enforced" in {f.id for f in build_findings(testing)}


def test_email_findings_are_indeterminate_when_dns_errors():
    email = analyze_email_security("example.com", resolver=make_resolver({}, status="error"))

    findings = {finding.id: finding for finding in build_findings({"email_security": email})}

    assert findings["spf-missing"].confidence == "indeterminate"
    assert findings["dmarc-missing"].confidence == "indeterminate"
