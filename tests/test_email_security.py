from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.email_security import analyze_email_security, parse_txt_records


def test_parse_txt_records_joins_split_segments():
    output = '"v=spf1 include:_spf.example.com " "-all"\n"other=value"\n'

    assert parse_txt_records(output) == ["v=spf1 include:_spf.example.com -all", "other=value"]


def test_parse_mx_records_preserves_null_mx():
    from sentineldeck.scanners.email_security import parse_mx_records

    assert parse_mx_records("0 .\n") == ["0 ."]


def test_analyze_email_security_detects_present_controls():
    dns_query = {
        ("example.com", "MX"): "10 mail.example.com.\n",
        ("example.com", "TXT"): '"v=spf1 mx -all"\n',
        ("_dmarc.example.com", "TXT"): '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"\n',
    }

    result = analyze_email_security("example.com", query=lambda name, record_type: dns_query[(name, record_type)])

    assert result["mx"]["present"] is True
    assert result["spf"]["present"] is True
    assert result["spf"]["policy"] == "-all"
    assert result["dmarc"]["present"] is True
    assert result["dmarc"]["policy"] == "reject"


def test_analyze_email_security_handles_missing_records():
    result = analyze_email_security("example.com", query=lambda name, record_type: "")

    assert result["mx"]["present"] is False
    assert result["spf"]["present"] is False
    assert result["dmarc"]["present"] is False


def test_build_findings_flags_missing_dmarc_and_weak_spf():
    checks = {
        "email_security": {
            "mx": {"present": True, "records": ["10 mail.example.com."]},
            "spf": {"present": True, "records": ["v=spf1 include:mail.example.com ~all"], "policy": "~all"},
            "dmarc": {"present": False, "records": [], "policy": None},
        }
    }

    findings = build_findings(checks)
    finding_ids = {finding.id for finding in findings}

    assert "dmarc-missing" in finding_ids
    assert "spf-weak-policy" in finding_ids
