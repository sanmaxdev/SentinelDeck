from sentineldeck.models import Finding
from sentineldeck.remediation import attach_remediations, remediation_for
from sentineldeck.risk.scoring import build_findings, path_to_grade, quick_wins


def f(id, severity="medium", evidence=None, confidence="confirmed"):
    return Finding(
        id=id,
        title=id,
        severity=severity,
        description="d",
        recommendation="r",
        evidence=evidence or {},
        confidence=confidence,
    )


def test_remediation_hsts_snippet():
    fix = remediation_for(f("missing-strict-transport-security"), "example.com")

    assert fix["kind"] == "http"
    assert "Strict-Transport-Security" in fix["snippet"]
    assert "RFC 6797" in fix["references"]


def test_remediation_dmarc_uses_target():
    fix = remediation_for(f("dmarc-missing"), "acme.test")

    assert fix["kind"] == "dns"
    assert "_dmarc.acme.test" in fix["snippet"]
    assert "v=DMARC1" in fix["snippet"]


def test_remediation_caa_uses_target():
    fix = remediation_for(f("caa-missing", severity="low"), "acme.test")

    assert 'acme.test.    IN  CAA  0 issue "letsencrypt.org"' in fix["snippet"]


def test_remediation_spf_weak_hardens_the_actual_record():
    finding = f("spf-weak-policy", severity="low", evidence={"records": ["v=spf1 include:x ~all"]})

    fix = remediation_for(finding, "example.com")

    assert "v=spf1 include:x ~all" in fix["snippet"]  # the "from"
    assert "v=spf1 include:x -all" in fix["snippet"]  # the hardened "to"


def test_remediation_generic_header_fallback():
    finding = f("missing-x-content-type-options", evidence={"checked_header": "x-content-type-options"})

    fix = remediation_for(finding, "example.com")

    assert fix is not None
    assert "nosniff" in fix["snippet"]


def test_remediation_for_email_hardening_records():
    for fid, needle in [
        ("mta-sts-missing", "_mta-sts.example.com"),
        ("tls-rpt-missing", "_smtp._tls.example.com"),
        ("bimi-missing", "default._bimi.example.com"),
    ]:
        fix = remediation_for(f(fid, "info"), "example.com")
        assert fix is not None
        assert needle in fix["snippet"]


def test_remediation_for_phase1_findings():
    for fid, needle in [
        ("single-nameserver", "IN  NS"),
        ("no-ipv6", "IN  AAAA"),
        ("dane-missing", "IN  TLSA"),
        ("dkim-weak-key", "genrsa"),
        ("mta-sts-policy-invalid", "mta-sts"),
        ("mta-sts-not-enforced", "mta-sts"),
    ]:
        fix = remediation_for(f(fid, "low"), "example.com")
        assert fix is not None, fid
        assert needle in fix["snippet"], fid


def test_remediation_for_phase2_header_findings():
    for fid, needle in [
        ("cors-credentials-wildcard", "Access-Control-Allow-Origin"),
        ("cors-open", "Access-Control-Allow-Origin"),
        ("referrer-policy-unsafe", "Referrer-Policy"),
        ("hsts-not-preloadable", "preload"),
        ("cookie-no-samesite", "SameSite"),
        ("no-coop", "Cross-Origin-Opener-Policy"),
    ]:
        fix = remediation_for(f(fid, "low"), "example.com")
        assert fix is not None, fid
        assert needle in fix["snippet"], fid


def test_remediation_for_phase3_findings():
    js = remediation_for(
        f("vulnerable-js-library:jquery", "medium", evidence={"library": "jquery", "advisory": "CVE-x"}),
        "example.com",
    )
    assert js is not None and "jquery" in js["snippet"]

    bucket = remediation_for(
        f("cloud-bucket-public:leaky", "high", evidence={"provider": "s3", "name": "leaky"}),
        "example.com",
    )
    assert bucket is not None and "leaky" in bucket["snippet"]


def test_redirect_downgrade_finding_and_fix():
    findings = {f.id: f for f in build_findings({"redirect_chain": {"downgrade": True, "hops": []}})}
    assert "redirect-downgrades-to-http" in findings
    fix = remediation_for(findings["redirect-downgrades-to-http"], "example.com")
    assert fix is not None and "https://example.com" in fix["snippet"]


def test_remediation_unknown_finding_returns_none():
    assert remediation_for(f("domain-newly-registered", severity="low"), "example.com") is None


def test_attach_remediations_populates_in_place():
    findings = [f("missing-content-security-policy"), f("domain-newly-registered", severity="low")]

    attach_remediations(findings, "example.com")

    assert findings[0].remediation is not None
    assert "Content-Security-Policy" in findings[0].remediation["snippet"]
    assert findings[1].remediation is None


def test_quick_wins_orders_by_impact():
    findings = [f("a", "low"), f("b", "medium"), f("c", "high")]

    assert [x.id for x in quick_wins(findings)] == ["c", "b", "a"]


def test_quick_wins_excludes_indeterminate_and_zero_point():
    findings = [f("a", "medium"), f("b", "info"), f("c", "medium", confidence="indeterminate")]

    assert [x.id for x in quick_wins(findings)] == ["a"]


def test_path_to_grade_returns_minimal_set():
    # medium(12) x3 + low(5) = 41 -> grade C; fixing the two mediums reaches 17 (< 20 -> A).
    findings = [f("m1", "medium"), f("m2", "medium"), f("m3", "medium"), f("l1", "low")]

    plan = path_to_grade(findings, "A")

    assert len(plan) == 2
    assert all(p.severity == "medium" for p in plan)


def test_path_to_grade_empty_when_already_met():
    assert path_to_grade([f("l1", "low")], "A") == []
