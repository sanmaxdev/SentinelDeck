from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.typosquat import detect_typosquats, generate_permutations


def test_generate_permutations_creates_variants():
    perms = generate_permutations("example.com")

    assert "exampl.com" in perms       # omission
    assert "example.net" in perms      # TLD swap
    assert "exampl3.com" in perms      # homoglyph e -> 3
    assert "example.com" not in perms  # excludes the original


def test_generate_permutations_needs_a_tld():
    assert generate_permutations("localhost") == []


def test_detect_typosquats_reports_resolving_variants():
    def resolver(name, record_type):
        return (["1.2.3.4"], "ok") if name == "example.net" else ([], "ok")

    out = detect_typosquats("example.com", resolver=resolver, limit=200)

    assert out["status"] == "ok"
    assert any(r["domain"] == "example.net" for r in out["registered"])


def test_lookalike_domains_finding():
    checks = {"typosquatting": {"status": "ok", "registered": [{"domain": "examp1e.com"}]}}
    findings = {f.id: f for f in build_findings(checks)}

    assert "lookalike-domains" in findings
    assert findings["lookalike-domains"].severity == "low"
