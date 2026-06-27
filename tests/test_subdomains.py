from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.subdomains import discover_subdomains


def crt(*name_values, common_name=""):
    return [{"name_value": nv, "common_name": common_name} for nv in name_values]


def test_discover_extracts_dedupes_and_strips_wildcards():
    entries = crt("www.example.com\n*.example.com", "api.example.com", "www.example.com")

    out = discover_subdomains("example.com", fetcher=lambda d, t: entries)

    assert out["status"] == "ok"
    assert out["subdomains"] == ["api.example.com", "www.example.com"]
    assert out["count"] == 2


def test_discover_excludes_apex_and_unrelated_domains():
    entries = crt("example.com\nfoo.example.com\nexample.com.evil.com\nother.org")

    out = discover_subdomains("example.com", fetcher=lambda d, t: entries)

    assert out["subdomains"] == ["foo.example.com"]


def test_discover_flags_sensitive_subdomains():
    entries = crt("www.example.com\ndev.example.com\napi.staging.example.com\nshop.example.com")

    out = discover_subdomains("example.com", fetcher=lambda d, t: entries)

    assert out["sensitive"] == ["api.staging.example.com", "dev.example.com"]


def test_discover_parses_certspotter_dns_names_shape():
    # CertSpotter (the fallback source) uses dns_names instead of name_value.
    entries = [{"dns_names": ["example.com", "vpn.example.com", "*.example.com"]}]

    out = discover_subdomains("example.com", fetcher=lambda d, t: entries)

    assert out["subdomains"] == ["vpn.example.com"]
    assert out["sensitive"] == ["vpn.example.com"]


def test_discover_includes_common_name():
    entries = [{"name_value": "", "common_name": "vpn.example.com"}]

    out = discover_subdomains("example.com", fetcher=lambda d, t: entries)

    assert out["subdomains"] == ["vpn.example.com"]
    assert out["sensitive"] == ["vpn.example.com"]


def test_discover_merges_passive_dns_hosts():
    out = discover_subdomains(
        "example.com",
        fetcher=lambda d, t: crt("www.example.com"),
        host_fetcher=lambda d, t: ["api.example.com", "www.example.com", "skip.other.org"],
    )

    assert out["subdomains"] == ["api.example.com", "www.example.com"]
    assert "passive DNS" in out["source"]


def test_discover_passive_dns_works_when_ct_fails():
    out = discover_subdomains(
        "example.com",
        fetcher=lambda d, t: None,
        host_fetcher=lambda d, t: ["vpn.example.com"],
    )

    assert out["status"] == "ok"
    assert out["subdomains"] == ["vpn.example.com"]


def test_discover_handles_empty_logs_as_ok():
    out = discover_subdomains("example.com", fetcher=lambda d, t: [])

    assert out["status"] == "ok"
    assert out["count"] == 0
    assert out["subdomains"] == []


def test_discover_handles_fetch_failure_as_error():
    out = discover_subdomains("example.com", fetcher=lambda d, t: None)

    assert out["status"] == "error"
    assert out["count"] == 0


def test_subdomain_findings_report_surface_and_sensitive():
    subs = {
        "status": "ok",
        "source": "crt.sh",
        "count": 3,
        "subdomains": ["dev.example.com", "shop.example.com", "www.example.com"],
        "sensitive": ["dev.example.com"],
    }

    findings = {f.id: f for f in build_findings({"subdomains": subs})}

    assert "subdomains-discovered" in findings
    assert findings["subdomains-discovered"].severity == "info"
    assert "sensitive-subdomains-exposed" in findings
    assert findings["sensitive-subdomains-exposed"].severity == "low"


def test_subdomain_findings_silent_on_error():
    findings = {f.id: f for f in build_findings({"subdomains": {"status": "error", "count": 0}})}

    assert "subdomains-discovered" not in findings
    assert "sensitive-subdomains-exposed" not in findings
