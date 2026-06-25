from sentineldeck.models import Finding
from sentineldeck.remediation import remediation_for
from sentineldeck.risk.scoring import build_findings, score_findings
from sentineldeck.scanners.takeover import detect_takeovers


def cname_resolver(mapping):
    # mapping: host -> cname target (or None for no CNAME)
    def resolver(name, record_type):
        if record_type == "CNAME" and mapping.get(name):
            return [mapping[name] + "."], "ok"
        return [], "ok"

    return resolver


def test_detect_flags_github_pages_via_fingerprint():
    out = detect_takeovers(
        ["blog.example.com"],
        resolver=cname_resolver({"blog.example.com": "myorg.github.io"}),
        body_fetcher=lambda host, t: "<html>There isn't a GitHub Pages site here.</html>",
    )

    assert len(out["candidates"]) == 1
    candidate = out["candidates"][0]
    assert candidate["service"] == "GitHub Pages"
    assert candidate["subdomain"] == "blog.example.com"
    assert candidate["signal"] == "http-fingerprint"


def test_detect_ignores_live_service_without_fingerprint():
    out = detect_takeovers(
        ["blog.example.com"],
        resolver=cname_resolver({"blog.example.com": "myorg.github.io"}),
        body_fetcher=lambda host, t: "<html>my real blog content</html>",
    )

    assert out["candidates"] == []


def test_detect_ignores_cname_to_unknown_service():
    out = detect_takeovers(
        ["x.example.com"],
        resolver=cname_resolver({"x.example.com": "internal.corp.local"}),
        body_fetcher=lambda host, t: "anything at all",
    )

    assert out["candidates"] == []


def test_detect_ignores_plain_a_record_host():
    out = detect_takeovers(
        ["www.example.com"],
        resolver=cname_resolver({}),  # no CNAME
        body_fetcher=lambda host, t: None,
    )

    assert out["candidates"] == []


def test_detect_respects_limit():
    seen = []

    def resolver(name, record_type):
        seen.append(name)
        return [], "ok"

    detect_takeovers(
        [f"h{i}.example.com" for i in range(100)],
        resolver=resolver,
        body_fetcher=lambda host, t: None,
        limit=10,
    )

    assert len(seen) == 10


def test_takeover_finding_is_high_and_scored():
    checks = {
        "takeover": {
            "status": "ok",
            "candidates": [
                {"subdomain": "blog.example.com", "cname": "x.github.io", "service": "GitHub Pages"}
            ],
        }
    }

    findings = {f.id: f for f in build_findings(checks)}
    fid = "subdomain-takeover:blog.example.com"

    assert fid in findings
    assert findings[fid].severity == "high"
    assert score_findings(list(findings.values())) >= 25


def test_takeover_has_remediation():
    finding = Finding(
        id="subdomain-takeover:blog.example.com",
        title="t",
        severity="high",
        description="d",
        recommendation="r",
        evidence={"subdomain": "blog.example.com", "cname": "x.github.io", "service": "GitHub Pages"},
    )

    fix = remediation_for(finding, "example.com")

    assert fix is not None
    assert "blog.example.com" in fix["snippet"]
    assert "x.github.io" in fix["snippet"]
