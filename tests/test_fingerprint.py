from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.fingerprint import (
    analyze_technologies,
    detect_vulnerable_js,
    fingerprint,
)


def test_fingerprint_detects_from_headers_and_html():
    page = {
        "headers": {"server": "nginx/1.25.3", "x-powered-by": "PHP/8.1.2"},
        "body": '<html><meta name="generator" content="WordPress 6.4.1"><script src="/wp-includes/x.js">',
    }

    detected = {d["name"]: d for d in fingerprint(page)}

    assert detected["nginx"]["version"] == "1.25.3"
    assert detected["PHP"]["version"] == "8.1.2"
    assert detected["WordPress"]["version"] == "6.4.1"
    assert detected["WordPress"]["category"] == "CMS"


def test_detect_vulnerable_js_flags_old_jquery_but_not_new():
    old = '<script src="https://cdn.example.com/jquery-3.4.1.min.js"></script>'
    findings = detect_vulnerable_js(old)
    assert findings and findings[0]["library"] == "jquery"
    assert findings[0]["severity"] == "medium"

    new = '<script src="/assets/jquery-3.6.0.min.js"></script>'
    assert detect_vulnerable_js(new) == []


def test_analyze_technologies_uses_injected_fetcher():
    page = {"reachable": True, "status": 200, "headers": {"server": "cloudflare"},
            "body": '<script src="/lodash-4.17.10.js"></script>'}

    out = analyze_technologies("example.com", fetcher=lambda d, t: page)

    assert out["status"] == "ok"
    assert any(d["name"] == "Cloudflare" for d in out["detected"])
    assert out["vulnerable_js"][0]["library"] == "lodash"
    assert out["vulnerable_js"][0]["severity"] == "high"


def test_analyze_technologies_unreachable_is_error():
    out = analyze_technologies("example.com", fetcher=lambda d, t: {"reachable": False})

    assert out["status"] == "error"
    assert out["detected"] == [] and out["vulnerable_js"] == []


def test_vulnerable_js_becomes_a_scored_finding():
    checks = {"technologies": {"status": "ok", "detected": [],
              "vulnerable_js": [{"library": "lodash", "version": "4.17.10",
                                 "advisory": "CVE-2021-23337", "severity": "high"}]}}

    findings = {f.id: f for f in build_findings(checks)}

    assert "vulnerable-js-library:lodash" in findings
    assert findings["vulnerable-js-library:lodash"].severity == "high"
