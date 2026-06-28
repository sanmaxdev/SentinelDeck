from sentineldeck.scanners.web_content import (
    analyze_web_content,
    detect_waf,
    extract_links,
    extract_social_tags,
    fetch_robots,
)


def test_extract_links_splits_internal_and_external():
    body = (
        '<a href="/about">a</a> <a href="https://example.com/x">b</a> '
        '<a href="https://cdn.other.com/y">c</a> <a href="mailto:x@example.com">m</a>'
    )
    out = extract_links(body, "example.com")

    assert out["internal"] == 2
    assert out["external"] == 1
    assert out["external_domains"] == ["cdn.other.com"]


def test_extract_social_tags_handles_attribute_order():
    body = (
        '<meta property="og:title" content="Hello">'
        '<meta content="A site" name="twitter:description">'
    )
    tags = extract_social_tags(body)

    assert tags["og:title"] == "Hello"
    assert tags["twitter:description"] == "A site"


def test_detect_waf_from_headers():
    assert "Cloudflare" in detect_waf({"Server": "cloudflare", "CF-RAY": "abc"})
    assert "Sucuri" in detect_waf({"X-Sucuri-ID": "12"})
    assert detect_waf({"Server": "nginx"}) == []


def test_fetch_robots_parses_sitemaps_and_disallows():
    text = "User-agent: *\nDisallow: /admin\nDisallow: /private\nSitemap: https://e.com/sitemap.xml"
    out = fetch_robots("e.com", fetcher=lambda url, timeout=10: text)

    assert out["present"] is True
    assert out["disallow_count"] == 2
    assert out["sitemaps"] == ["https://e.com/sitemap.xml"]


def test_analyze_web_content_combines_sources():
    page = {"reachable": True, "headers": {"server": "cloudflare"},
            "body": '<a href="/x">x</a><meta property="og:title" content="T">'}
    out = analyze_web_content("e.com", page, fetcher=lambda url, timeout=10: None)

    assert out["status"] == "ok"
    assert out["waf"] == ["Cloudflare"]
    assert out["links"]["internal"] == 1
    assert out["social"]["og:title"] == "T"
    assert out["robots"]["present"] is False
