from sentineldeck.scanners.asn import analyze_asn


def _fetcher(call, resource, timeout=12):
    if call == "network-info":
        return {"asns": ["13335"], "prefix": "1.1.1.0/24"}
    if call == "as-overview":
        return {"holder": "CLOUDFLARENET, US"}
    if call == "announced-prefixes":
        return {"prefixes": [
            {"prefix": "1.1.1.0/24"},
            {"prefix": "104.16.0.0/13"},
            {"prefix": "2606:4700::/32"},
        ]}
    return None


def test_analyze_asn_maps_footprint():
    out = analyze_asn("1.1.1.1", fetcher=_fetcher)
    assert out["status"] == "ok"
    assert out["asn"] == "13335"
    assert out["holder"] == "CLOUDFLARENET, US"
    assert out["prefix"] == "1.1.1.0/24"
    assert "104.16.0.0/13" in out["prefixes"]
    assert out["prefix_count"] == 3
    assert out["ipv4_prefixes"] == 2
    assert out["ipv6_prefixes"] == 1
    assert out["ipv4_addresses"] == 256 + 524288  # /24 + /13


def test_analyze_asn_no_asn():
    def fetch(call, resource, timeout=12):
        return {"asns": [], "prefix": None} if call == "network-info" else {}

    out = analyze_asn("192.0.2.1", fetcher=fetch)
    assert out["status"] == "ok"
    assert out["asn"] is None
    assert out["prefix_count"] == 0


def test_analyze_asn_error():
    out = analyze_asn("1.1.1.1", fetcher=lambda call, resource, timeout=12: None)
    assert out["status"] == "error"
