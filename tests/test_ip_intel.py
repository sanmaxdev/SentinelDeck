from sentineldeck.scanners.ip_intel import analyze_ip_intel


def test_analyze_ip_intel_maps_fields():
    data = {
        "status": "success", "query": "1.2.3.4", "city": "Berlin", "regionName": "BE",
        "country": "Germany", "countryCode": "DE", "isp": "Acme", "org": "Acme Hosting",
        "as": "AS64500 Acme",
    }
    out = analyze_ip_intel("1.2.3.4", fetcher=lambda ip, timeout=10: data)

    assert out["status"] == "ok"
    assert out["city"] == "Berlin"
    assert out["country"] == "Germany"
    assert out["asn"] == "AS64500 Acme"


def test_analyze_ip_intel_handles_no_ip():
    assert analyze_ip_intel(None)["status"] == "error"


def test_analyze_ip_intel_handles_failure():
    out = analyze_ip_intel("1.2.3.4", fetcher=lambda ip, timeout=10: {"status": "fail"})
    assert out["status"] == "error"
