from sentineldeck.scanners.ip_rdap import analyze_ip_rdap

SAMPLE = {
    "handle": "NET-157-240-0-0-1",
    "name": "THEFACEBOOK",
    "startAddress": "157.240.0.0",
    "endAddress": "157.240.255.255",
    "cidr0_cidrs": [{"v4prefix": "157.240.0.0", "length": 16}],
    "country": "US",
    "events": [{"eventAction": "registration", "eventDate": "2015-05-14T00:00:00Z"}],
    "entities": [
        {
            "roles": ["registrant"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Facebook, Inc."]]],
            "entities": [
                {
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "abuse@facebook.com"]]],
                }
            ],
        }
    ],
}


def test_analyze_ip_rdap_parses_allocation():
    out = analyze_ip_rdap("157.240.15.35", fetcher=lambda ip, timeout=10: SAMPLE)
    assert out["status"] == "ok"
    assert out["name"] == "THEFACEBOOK"
    assert out["cidr"] == "157.240.0.0/16"
    assert out["country"] == "US"
    assert out["org"] == "Facebook, Inc."
    assert out["abuse_email"] == "abuse@facebook.com"
    assert out["registered"] == "2015-05-14"


def test_analyze_ip_rdap_error_on_no_data():
    assert analyze_ip_rdap("1.2.3.4", fetcher=lambda ip, timeout=10: None) == {"status": "error"}


def test_analyze_ip_rdap_falls_back_to_range():
    data = {"startAddress": "1.0.0.0", "endAddress": "1.0.0.255", "entities": []}
    out = analyze_ip_rdap("1.0.0.1", fetcher=lambda ip, timeout=10: data)
    assert out["cidr"] == "1.0.0.0 - 1.0.0.255"
    assert out["abuse_email"] is None
    assert out["org"] is None
