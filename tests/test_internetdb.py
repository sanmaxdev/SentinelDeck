from sentineldeck.scanners.internetdb import analyze_internetdb


def test_internetdb_parses_exposure():
    data = {
        "ip": "1.1.1.1",
        "ports": [443, 80],
        "vulns": ["CVE-2021-1234"],
        "cpes": ["cpe:/a:x"],
        "tags": ["cdn"],
        "hostnames": ["one.one.one.one"],
    }
    out = analyze_internetdb("1.1.1.1", fetcher=lambda ip, timeout=10: data)
    assert out["status"] == "ok"
    assert out["ports"] == [80, 443]
    assert out["vulns"] == ["CVE-2021-1234"]
    assert out["tags"] == ["cdn"]


def test_internetdb_404_is_clean():
    out = analyze_internetdb("1.2.3.4", fetcher=lambda ip, timeout=10: {})
    assert out["status"] == "ok"
    assert out["ports"] == []
    assert out["vulns"] == []


def test_internetdb_error_on_none():
    out = analyze_internetdb("1.2.3.4", fetcher=lambda ip, timeout=10: None)
    assert out["status"] == "error"
