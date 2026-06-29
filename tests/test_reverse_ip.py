from sentineldeck.scanners.reverse_ip import reverse_ip


def test_reverse_ip_parses_domains():
    text = "example.com\nwww.example.com\nfoo.example.org\n"
    out = reverse_ip("1.2.3.4", fetcher=lambda ip, timeout=12: text)
    assert out["status"] == "ok"
    assert out["count"] == 3
    assert "example.com" in out["domains"]
    assert out["truncated"] is False


def test_reverse_ip_handles_no_records():
    out = reverse_ip("1.2.3.4", fetcher=lambda ip, timeout=12: "No records found")
    assert out["status"] == "ok"
    assert out["count"] == 0


def test_reverse_ip_handles_rate_limit():
    out = reverse_ip("1.2.3.4", fetcher=lambda ip, timeout=12: "API count exceeded")
    assert out["count"] == 0


def test_reverse_ip_error_on_none():
    out = reverse_ip("1.2.3.4", fetcher=lambda ip, timeout=12: None)
    assert out["status"] == "error"
    assert out["domains"] == []
