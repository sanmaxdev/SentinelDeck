import pytest

from sentineldeck.scanners.target import classify_target, is_private_ip


def test_classify_plain_domain():
    assert classify_target("Example.COM") == ("domain", "example.com")


def test_classify_ipv4():
    assert classify_target("157.240.15.35") == ("ip", "157.240.15.35")


def test_classify_url_with_port_and_path():
    assert classify_target("https://1.1.1.1:8443/path") == ("ip", "1.1.1.1")


def test_classify_ipv6_bracketed():
    assert classify_target("[2606:4700:4700::1111]") == ("ip", "2606:4700:4700::1111")


def test_classify_domain_with_scheme_and_port():
    assert classify_target("http://example.com:8080/login") == ("domain", "example.com")


def test_classify_rejects_empty():
    with pytest.raises(ValueError):
        classify_target("   ")


def test_classify_rejects_garbage():
    with pytest.raises(ValueError):
        classify_target("not a domain")


def test_is_private_ip():
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("127.0.0.1")
    assert is_private_ip("10.0.0.5")
    assert not is_private_ip("8.8.8.8")
    assert not is_private_ip("not-an-ip")
