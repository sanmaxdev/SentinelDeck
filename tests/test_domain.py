import pytest

from sentineldeck.scanners.domain import normalize_domain


def test_normalize_domain_strips_scheme_and_path():
    assert normalize_domain("https://Example.COM/login") == "example.com"


def test_normalize_domain_rejects_bad_domain():
    with pytest.raises(ValueError):
        normalize_domain("not a domain")
