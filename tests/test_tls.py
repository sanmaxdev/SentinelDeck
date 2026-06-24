from datetime import datetime, timezone

from sentineldeck.scanners.tls import _flatten_name, parse_cert

NOW = datetime(2026, 6, 24, tzinfo=timezone.utc)


def test_flatten_name_collapses_rdn_tuples():
    name = (
        (("countryName", "US"),),
        (("organizationName", "Example Inc"),),
        (("commonName", "example.com"),),
    )

    assert _flatten_name(name) == {
        "countryName": "US",
        "organizationName": "Example Inc",
        "commonName": "example.com",
    }


def test_flatten_name_handles_empty():
    assert _flatten_name(None) == {}
    assert _flatten_name(()) == {}


def test_parse_cert_reports_days_remaining_for_valid_cert():
    cert = {
        "notAfter": "Sep 22 12:00:00 2026 GMT",
        "issuer": ((("commonName", "Trusted CA"),),),
        "subject": ((("commonName", "example.com"),),),
    }

    result = parse_cert(cert, now=NOW)

    assert result["valid"] is True
    assert result["expired"] is False
    assert result["days_remaining"] == 90
    assert result["issuer"] == {"commonName": "Trusted CA"}
    assert result["subject"] == {"commonName": "example.com"}
    assert result["expires_at"] == "2026-09-22T12:00:00+00:00"


def test_parse_cert_flags_expired_certificate():
    cert = {"notAfter": "Jan 01 12:00:00 2026 GMT"}

    result = parse_cert(cert, now=NOW)

    assert result["expired"] is True
    assert result["days_remaining"] < 0


def test_parse_cert_without_not_after_is_inconclusive():
    result = parse_cert({}, now=NOW)

    assert result["valid"] is True
    assert result["expires_at"] is None
    assert result["days_remaining"] is None
    assert result["expired"] is False
