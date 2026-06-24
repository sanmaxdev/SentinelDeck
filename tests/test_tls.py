from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sentineldeck.scanners.tls import classify_verify_error, hostname_matches, summarize_certificate

NOW = datetime(2026, 6, 24, tzinfo=timezone.utc)


def make_cert(cn="example.com", sans=("example.com",), days_valid=90, key_bits=2048, hash_alg=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW + timedelta(days=days_valid - 365))
        .not_valid_after(NOW + timedelta(days=days_valid))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    return builder.sign(key, hash_alg or hashes.SHA256())


class _FakeVerifyError:
    def __init__(self, code, message):
        self.verify_code = code
        self.verify_message = message

    def __str__(self):
        return self.verify_message


def test_summarize_certificate_extracts_core_fields():
    summary = summarize_certificate(make_cert(), "example.com", now=NOW)

    assert summary["subject_cn"] == "example.com"
    assert summary["san"] == ["example.com"]
    assert summary["days_remaining"] == 90
    assert summary["expired"] is False
    assert summary["self_signed"] is True
    assert summary["key_type"] == "RSA"
    assert summary["key_bits"] == 2048
    assert summary["signature_algorithm"] == "sha256"
    assert summary["hostname_match"] is True


def test_summarize_certificate_flags_expiry_and_weak_key():
    summary = summarize_certificate(make_cert(days_valid=-5, key_bits=1024), "example.com", now=NOW)

    assert summary["expired"] is True
    assert summary["key_bits"] == 1024


def test_summarize_certificate_detects_hostname_mismatch():
    summary = summarize_certificate(make_cert(sans=("other.com",)), "example.com", now=NOW)

    assert summary["hostname_match"] is False


def test_hostname_matches_supports_wildcards():
    assert hostname_matches("www.example.com", ["*.example.com"]) is True
    assert hostname_matches("example.com", ["*.example.com"]) is False
    assert hostname_matches("example.com", ["example.com"]) is True


def test_classify_verify_error_expired():
    assert classify_verify_error(_FakeVerifyError(10, "certificate has expired")) == "expired"


def test_classify_verify_error_self_signed():
    assert classify_verify_error(_FakeVerifyError(18, "self-signed certificate")) == "self-signed"


def test_classify_verify_error_hostname_mismatch():
    err = _FakeVerifyError(None, "Hostname mismatch, certificate is not valid for 'x'")
    assert classify_verify_error(err) == "hostname-mismatch"


def test_classify_verify_error_defaults_to_untrusted():
    assert classify_verify_error(_FakeVerifyError(20, "unable to get local issuer certificate")) == "untrusted"
