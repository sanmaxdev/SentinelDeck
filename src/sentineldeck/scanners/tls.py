from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

OUTDATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_SIGNATURE_HASHES = {"md5", "sha1"}
MIN_RSA_BITS = 2048
MIN_EC_BITS = 256


def classify_verify_error(exc: ssl.SSLCertVerificationError) -> str:
    """Map an OpenSSL verification failure to a stable, human-meaningful reason."""
    code = getattr(exc, "verify_code", None)
    message = (getattr(exc, "verify_message", "") or str(exc)).lower()
    if code == 10 or "expired" in message:
        return "expired"
    if code in (18, 19) or "self-signed" in message or "self signed" in message:
        return "self-signed"
    if "hostname mismatch" in message or "doesn't match" in message or "ip address mismatch" in message:
        return "hostname-mismatch"
    return "untrusted"


def _common_name(name: x509.Name) -> str | None:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return values[0].value if values else None


def _organization(name: x509.Name) -> str | None:
    values = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return values[0].value if values else None


def _public_key_summary(cert: x509.Certificate) -> tuple[str | None, int | None]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.curve.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    return None, None


def _san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    return ext.value.get_values_for_type(x509.DNSName)


def hostname_matches(hostname: str, dns_names: list[str]) -> bool:
    hostname = hostname.lower().rstrip(".")
    for raw in dns_names:
        name = raw.lower().rstrip(".")
        if name == hostname:
            return True
        if name.startswith("*."):
            base = name[2:]
            if "." in hostname and hostname.split(".", 1)[1] == base:
                return True
    return False


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def summarize_certificate(
    cert: x509.Certificate, hostname: str, now: datetime | None = None
) -> dict[str, Any]:
    """Extract the security-relevant fields from a presented certificate.

    Works on any certificate the server presents, including expired,
    self-signed, or hostname-mismatched ones, because it reads the leaf
    directly rather than relying on a validated chain.
    """
    now = now or datetime.now(timezone.utc)
    # Prefer cryptography's timezone-aware accessors (42+); fall back to the
    # legacy naive properties only on older versions, avoiding the deprecation
    # warning that otherwise leaks into scan output.
    not_after = getattr(cert, "not_valid_after_utc", None) or _aware(cert.not_valid_after)
    not_before = getattr(cert, "not_valid_before_utc", None) or _aware(cert.not_valid_before)
    key_type, key_bits = _public_key_summary(cert)
    san = _san_dns_names(cert)
    try:
        sig_hash = cert.signature_hash_algorithm.name.lower() if cert.signature_hash_algorithm else None
    except Exception:  # noqa: BLE001 - exotic algorithms should not crash a scan
        sig_hash = None

    return {
        "subject_cn": _common_name(cert.subject),
        "issuer_cn": _common_name(cert.issuer),
        "issuer_org": _organization(cert.issuer),
        "san": san,
        "not_before": not_before.isoformat(),
        "expires_at": not_after.isoformat(),
        "days_remaining": (not_after - now).days,
        "expired": not_after <= now,
        "not_yet_valid": not_before > now,
        "self_signed": cert.subject == cert.issuer,
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_algorithm": sig_hash,
        "hostname_match": hostname_matches(hostname, san) if san else None,
    }


def _verify_chain(domain: str, timeout: int) -> tuple[bool, str | None, str | None]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as wrapped:
                return True, None, wrapped.version()
    except ssl.SSLCertVerificationError as exc:
        return False, classify_verify_error(exc), None
    except ssl.SSLError:
        return False, "untrusted", None
    except (socket.gaierror, TimeoutError, OSError):
        return False, "unreachable", None


def _fetch_leaf(domain: str, timeout: int) -> tuple[bytes | None, str | None]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as wrapped:
                return wrapped.getpeercert(binary_form=True), wrapped.version()
    except OSError:
        return None, None


def inspect_tls(domain: str, timeout: int = 10) -> dict[str, Any]:
    verified, reason, protocol = _verify_chain(domain, timeout)
    der, der_protocol = _fetch_leaf(domain, timeout)

    if not verified and der is None:
        return {"reachable": False, "valid": False, "reason": reason or "unreachable",
                "error": "could not establish a TLS connection on port 443"}

    negotiated = protocol or der_protocol
    result: dict[str, Any] = {
        "reachable": True,
        "valid": verified,
        "verified": verified,
        "reason": reason,
        "protocol": negotiated,
        "protocol_outdated": negotiated in OUTDATED_PROTOCOLS if negotiated else False,
    }
    if der is not None:
        try:
            result.update(summarize_certificate(x509.load_der_x509_certificate(der), domain))
        except Exception as exc:  # noqa: BLE001 - malformed cert should not crash a scan
            result["certificate_error"] = str(exc)
    return result
