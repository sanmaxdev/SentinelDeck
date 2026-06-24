from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

CERT_TIME_FORMAT = "%b %d %H:%M:%S %Y %Z"
OUTDATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _flatten_name(name: Any) -> dict[str, str]:
    """Flatten an x509 name (tuple of RDNs) into a simple ``{field: value}`` dict."""
    flattened: dict[str, str] = {}
    for rdn in name or ():
        for entry in rdn:
            if isinstance(entry, (tuple, list)) and len(entry) == 2:
                key, value = entry
                flattened[str(key)] = str(value)
    return flattened


def parse_cert(cert: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Turn a raw ``getpeercert`` mapping into a structured, JSON-friendly summary."""
    now = now or datetime.now(timezone.utc)
    not_after = cert.get("notAfter")
    expires_at = None
    days_remaining = None
    expired = False
    if not_after:
        expires = datetime.strptime(not_after, CERT_TIME_FORMAT).replace(tzinfo=timezone.utc)
        expires_at = expires.isoformat()
        days_remaining = (expires - now).days
        expired = expires <= now

    return {
        "valid": True,
        "issuer": _flatten_name(cert.get("issuer")),
        "subject": _flatten_name(cert.get("subject")),
        "expires_at": expires_at,
        "days_remaining": days_remaining,
        "expired": expired,
    }


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


def inspect_tls(domain: str, timeout: int = 10) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as wrapped:
                cert = wrapped.getpeercert()
                protocol = wrapped.version()
    except ssl.SSLCertVerificationError as exc:
        return _inspect_untrusted(domain, timeout, classify_verify_error(exc), str(exc))
    except ssl.SSLError as exc:
        return {"valid": False, "reason": "untrusted", "error": str(exc)}
    except (socket.gaierror, TimeoutError, OSError) as exc:
        return {"valid": False, "reason": "unreachable", "error": str(exc)}

    result = parse_cert(cert or {})
    result["verified"] = True
    result["protocol"] = protocol
    result["protocol_outdated"] = protocol in OUTDATED_PROTOCOLS
    return result


def _inspect_untrusted(domain: str, timeout: int, reason: str, error: str) -> dict[str, Any]:
    """The chain did not validate; still record the negotiated protocol if we can.

    ``getpeercert()`` only returns parsed fields for a *validated* chain, so we
    cannot safely report issuer/expiry here — but the classified ``reason`` is
    the actionable part, and the protocol still helps the report.
    """
    info: dict[str, Any] = {"valid": False, "reason": reason, "error": error}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as wrapped:
                info["protocol"] = wrapped.version()
                info["certificate_present"] = wrapped.getpeercert(binary_form=True) is not None
    except OSError:
        pass
    return info
