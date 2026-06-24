from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

CERT_TIME_FORMAT = "%b %d %H:%M:%S %Y %Z"


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


def inspect_tls(domain: str, timeout: int = 10) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as wrapped:
                cert = wrapped.getpeercert()
    except Exception as exc:  # noqa: BLE001 - scanner should return structured failure
        return {"valid": False, "error": str(exc)}

    return parse_cert(cert or {})
