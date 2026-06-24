from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any


def inspect_tls(domain: str, timeout: int = 10) -> dict[str, Any]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as wrapped:
                cert = wrapped.getpeercert()
    except Exception as exc:  # noqa: BLE001 - scanner should return structured failure
        return {"valid": False, "error": str(exc)}

    not_after = cert.get("notAfter")
    expires_at = None
    days_remaining = None
    if not_after:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        expires_at = expires.isoformat()
        days_remaining = (expires - datetime.now(timezone.utc)).days

    return {
        "valid": True,
        "issuer": cert.get("issuer"),
        "subject": cert.get("subject"),
        "expires_at": expires_at,
        "days_remaining": days_remaining,
    }
