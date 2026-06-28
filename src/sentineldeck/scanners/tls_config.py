"""TLS configuration depth: which protocol versions the server still supports
and a Mozilla-style configuration grade. This probes the target's own HTTPS port
with forced TLS versions (a handshake per version, the same thing a browser does
while negotiating), so it stays safe. The prober is injectable for offline tests.
"""
from __future__ import annotations

import socket
import ssl
from collections.abc import Callable

_VERSIONS = [
    ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]
Prober = Callable[[str, int, int], dict]


def supported_protocols(domain: str, port: int = 443, timeout: int = 5) -> dict:
    """Return {version: True/False} for each TLS version the server accepts."""
    results: dict[str, bool | None] = {}
    for name, version in _VERSIONS:
        if version is None:
            results[name] = None
            continue
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
        except (ValueError, OSError):
            results[name] = None
            continue
        try:
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain):
                    results[name] = True
        except Exception:  # noqa: BLE001 - a refused handshake means unsupported
            results[name] = False
    return results


def grade_config(protocols: dict) -> str:
    """A simplified Mozilla-style grade from the supported protocol set."""
    if protocols.get("TLSv1") or protocols.get("TLSv1.1"):
        return "old"
    if protocols.get("TLSv1.3") and not protocols.get("TLSv1.2"):
        return "modern"
    return "intermediate"


def analyze_tls_config(domain: str, port: int = 443, timeout: int = 5, prober: Prober = supported_protocols) -> dict:
    """Enumerate supported TLS versions and grade the configuration."""
    protocols = prober(domain, port, timeout)
    if all(v is not True for v in protocols.values()):
        return {"status": "error", "protocols": protocols, "weak_protocols": [], "grade": None}
    weak = [name for name in ("TLSv1", "TLSv1.1") if protocols.get(name)]
    return {
        "status": "ok",
        "protocols": protocols,
        "weak_protocols": weak,
        "grade": grade_config(protocols),
    }
