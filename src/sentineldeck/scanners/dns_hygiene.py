"""Additional DNS hardening signals: CAA issuance control and DNSSEC."""
from __future__ import annotations

from collections.abc import Callable

from sentineldeck.scanners.dns_lookup import resolve

Resolver = Callable[[str, str], "tuple[list[str], str]"]


def analyze_dns_hygiene(domain: str, resolver: Resolver = resolve) -> dict:
    caa, caa_status = resolver(domain, "CAA")
    dnskey, dnskey_status = resolver(domain, "DNSKEY")
    return {
        "caa": {
            "present": bool(caa),
            "records": caa,
            "status": caa_status,
        },
        "dnssec": {
            "enabled": bool(dnskey),
            "status": dnskey_status,
        },
    }
