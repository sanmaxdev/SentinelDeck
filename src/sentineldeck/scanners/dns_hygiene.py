"""Additional DNS hardening signals: CAA, DNSSEC, nameserver redundancy, IPv6,
and DANE/TLSA."""
from __future__ import annotations

from collections.abc import Callable

from sentineldeck.scanners.dns_lookup import resolve

Resolver = Callable[[str, str], "tuple[list[str], str]"]


def analyze_dns_hygiene(domain: str, resolver: Resolver = resolve) -> dict:
    caa, caa_status = resolver(domain, "CAA")
    dnskey, dnskey_status = resolver(domain, "DNSKEY")
    ns, ns_status = resolver(domain, "NS")
    aaaa, aaaa_status = resolver(domain, "AAAA")
    tlsa, tlsa_status = resolver(f"_443._tcp.{domain}", "TLSA")
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
        "ns": {
            "records": ns,
            "count": len(ns),
            "status": ns_status,
        },
        "ipv6": {
            "present": bool(aaaa),
            "records": aaaa,
            "status": aaaa_status,
        },
        "dane": {
            "present": bool(tlsa),
            "records": tlsa,
            "status": tlsa_status,
        },
    }
