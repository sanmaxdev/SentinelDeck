"""ASN / network footprint via RIPEstat (free, keyless). From a single IP we find
the owning autonomous system and every prefix it announces, mapping an
organisation's whole routed IP estate from one address. The network calls are
injectable for offline tests.
"""
from __future__ import annotations

import ipaddress
import json
import urllib.parse
import urllib.request

USER_AGENT = "SentinelDeck/0.1"
RIPESTAT = "https://stat.ripe.net/data/{call}/data.json?resource={resource}"
MAX_PREFIXES = 256


def _default_fetch(call: str, resource: str, timeout: int = 12) -> dict | None:
    url = RIPESTAT.format(call=call, resource=urllib.parse.quote(str(resource)))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
            return data.get("data") if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001 - any failure is reported as inconclusive
        return None


def analyze_asn(ip: str, timeout: int = 12, fetcher=_default_fetch) -> dict:
    """Return the ASN and every announced prefix for the network ``ip`` sits in."""
    info = fetcher("network-info", ip, timeout)
    if not info:
        return {"status": "error"}
    asns = info.get("asns") or []
    if not asns:
        return {"status": "ok", "asn": None, "prefixes": [], "prefix_count": 0}

    asn = asns[0]
    overview = fetcher("as-overview", f"AS{asn}", timeout) or {}
    announced = fetcher("announced-prefixes", f"AS{asn}", timeout) or {}
    prefixes = sorted({p["prefix"] for p in (announced.get("prefixes") or []) if p.get("prefix")})

    ipv4_addresses = ipv4_prefixes = ipv6_prefixes = 0
    for prefix in prefixes:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            ipv4_addresses += net.num_addresses
            ipv4_prefixes += 1
        else:
            ipv6_prefixes += 1

    return {
        "status": "ok",
        "asn": asn,
        "holder": overview.get("holder"),
        "prefix": info.get("prefix"),
        "prefixes": prefixes[:MAX_PREFIXES],
        "prefix_count": len(prefixes),
        "ipv4_addresses": ipv4_addresses,
        "ipv4_prefixes": ipv4_prefixes,
        "ipv6_prefixes": ipv6_prefixes,
        "truncated": len(prefixes) > MAX_PREFIXES,
    }
