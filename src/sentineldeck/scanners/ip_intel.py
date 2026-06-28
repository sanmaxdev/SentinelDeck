"""Passive IP intelligence: geolocation, ASN, and hosting provider for the
domain's resolved address, via the free ip-api.com endpoint (no key). The
network call is injectable so parsing is tested offline.
"""
from __future__ import annotations

import json
import urllib.request

USER_AGENT = "SentinelDeck/0.1"
IPAPI_URL = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,country,countryCode,city,regionName,isp,org,as,query,lat,lon,timezone"
)


def _default_fetch(ip: str, timeout: int = 10) -> dict | None:
    request = urllib.request.Request(IPAPI_URL.format(ip=ip), headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
            return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001 - inconclusive, reported as error
        return None


def analyze_ip_intel(ip: str | None, timeout: int = 10, fetcher=_default_fetch) -> dict:
    """Return geolocation, ASN, and hosting details for ``ip``."""
    if not ip:
        return {"status": "error"}
    data = fetcher(ip, timeout)
    if not data or data.get("status") != "success":
        return {"status": "error", "ip": ip}
    return {
        "status": "ok",
        "ip": data.get("query", ip),
        "city": data.get("city"),
        "region": data.get("regionName"),
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "asn": data.get("as"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "timezone": data.get("timezone"),
    }
