"""Reverse-IP lookup: which domains are hosted on an IP address. For an IP scan
this is "what lives here"; for a domain scan it is the shared-hosting neighbours
on the domain's server. Uses HackerTarget's free reverse-IP API (no key); the
network call is injectable for offline tests.
"""
from __future__ import annotations

import urllib.parse
import urllib.request

USER_AGENT = "SentinelDeck/0.1"
REVERSE_IP_URL = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
MAX_HOSTS = 200


def _default_fetch(ip: str, timeout: int = 12) -> str | None:
    url = REVERSE_IP_URL.format(ip=urllib.parse.quote(ip))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - any failure just means no reverse-IP data
        return None


def reverse_ip(ip: str, timeout: int = 12, fetcher=_default_fetch) -> dict:
    """Return the domains hosted on ``ip``."""
    text = fetcher(ip, timeout)
    if not text or text.lower().startswith(("error", "no records", "api count")):
        return {"status": "ok" if text is not None else "error", "count": 0, "domains": []}
    domains = sorted({line.strip().lower() for line in text.splitlines() if line.strip() and "." in line})
    return {
        "status": "ok",
        "count": len(domains),
        "domains": domains[:MAX_HOSTS],
        "truncated": len(domains) > MAX_HOSTS,
    }
