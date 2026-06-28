"""DNS blocklist checks: query the domain through public filtering resolvers and
see whether any of them block it. A malware/security filter blocking the domain
is a strong signal it is flagged as malicious. Uses DNS-over-HTTPS JSON, so it
works where port 53 is blocked. Queries are injectable for offline tests.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

USER_AGENT = "SentinelDeck/0.1"

# (name, DoH JSON endpoint, is_security_filter)
FILTERS = [
    ("Cloudflare Security", "https://security.cloudflare-dns.com/dns-query", True),
    ("Cloudflare Family", "https://family.cloudflare-dns.com/dns-query", False),
    ("Quad9", "https://dns.quad9.net/dns-query", True),
    ("AdGuard", "https://dns.adguard-dns.com/dns-query", True),
    ("AdGuard Family", "https://family.adguard-dns.com/dns-query", False),
    ("Google DNS", "https://dns.google/resolve", False),
]
# Sinkhole IPs that filtering resolvers return for blocked domains (not a bind address).
SINKHOLES = {"0.0.0.0", "::", "146.112.61.104", "146.112.61.106", "146.112.61.108"}  # nosec B104


def _doh_query(endpoint: str, domain: str, timeout: int = 8) -> dict | None:
    url = endpoint + "?" + urllib.parse.urlencode({"name": domain, "type": "A"})
    request = urllib.request.Request(
        url, headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - an unreachable filter is inconclusive
        return None


def _is_blocked(data: dict | None) -> bool | None:
    if data is None:
        return None
    if data.get("Status") == 3:  # NXDOMAIN
        return True
    answers = [a.get("data") for a in data.get("Answer", []) if a.get("type") == 1]
    if answers:
        return all(a in SINKHOLES for a in answers)
    return data.get("Status") == 0  # NOERROR with no answer = filtered


def check_blocklists(domain: str, query=_doh_query) -> dict:
    """Return each filter's verdict for ``domain`` and which security filters block it."""
    def check(item):
        name, endpoint, security = item
        return {"filter": name, "blocked": _is_blocked(query(endpoint, domain)), "security": security}

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(check, FILTERS))
    blocked_security = [r["filter"] for r in results if r["blocked"] and r["security"]]
    return {"status": "ok", "results": results, "blocked_security": blocked_security}
