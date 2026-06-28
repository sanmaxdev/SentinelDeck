"""Threat reputation: check whether a domain is listed as serving malware or
phishing, via abuse.ch URLhaus (free, no API key). The network call is
injectable so parsing is tested offline.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

USER_AGENT = "SentinelDeck/0.1"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"


def _urlhaus_fetch(domain: str, timeout: int = 10) -> dict | None:
    data = urllib.parse.urlencode({"host": domain}).encode()
    request = urllib.request.Request(URLHAUS_URL, data=data, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - inconclusive, reported as error
        return None


def check_reputation(domain: str, fetcher=_urlhaus_fetch) -> dict:
    """Return whether ``domain`` is listed on a threat feed."""
    data = fetcher(domain)
    if not data:
        return {"status": "error", "listed": False, "sources": [], "url_count": 0}
    listed = data.get("query_status") == "ok" and bool(data.get("urls"))
    return {
        "status": "ok",
        "listed": listed,
        "sources": ["URLhaus"] if listed else [],
        "url_count": len(data.get("urls") or []),
    }
