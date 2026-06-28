"""Wayback Machine archive history: how long a domain has been archived and how
many snapshots exist, via the Internet Archive CDX API (free, no key). Useful
context for a domain's age and history. The call is injectable for offline tests.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

USER_AGENT = "SentinelDeck/0.1"
CDX_URL = (
    "http://web.archive.org/cdx/search/cdx?url={domain}"
    "&output=json&fl=timestamp&collapse=timestamp:6&limit=40"
)


def _wayback_fetch(domain: str, timeout: int = 12) -> list | None:
    url = CDX_URL.format(domain=urllib.parse.quote(domain))
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
            return data if isinstance(data, list) else None
    except Exception:  # noqa: BLE001 - no archive data is not an error
        return None


def archive_history(domain: str, fetcher=_wayback_fetch) -> dict:
    """Return snapshot count and first/last archived year for ``domain``."""
    rows = fetcher(domain)
    if not rows or len(rows) < 2:  # first row is the CDX header
        return {"status": "ok", "snapshots": 0, "first": None, "last": None}
    stamps = sorted(r[0] for r in rows[1:] if r and str(r[0]).isdigit())
    if not stamps:
        return {"status": "ok", "snapshots": 0, "first": None, "last": None, "truncated": False}
    return {
        "status": "ok",
        "snapshots": len(stamps),
        "first": stamps[0][:4],
        "last": stamps[-1][:4],
        "truncated": len(stamps) >= 40,
    }
