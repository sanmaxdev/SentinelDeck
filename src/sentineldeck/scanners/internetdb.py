"""Shodan InternetDB lookup: the open ports, service CPEs, tags, and known CVEs
Shodan has already observed for an IP, returned without us touching the host.
Free and keyless (https://internetdb.shodan.io). This gives a passive exposure +
vulnerability surface; the network call is injectable for offline tests.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

USER_AGENT = "SentinelDeck/0.1"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

_EMPTY = {"status": "ok", "ports": [], "vulns": [], "cpes": [], "tags": [], "hostnames": []}


def _default_fetch(ip: str, timeout: int = 10) -> dict | None:
    request = urllib.request.Request(INTERNETDB_URL.format(ip=ip), headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
            return data if isinstance(data, dict) else None
    except urllib.error.HTTPError as exc:
        return {} if exc.code == 404 else None  # 404 = no record on file = nothing exposed
    except Exception:  # noqa: BLE001 - any failure is reported as inconclusive
        return None


def analyze_internetdb(ip: str, timeout: int = 10, fetcher=_default_fetch) -> dict:
    """Return the passively-known exposure (ports, CVEs, CPEs, tags) for ``ip``."""
    data = fetcher(ip, timeout)
    if data is None:
        return {"status": "error", "ports": [], "vulns": []}
    if not data:
        return dict(_EMPTY)
    return {
        "status": "ok",
        "ports": sorted(data.get("ports") or []),
        "vulns": sorted(data.get("vulns") or []),
        "cpes": data.get("cpes") or [],
        "tags": data.get("tags") or [],
        "hostnames": data.get("hostnames") or [],
    }
