"""RDAP lookup for an IP address: which network block it belongs to, the owning
organisation, the registration date, and the abuse contact. Uses the public
rdap.org bootstrap (no key), which redirects to the authoritative RIR. The
network call is injectable for offline tests.
"""
from __future__ import annotations

import json
import urllib.request

USER_AGENT = "SentinelDeck/0.1"
RDAP_URL = "https://rdap.org/ip/{ip}"


def _default_fetch(ip: str, timeout: int = 10) -> dict | None:
    request = urllib.request.Request(
        RDAP_URL.format(ip=ip), headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
            return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001 - inconclusive, reported as error
        return None


def _vcard_value(vcard, field: str):
    try:
        for entry in vcard[1]:
            if entry[0] == field:
                return entry[3]
    except Exception:  # noqa: BLE001 - vcard shapes vary by RIR
        return None
    return None


def _find_abuse(entities) -> str | None:
    for ent in entities or []:
        if "abuse" in (ent.get("roles") or []):
            email = _vcard_value(ent.get("vcardArray"), "email")
            if email:
                return email
        nested = _find_abuse(ent.get("entities"))
        if nested:
            return nested
    return None


def _org_name(entities) -> str | None:
    for wanted in ("registrant", "administrative", None):
        for ent in entities or []:
            if wanted is None or wanted in (ent.get("roles") or []):
                fn = _vcard_value(ent.get("vcardArray"), "fn")
                if fn:
                    return fn
    return None


def analyze_ip_rdap(ip: str, timeout: int = 10, fetcher=_default_fetch) -> dict:
    """Return the network allocation details for ``ip``."""
    data = fetcher(ip, timeout)
    if not data:
        return {"status": "error"}
    cidr = None
    cidrs = data.get("cidr0_cidrs")
    if cidrs:
        block = cidrs[0]
        prefix = block.get("v4prefix") or block.get("v6prefix")
        length = block.get("length")
        if prefix and length is not None:
            cidr = f"{prefix}/{length}"
    if not cidr and data.get("startAddress") and data.get("endAddress"):
        cidr = f"{data['startAddress']} - {data['endAddress']}"
    registered = None
    for event in data.get("events", []):
        if event.get("eventAction") == "registration":
            registered = (event.get("eventDate") or "")[:10]
    return {
        "status": "ok",
        "name": data.get("name"),
        "handle": data.get("handle"),
        "cidr": cidr,
        "country": data.get("country"),
        "org": _org_name(data.get("entities")),
        "abuse_email": _find_abuse(data.get("entities")),
        "registered": registered,
    }
