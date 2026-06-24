"""Passive domain intelligence via RDAP (the modern, structured WHOIS).

RDAP is served over HTTPS and needs no extra dependencies. Newly registered
domains and imminent registration expiry are useful risk signals for the kind
of small-business targets SentinelDeck reports on.
"""
from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

RDAP_BOOTSTRAP = "https://rdap.org/domain/"
USER_AGENT = "SentinelDeck/0.1"

Fetcher = Callable[[str, int], "dict[str, Any] | None"]


def _rdap_fetch(domain: str, timeout: int) -> dict[str, Any] | None:
    request = urllib.request.Request(
        f"{RDAP_BOOTSTRAP}{domain}",
        headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - any failure means we simply have no intel
        return None


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _extract_registrar(data: dict[str, Any]) -> str | None:
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            for item in entity.get("vcardArray", [None, []])[1]:
                if isinstance(item, list) and item and item[0] == "fn":
                    return item[3]
    return None


def analyze_domain_intel(domain: str, timeout: int = 10, fetcher: Fetcher = _rdap_fetch,
                         now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    data = fetcher(domain, timeout)
    if not data:
        return {"status": "error"}

    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    created = _parse_date(events.get("registration"))
    expires = _parse_date(events.get("expiration"))

    return {
        "status": "ok",
        "registrar": _extract_registrar(data),
        "created": created.isoformat() if created else None,
        "expires": expires.isoformat() if expires else None,
        "age_days": (now - created).days if created else None,
        "expires_in_days": (expires - now).days if expires else None,
    }
