"""Decide whether a scan target is a domain or an IP address.

The search box and CLI accept a domain, a bare IP (v4 or v6), or a full URL.
``classify_target`` normalises the input and reports which kind it is so the
scanner can run the right pipeline.
"""
from __future__ import annotations

import ipaddress
import urllib.parse

from sentineldeck.scanners.domain import normalize_domain


def classify_target(raw: str) -> tuple[str, str]:
    """Return ("ip"|"domain", normalised value) for ``raw``.

    Accepts ``example.com``, ``1.2.3.4``, ``[::1]``, ``host:port``, or a full URL.
    Raises ValueError for empty or unparseable input.
    """
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("No target provided")
    parsed = urllib.parse.urlsplit(raw if "://" in raw else "//" + raw)
    host = parsed.hostname or raw.split("/", 1)[0]
    try:
        return "ip", str(ipaddress.ip_address(host))
    except ValueError:
        return "domain", normalize_domain(host)


def is_private_ip(ip: str) -> bool:
    """True for loopback / private / reserved / link-local addresses."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return obj.is_private or obj.is_loopback or obj.is_reserved or obj.is_link_local
