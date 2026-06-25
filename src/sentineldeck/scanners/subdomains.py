"""Passive subdomain discovery via certificate transparency logs (crt.sh).

Every publicly trusted certificate is logged to CT, so the logs are a free,
passive map of a domain's hostnames. crt.sh serves them as JSON over HTTPS with
no API key, which turns a single-host scan into an attack-surface map without
ever touching the target. The network call is injectable so the parsing is
tested entirely offline.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
CERTSPOTTER_URL = (
    "https://api.certspotter.com/v1/issuances?domain={domain}"
    "&include_subdomains=true&expand=dns_names"
)
USER_AGENT = "SentinelDeck/0.1"
MAX_STORED = 1000

# Left-of-apex labels that suggest non-production or internal systems. A host is
# flagged when any of its labels matches, so dev.api.example.com is caught too.
SENSITIVE_LABELS = frozenset({
    "dev", "develop", "development", "staging", "stage", "test", "testing", "qa",
    "uat", "preprod", "sandbox", "demo", "beta", "admin", "internal", "intranet",
    "vpn", "jenkins", "gitlab", "git", "ci", "grafana", "kibana", "jira",
    "confluence", "backup", "db", "database", "phpmyadmin", "pma", "old", "legacy",
})

Fetcher = Callable[[str, int], "list[dict[str, Any]] | None"]


def _fetch_json(url: str, timeout: int, attempts: int = 1) -> list[dict[str, Any]] | None:
    deadline = max(timeout, 15)
    for _ in range(attempts):
        request = urllib.request.Request(
            url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=deadline) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
                return data if isinstance(data, list) else None
        except Exception:  # noqa: BLE001 - any failure just means no CT data
            continue
    return None


def _default_fetch(domain: str, timeout: int) -> list[dict[str, Any]] | None:
    # crt.sh is the richer source but frequently returns 502s, so fall back to
    # CertSpotter (a different CT aggregator) when it is unavailable.
    quoted = urllib.parse.quote(domain)
    entries = _fetch_json(CRTSH_URL.format(domain=quoted), timeout, attempts=2)
    if entries is None:
        entries = _fetch_json(CERTSPOTTER_URL.format(domain=quoted), timeout)
    return entries


def _hostnames(entries: list[dict[str, Any]], domain: str) -> set[str]:
    suffix = "." + domain
    names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        # crt.sh uses name_value/common_name; CertSpotter uses dns_names.
        candidates = (entry.get("name_value") or "").split("\n")
        candidates.append(entry.get("common_name") or "")
        candidates.extend(entry.get("dns_names") or [])
        for candidate in candidates:
            name = candidate.strip().lower().lstrip("*.")
            if name and name != domain and name.endswith(suffix) and " " not in name:
                names.add(name)
    return names


def _is_sensitive(host: str, domain: str) -> bool:
    sub = host[: -len("." + domain)]
    return any(label in SENSITIVE_LABELS for label in sub.split("."))


def discover_subdomains(domain: str, timeout: int = 10, fetcher: Fetcher = _default_fetch) -> dict[str, Any]:
    """Return the subdomains of ``domain`` seen in certificate transparency."""
    entries = fetcher(domain, timeout)
    if not isinstance(entries, list):
        return {
            "status": "error", "source": "certificate transparency",
            "count": 0, "subdomains": [], "sensitive": [],
        }

    names = sorted(_hostnames(entries, domain))
    sensitive = sorted(host for host in names if _is_sensitive(host, domain))
    return {
        "status": "ok",
        "source": "certificate transparency",
        "count": len(names),
        "subdomains": names[:MAX_STORED],
        "sensitive": sensitive[:MAX_STORED],
        "truncated": len(names) > MAX_STORED,
    }
