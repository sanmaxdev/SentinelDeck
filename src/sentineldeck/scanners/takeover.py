"""Passive subdomain-takeover detection.

A subdomain that CNAMEs to a third-party service (GitHub Pages, Heroku, S3, ...)
becomes hijackable when the underlying resource is deleted but the DNS record
stays: an attacker re-creates the resource under that name and serves content
from your subdomain. Detection is passive and fingerprint-based: resolve the
CNAME, and only flag a host when the provider serves its specific "no such
resource" page. That keeps this high-severity finding low on false positives.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sentineldeck.scanners.dns_lookup import resolve

USER_AGENT = "SentinelDeck/0.1"
MAX_CHECKS = 50


@dataclass(frozen=True)
class Service:
    name: str
    cnames: tuple[str, ...]
    fingerprints: tuple[str, ...]


# Fingerprints are matched against a lower-cased response body. Sourced from the
# community "can I take over xyz" project.
SERVICES: tuple[Service, ...] = (
    Service("GitHub Pages", ("github.io",), ("there isn't a github pages site here",)),
    Service("Heroku", ("herokuapp.com", "herokudns.com"), ("no such app", "no-such-app.html")),
    Service("AWS S3", ("s3.amazonaws.com", "s3-website", ".s3."),
            ("nosuchbucket", "the specified bucket does not exist")),
    Service("Fastly", ("fastly.net",), ("fastly error: unknown domain",)),
    Service("Azure", ("azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net"),
            ("404 web site not found",)),
    Service("Shopify", ("myshopify.com",), ("sorry, this shop is currently unavailable",)),
    Service("Surge.sh", ("surge.sh",), ("project not found",)),
    Service("Bitbucket", ("bitbucket.io",), ("repository not found",)),
    Service("Pantheon", ("pantheonsite.io",), ("404 error unknown site", "the gods are wise")),
    Service("Tumblr", ("domains.tumblr.com",),
            ("whatever you were looking for doesn't currently exist",)),
    Service("Webflow", ("proxy.webflow.com", "proxy-ssl.webflow.com"),
            ("the page you are looking for doesn't exist or has been moved",)),
    Service("Read the Docs", ("readthedocs.io",), ("unknown domain", "404 not found")),
)

Resolver = Callable[[str, str], "tuple[list[str], str]"]
BodyFetcher = Callable[[str, int], "str | None"]


def _match_service(cname: str) -> Service | None:
    low = cname.lower()
    for service in SERVICES:
        if any(token in low for token in service.cnames):
            return service
    return None


def _http_body(host: str, timeout: int) -> str | None:
    for scheme in ("https", "http"):
        request = urllib.request.Request(f"{scheme}://{host}/", headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read(20000).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:  # provider error pages carry the fingerprint
            try:
                return exc.read(20000).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                continue
        except Exception:  # noqa: BLE001
            continue
    return None


def detect_takeovers(
    subdomains: list[str],
    resolver: Resolver = resolve,
    body_fetcher: BodyFetcher = _http_body,
    timeout: int = 10,
    limit: int = MAX_CHECKS,
) -> dict[str, Any]:
    """Flag subdomains that CNAME to an apparently unclaimed third-party service."""
    checked = subdomains[:limit]
    candidates: list[dict[str, Any]] = []
    for host in checked:
        cnames, _ = resolver(host, "CNAME")
        if not cnames:
            continue
        cname = cnames[0].rstrip(".")
        service = _match_service(cname)
        if service is None:
            continue
        body = body_fetcher(host, timeout)
        body = body.lower() if body else None
        if body and any(fingerprint in body for fingerprint in service.fingerprints):
            candidates.append(
                {"subdomain": host, "cname": cname, "service": service.name, "signal": "http-fingerprint"}
            )
    return {"status": "ok", "candidates": candidates, "checked": len(checked)}
