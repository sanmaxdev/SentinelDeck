"""Passive web-content checks derived from the homepage: internal/external
links, social (Open Graph / Twitter) meta tags, web-application-firewall
fingerprinting, robots.txt, and sitemap.xml. The page is already fetched once by
the fingerprint scanner, so link/social/WAF parsing adds no extra requests;
robots.txt and sitemap.xml are two small injectable GETs.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "SentinelDeck/0.1"

_HREF = re.compile(r'<a\s[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)
_META = re.compile(r"<meta\s+([^>]+?)/?>", re.IGNORECASE)
_META_KEY = re.compile(r'(?:property|name)=["\'](og:[^"\']+|twitter:[^"\']+)["\']', re.IGNORECASE)
_META_VAL = re.compile(r'content=["\']([^"\']*)["\']', re.IGNORECASE)

# Header / cookie fingerprints for common web application firewalls and CDNs.
_WAF_SIGNATURES = [
    ("Cloudflare", ("server:cloudflare", "cf-ray", "__cfduid", "cf-cache-status")),
    ("AWS CloudFront / WAF", ("x-amz-cf-id", "x-amzn-requestid", "awselb")),
    ("Akamai", ("server:akamaighost", "x-akamai-transformed", "akamai")),
    ("Sucuri", ("server:sucuri", "x-sucuri-id", "x-sucuri-cache")),
    ("Imperva Incapsula", ("incap_ses", "x-iinfo", "x-cdn:incapsula", "visid_incap")),
    ("F5 BIG-IP", ("bigipserver", "x-waf-status", "ts01")),
    ("Fastly", ("server:fastly", "x-served-by", "x-fastly")),
    ("Wordfence", ("wfvt_", "wordfence")),
    ("Barracuda", ("barra_counter_session",)),
]


def extract_links(body: str, domain: str) -> dict:
    """Count internal links and collect distinct external domains."""
    internal = 0
    external: set[str] = set()
    suffix = "." + domain
    for href in _HREF.findall(body or ""):
        href = href.strip()
        if href.startswith(("mailto:", "tel:", "javascript:", "data:", "#")):
            continue
        netloc = urllib.parse.urlparse(href).netloc.lower().split(":")[0]
        if not netloc or netloc == domain or netloc.endswith(suffix):
            internal += 1
        else:
            external.add(netloc)
    return {"internal": internal, "external": len(external), "external_domains": sorted(external)[:50]}


def extract_social_tags(body: str) -> dict:
    """Pull Open Graph and Twitter-card meta tags, order-independent."""
    tags: dict[str, str] = {}
    for attrs in _META.findall(body or ""):
        key = _META_KEY.search(attrs)
        val = _META_VAL.search(attrs)
        if key and val:
            tags[key.group(1).lower()] = val.group(1)
    return tags


def detect_waf(headers: dict) -> list[str]:
    """Fingerprint web application firewalls / CDNs from response headers."""
    lowered = {k.lower(): str(v).lower() for k, v in (headers or {}).items()}
    blob = " ".join(f"{k}:{v}" for k, v in lowered.items())
    found = []
    for name, markers in _WAF_SIGNATURES:
        for marker in markers:
            if marker.startswith("server:"):
                if marker.split(":", 1)[1] in lowered.get("server", ""):
                    found.append(name)
                    break
            elif marker in blob:
                found.append(name)
                break
    return found


def _http_get(url: str, timeout: int = 10) -> str | None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            return response.read(200_000).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - a missing file is just no file
        return None


def fetch_robots(domain: str, fetcher=_http_get) -> dict:
    body = fetcher(f"https://{domain}/robots.txt")
    if body is None:
        return {"present": False, "sitemaps": [], "disallow_count": 0}
    sitemaps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", body)
    disallows = len(re.findall(r"(?im)^\s*disallow:\s*\S", body))
    return {"present": True, "sitemaps": sitemaps[:20], "disallow_count": disallows}


def fetch_sitemap(url: str, fetcher=_http_get) -> dict:
    body = fetcher(url)
    if body is None:
        return {"present": False, "urls": 0}
    return {"present": True, "urls": len(re.findall(r"<loc>", body, re.IGNORECASE))}


def analyze_web_content(domain: str, page: dict, fetcher=_http_get) -> dict:
    """Combine page-derived checks with robots.txt and sitemap.xml."""
    body = (page or {}).get("body", "") or ""
    headers = (page or {}).get("headers", {}) or {}
    robots = fetch_robots(domain, fetcher)
    sitemap_url = robots["sitemaps"][0] if robots.get("sitemaps") else f"https://{domain}/sitemap.xml"
    return {
        "status": "ok" if (page or {}).get("reachable") else "error",
        "links": extract_links(body, domain),
        "social": extract_social_tags(body),
        "waf": detect_waf(headers),
        "robots": robots,
        "sitemap": fetch_sitemap(sitemap_url, fetcher),
    }
