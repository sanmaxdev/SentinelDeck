"""Passive technology fingerprinting and vulnerable-JavaScript detection.

Reads the homepage (headers + HTML) the way a browser would and matches it
against a built-in signature set to identify servers, frameworks, CMSs, CDNs,
and analytics, then flags known-vulnerable JavaScript libraries by version.
No active probing: a single GET of the home page, nothing more.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request
from typing import Any

USER_AGENT = "SentinelDeck/0.1"
MAX_BODY = 400_000  # cap the HTML we read; enough for <head> and script tags


def fetch_page(domain: str, timeout: int = 10) -> dict:
    """GET the homepage and return its headers and (capped) HTML body."""
    url = f"https://{domain}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(MAX_BODY).decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in response.headers.items()}
            return {"reachable": True, "status": response.status, "headers": headers, "body": body}
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(MAX_BODY).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001
            body = ""
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return {"reachable": True, "status": exc.code, "headers": headers, "body": body}
    except Exception as exc:  # noqa: BLE001 - scanner returns a structured failure
        return {"reachable": False, "status": None, "headers": {}, "body": "", "error": str(exc)}


# Each signature matches on response headers and/or HTML. ``version_header`` and
# ``version_html`` optionally extract a version from the first capture group.
SIGNATURES: list[dict[str, Any]] = [
    {"name": "WordPress", "category": "CMS",
     "html": [r"wp-content/", r"wp-includes/", r'name=["\']generator["\'] content=["\']WordPress'],
     "version_html": r'content=["\']WordPress\s+([\d.]+)'},
    {"name": "Drupal", "category": "CMS",
     "html": [r"Drupal\.settings", r'name=["\']generator["\'] content=["\']Drupal'],
     "version_html": r'content=["\']Drupal\s+([\d.]+)'},
    {"name": "Joomla", "category": "CMS",
     "html": [r"/media/jui/", r'name=["\']generator["\'] content=["\']Joomla']},
    {"name": "Magento", "category": "E-commerce", "html": [r"/static/version\d", r"Mage\.Cookies"]},
    {"name": "Shopify", "category": "E-commerce",
     "headers": [("x-shopid", r".+"), ("x-shopify-stage", r".+")], "html": [r"cdn\.shopify\.com"]},
    {"name": "WooCommerce", "category": "E-commerce",
     "html": [r"woocommerce", r"wp-content/plugins/woocommerce"]},
    {"name": "React", "category": "JS framework",
     "html": [r"data-reactroot", r"react(?:-dom)?(?:\.production)?\.min\.js"]},
    {"name": "Vue.js", "category": "JS framework", "html": [r"data-v-[0-9a-f]{8}", r"vue(?:\.runtime)?(?:\.min)?\.js"]},
    {"name": "Angular", "category": "JS framework", "html": [r"ng-version=", r"\bng-app\b"]},
    {"name": "Next.js", "category": "Framework", "html": [r"/_next/static", r'id=["\']__next["\']']},
    {"name": "Nuxt.js", "category": "Framework", "html": [r"/_nuxt/", r'id=["\']__nuxt["\']']},
    {"name": "jQuery", "category": "JS library", "html": [r"jquery[.\-]"],
     "version_html": r"jquery[.\-]v?([\d.]+)(?:\.min)?\.js"},
    {"name": "Bootstrap", "category": "UI framework", "html": [r"bootstrap(?:\.min)?\.(?:css|js)"],
     "version_html": r"bootstrap[/@]?v?([\d.]+)"},
    {"name": "Cloudflare", "category": "CDN", "headers": [("server", r"cloudflare"), ("cf-ray", r".+")]},
    {"name": "AWS CloudFront", "category": "CDN", "headers": [("via", r"cloudfront"), ("x-amz-cf-id", r".+")]},
    {"name": "Fastly", "category": "CDN", "headers": [("x-served-by", r"cache"), ("x-fastly", r".+")]},
    {"name": "Varnish", "category": "Cache", "headers": [("via", r"varnish"), ("x-varnish", r".+")]},
    {"name": "nginx", "category": "Web server", "headers": [("server", r"nginx")],
     "version_header": ("server", r"nginx/([\d.]+)")},
    {"name": "Apache", "category": "Web server", "headers": [("server", r"apache")],
     "version_header": ("server", r"Apache/([\d.]+)")},
    {"name": "Microsoft IIS", "category": "Web server", "headers": [("server", r"iis|microsoft-iis")],
     "version_header": ("server", r"IIS/([\d.]+)")},
    {"name": "PHP", "category": "Language", "headers": [("x-powered-by", r"php")],
     "version_header": ("x-powered-by", r"PHP/([\d.]+)")},
    {"name": "ASP.NET", "category": "Framework",
     "headers": [("x-powered-by", r"asp\.net"), ("x-aspnet-version", r".+")],
     "version_header": ("x-aspnet-version", r"([\d.]+)")},
    {"name": "Express", "category": "Framework", "headers": [("x-powered-by", r"express")]},
    {"name": "Google Analytics", "category": "Analytics",
     "html": [r"google-analytics\.com/analytics\.js", r"googletagmanager\.com/gtag", r"gtag\("]},
    {"name": "Wix", "category": "Website builder", "headers": [("x-wix-request-id", r".+")],
     "html": [r"static\.wixstatic\.com"]},
    {"name": "Squarespace", "category": "Website builder", "html": [r"static1\.squarespace\.com", r"squarespace\.com"]},
]


def fingerprint(page: dict) -> list[dict]:
    """Return the technologies detected from a fetched page."""
    headers = page.get("headers", {})
    body = page.get("body", "") or ""
    detected: list[dict] = []
    for sig in SIGNATURES:
        version = None
        matched = False
        for hname, pattern in sig.get("headers", []):
            value = headers.get(hname)
            if value and re.search(pattern, value, re.IGNORECASE):
                matched = True
                break
        if not matched:
            for pattern in sig.get("html", []):
                if re.search(pattern, body, re.IGNORECASE):
                    matched = True
                    break
        if not matched:
            continue
        if sig.get("version_header"):
            hname, vpat = sig["version_header"]
            vmatch = re.search(vpat, headers.get(hname, ""), re.IGNORECASE)
            if vmatch:
                version = vmatch.group(1)
        if version is None and sig.get("version_html"):
            vmatch = re.search(sig["version_html"], body, re.IGNORECASE)
            if vmatch:
                version = vmatch.group(1)
        detected.append({"name": sig["name"], "category": sig["category"], "version": version})
    return detected


# library -> list of (highest_affected_version, advisory, severity).
JS_VULN_DB = {
    "jquery": [("3.4.1", "jQuery < 3.5.0: XSS via htmlPrefilter (CVE-2020-11022/11023).", "medium")],
    "bootstrap": [("4.3.0", "Bootstrap < 4.3.1 / 3.4.1: XSS in data-target and tooltips (CVE-2019-8331).", "medium")],
    "angular": [("1.8.3", "AngularJS (1.x) is end-of-life and no longer receives security fixes.", "medium")],
    "lodash": [("4.17.20", "lodash < 4.17.21: command injection / prototype pollution (CVE-2021-23337).", "high")],
    "moment": [("2.29.1", "moment < 2.29.2: path traversal (CVE-2022-24785).", "medium")],
    "vue": [("2.7.16", "Vue 2 reached end-of-life in Dec 2023; upgrade to Vue 3.", "low")],
    "dompurify": [("2.4.1", "DOMPurify < 2.4.2: mutation XSS bypass.", "high")],
}

_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_LIB_VERSION = re.compile(
    r"(?P<lib>jquery|bootstrap|angular|lodash|moment|vue|dompurify)[.\-]v?(?P<ver>\d+\.\d+(?:\.\d+)?)",
    re.IGNORECASE,
)


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for piece in version.split("."):
        match = re.match(r"\d+", piece)
        parts.append(int(match.group()) if match else 0)
    return tuple(parts)


def _version_le(a: str, b: str) -> bool:
    """Return True if version ``a`` is <= version ``b``."""
    ta, tb = _version_tuple(a), _version_tuple(b)
    width = max(len(ta), len(tb))
    ta += (0,) * (width - len(ta))
    tb += (0,) * (width - len(tb))
    return ta <= tb


def detect_vulnerable_js(body: str) -> list[dict]:
    """Find JavaScript libraries with known-vulnerable versions in the HTML."""
    found: dict[tuple[str, str], dict] = {}
    for src in _SCRIPT_SRC.findall(body or ""):
        match = _LIB_VERSION.search(src)
        if not match:
            continue
        lib = match.group("lib").lower()
        version = match.group("ver")
        for max_version, advisory, severity in JS_VULN_DB.get(lib, []):
            if _version_le(version, max_version):
                found[(lib, version)] = {
                    "library": lib, "version": version, "advisory": advisory, "severity": severity,
                }
                break
    return list(found.values())


def analyze_technologies(domain: str, timeout: int = 10, fetcher=fetch_page) -> dict:
    """Fingerprint a domain's technology stack and flag vulnerable JS libraries."""
    page = fetcher(domain, timeout)
    if not page.get("reachable"):
        return {"status": "error", "detected": [], "vulnerable_js": []}
    return {
        "status": "ok",
        "detected": fingerprint(page),
        "vulnerable_js": detect_vulnerable_js(page.get("body", "")),
    }
