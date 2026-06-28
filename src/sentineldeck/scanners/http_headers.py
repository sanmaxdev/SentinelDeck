from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

USER_AGENT = "SentinelDeck/0.1"
# Six months, the minimum max-age browsers expect before HSTS is meaningful.
HSTS_MIN_MAX_AGE = 15768000

SECURITY_HEADERS = {
    "strict-transport-security": "Add HSTS to force browsers to use HTTPS.",
    "content-security-policy": "Add a Content-Security-Policy to reduce XSS and injection impact.",
    "x-content-type-options": "Add X-Content-Type-Options: nosniff.",
    "x-frame-options": "Add X-Frame-Options or frame-ancestors to reduce clickjacking risk.",
    "referrer-policy": "Add Referrer-Policy to limit sensitive URL leakage.",
    "permissions-policy": "Add Permissions-Policy to restrict browser features.",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: D401 - suppress auto-follow
        return None


def fetch_headers(domain: str, timeout: int = 10) -> dict[str, Any]:
    """Fetch response headers over HTTPS, falling back from HEAD to GET."""
    url = f"https://{domain}"
    result: dict[str, Any] = {"reachable": False, "url": url, "status": None, "headers": {}, "error": None}

    for method in ("HEAD", "GET"):
        request = urllib.request.Request(url, method=method, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                result["reachable"] = True
                result["status"] = response.status
                result["headers"] = {key.lower(): value for key, value in response.headers.items()}
                result["cookies"] = response.headers.get_all("set-cookie") or []
            return result
        except urllib.error.HTTPError as exc:
            # Some servers reject HEAD with 405/501 - retry once with GET.
            if method == "HEAD" and exc.code in (405, 501):
                continue
            result["reachable"] = True
            result["status"] = exc.code
            result["headers"] = {key.lower(): value for key, value in exc.headers.items()}
            result["cookies"] = exc.headers.get_all("set-cookie") or []
            return result
        except Exception as exc:  # noqa: BLE001 - scanner should return structured failure
            result["error"] = str(exc)
            return result
    return result


def check_security_txt(domain: str, timeout: int = 10) -> dict[str, Any]:
    """Check for an RFC 9116 security.txt at the well-known location."""
    url = f"https://{domain}/.well-known/security.txt"
    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {"present": response.status == 200, "status": response.status, "url": url}
    except urllib.error.HTTPError as exc:
        return {"present": False, "status": exc.code, "url": url}
    except Exception:  # noqa: BLE001 - inconclusive, reported as unknown
        return {"present": None, "status": None, "url": url}


def check_http_redirect(domain: str, timeout: int = 10) -> dict[str, Any]:
    """Check whether plain HTTP redirects to HTTPS (without following the hop)."""
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(
        f"http://{domain}", method="HEAD", headers={"User-Agent": USER_AGENT}
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            location = response.headers.get("location", "")
            status = response.status
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("location", "") if exc.headers else ""
        status = exc.code
    except Exception:  # noqa: BLE001 - inconclusive, reported as unknown
        return {"https_redirect": None, "http_status": None}

    redirects_to_https = location.lower().startswith("https://")
    return {"https_redirect": bool(redirects_to_https), "http_status": status}


def trace_redirects(domain: str, timeout: int = 10, max_hops: int = 8) -> dict[str, Any]:
    """Follow the redirect chain from http://domain and record each hop."""
    opener = urllib.request.build_opener(_NoRedirect)
    url = f"http://{domain}"
    hops: list[dict[str, Any]] = []
    downgrade = False
    for _ in range(max_hops):
        request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": USER_AGENT})
        try:
            with opener.open(request, timeout=timeout) as response:
                status, location = response.status, response.headers.get("location")
        except urllib.error.HTTPError as exc:
            status = exc.code
            location = exc.headers.get("location") if exc.headers else None
        except Exception:  # noqa: BLE001 - stop tracing on any transport error
            break
        hops.append({"url": url, "status": status})
        if not location or not (300 <= status < 400):
            break
        nxt = urllib.parse.urljoin(url, location)
        if url.startswith("https://") and nxt.startswith("http://"):
            downgrade = True
        url = nxt
    return {"hops": hops, "final_url": url, "count": len(hops), "downgrade": downgrade}


def missing_security_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name: advice for name, advice in SECURITY_HEADERS.items() if name not in headers}


def evaluate_headers(headers: dict[str, str], cookies: list[str] | None = None) -> list[dict[str, Any]]:
    """Flag security headers that are present but configured ineffectively."""
    issues: list[dict[str, Any]] = []

    hsts = headers.get("strict-transport-security")
    if hsts is not None:
        match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        max_age = int(match.group(1)) if match else 0
        if max_age == 0:
            issues.append(_issue(
                "hsts-ineffective", "HSTS is present but disabled", "medium",
                "Strict-Transport-Security has max-age=0 (or none), which disables HSTS.",
                "Set a max-age of at least 15768000 (6 months).", {"value": hsts},
            ))
        elif max_age < HSTS_MIN_MAX_AGE:
            issues.append(_issue(
                "hsts-short-max-age", "HSTS max-age is short", "low",
                f"HSTS max-age is {max_age}s, below the recommended 6 months.",
                "Raise max-age to at least 15768000 and consider includeSubDomains.", {"value": hsts},
            ))
        elif "includesubdomains" not in hsts.lower() or "preload" not in hsts.lower():
            issues.append(_issue(
                "hsts-not-preloadable", "HSTS is not preload-eligible", "info",
                "HSTS has a strong max-age but lacks includeSubDomains and/or preload, so the domain "
                "cannot join the browser HSTS preload list.",
                "Add includeSubDomains and preload, then submit at hstspreload.org.", {"value": hsts},
            ))

    csp = headers.get("content-security-policy")
    if csp and re.search(r"unsafe-inline|unsafe-eval", csp, re.IGNORECASE):
        issues.append(_issue(
            "csp-unsafe-directives", "CSP allows unsafe inline/eval", "low",
            "The Content-Security-Policy permits unsafe-inline or unsafe-eval, weakening XSS protection.",
            "Remove unsafe-inline/unsafe-eval and adopt nonces or hashes.", {"value": csp},
        ))

    xcto = headers.get("x-content-type-options")
    if xcto is not None and xcto.strip().lower() != "nosniff":
        issues.append(_issue(
            "x-content-type-options-invalid", "X-Content-Type-Options is not nosniff", "low",
            "X-Content-Type-Options is set but not to the only valid value, nosniff.",
            "Set X-Content-Type-Options: nosniff.", {"value": xcto},
        ))

    xfo = headers.get("x-frame-options")
    if xfo is not None and xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
        issues.append(_issue(
            "x-frame-options-invalid", "X-Frame-Options has a non-standard value", "low",
            "X-Frame-Options should be DENY or SAMEORIGIN to reliably stop framing.",
            "Set X-Frame-Options: DENY or SAMEORIGIN (or use CSP frame-ancestors).", {"value": xfo},
        ))

    insecure = [c for c in (cookies or []) if not _cookie_is_secure(c)]
    if insecure:
        issues.append(_issue(
            "insecure-cookies", "Cookies missing Secure or HttpOnly", "low",
            "One or more Set-Cookie headers omit the Secure and/or HttpOnly attributes.",
            "Add Secure and HttpOnly (and SameSite) to session cookies.",
            {"cookies": [c.split(";")[0].split("=")[0] for c in insecure]},
        ))

    samesite_missing = [c for c in (cookies or []) if "samesite" not in c.lower()]
    if samesite_missing:
        issues.append(_issue(
            "cookie-no-samesite", "Cookies missing SameSite", "low",
            "One or more Set-Cookie headers omit the SameSite attribute, weakening CSRF protection.",
            "Add SameSite=Lax (or Strict) to cookies.",
            {"cookies": [c.split(";")[0].split("=")[0] for c in samesite_missing]},
        ))

    # CORS: a wildcard origin combined with credentials is a serious misconfiguration.
    acao = (headers.get("access-control-allow-origin") or "").strip()
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower()
    if acao == "*" and acac == "true":
        issues.append(_issue(
            "cors-credentials-wildcard", "CORS allows any origin with credentials", "high",
            "Access-Control-Allow-Origin is * while credentials are allowed, which usually means the "
            "server reflects the request Origin and exposes authenticated responses to any site.",
            "Never combine Access-Control-Allow-Origin: * with credentials; echo only a trusted allowlist.",
            {"allow_origin": acao},
        ))
    elif acao == "*":
        issues.append(_issue(
            "cors-open", "CORS is open to any origin", "low",
            "Access-Control-Allow-Origin is *, so any website can read non-credentialed responses.",
            "Restrict Access-Control-Allow-Origin to the origins that need cross-origin access.",
            {"allow_origin": acao},
        ))

    referrer = (headers.get("referrer-policy") or "").strip().lower()
    if referrer in ("unsafe-url", "no-referrer-when-downgrade"):
        issues.append(_issue(
            "referrer-policy-unsafe", "Referrer-Policy leaks full URLs", "low",
            f"Referrer-Policy is '{referrer}', which sends full URLs (including paths) to other origins.",
            "Use a tighter policy such as strict-origin-when-cross-origin or no-referrer.",
            {"value": referrer},
        ))

    if headers and "cross-origin-opener-policy" not in headers:
        issues.append(_issue(
            "no-coop", "No Cross-Origin-Opener-Policy", "info",
            "Cross-Origin-Opener-Policy is not set, so the page shares a browsing-context group with "
            "cross-origin openers (a building block for cross-origin isolation).",
            "Set Cross-Origin-Opener-Policy: same-origin where compatible.", {},
        ))

    if "x-powered-by" in headers:
        issues.append(_issue(
            "info-disclosure-x-powered-by", "Server discloses technology via X-Powered-By", "low",
            "The X-Powered-By header reveals backend technology, aiding targeted attacks.",
            "Remove the X-Powered-By header.", {"value": headers["x-powered-by"]},
        ))

    server = headers.get("server", "")
    if re.search(r"\d+\.\d+", server):
        issues.append(_issue(
            "info-disclosure-server-version", "Server header reveals a version", "info",
            "The Server header exposes precise software version information.",
            "Suppress version details in the Server banner.", {"value": server},
        ))

    return issues


def _cookie_is_secure(cookie: str) -> bool:
    lowered = cookie.lower()
    return "secure" in lowered and "httponly" in lowered


def _issue(id_: str, title: str, severity: str, description: str, recommendation: str,
           evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": id_,
        "title": title,
        "severity": severity,
        "description": description,
        "recommendation": recommendation,
        "evidence": evidence,
    }
