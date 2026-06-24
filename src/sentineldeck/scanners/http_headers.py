from __future__ import annotations

import re
import urllib.error
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
            return result
        except urllib.error.HTTPError as exc:
            # Some servers reject HEAD with 405/501 - retry once with GET.
            if method == "HEAD" and exc.code in (405, 501):
                continue
            result["reachable"] = True
            result["status"] = exc.code
            result["headers"] = {key.lower(): value for key, value in exc.headers.items()}
            return result
        except Exception as exc:  # noqa: BLE001 - scanner should return structured failure
            result["error"] = str(exc)
            return result
    return result


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


def missing_security_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name: advice for name, advice in SECURITY_HEADERS.items() if name not in headers}


def evaluate_headers(headers: dict[str, str]) -> list[dict[str, Any]]:
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

    return issues


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
