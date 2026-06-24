from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

SECURITY_HEADERS = {
    "strict-transport-security": "Add HSTS to force browsers to use HTTPS.",
    "content-security-policy": "Add a Content-Security-Policy to reduce XSS and injection impact.",
    "x-content-type-options": "Add X-Content-Type-Options: nosniff.",
    "x-frame-options": "Add X-Frame-Options or frame-ancestors to reduce clickjacking risk.",
    "referrer-policy": "Add Referrer-Policy to limit sensitive URL leakage.",
    "permissions-policy": "Add Permissions-Policy to restrict browser features.",
}


def fetch_headers(domain: str, timeout: int = 10) -> dict[str, Any]:
    result: dict[str, Any] = {
        "reachable": False,
        "url": f"https://{domain}",
        "status": None,
        "headers": {},
        "error": None,
    }
    request = urllib.request.Request(result["url"], method="HEAD", headers={"User-Agent": "SentinelDeck/0.1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            result["reachable"] = True
            result["status"] = response.status
            result["headers"] = {key.lower(): value for key, value in response.headers.items()}
    except urllib.error.HTTPError as exc:
        result["reachable"] = True
        result["status"] = exc.code
        result["headers"] = {key.lower(): value for key, value in exc.headers.items()}
    except Exception as exc:  # noqa: BLE001 - scanner should return structured failure
        result["error"] = str(exc)
    return result


def missing_security_headers(headers: dict[str, str]) -> dict[str, str]:
    return {name: advice for name, advice in SECURITY_HEADERS.items() if name not in headers}
