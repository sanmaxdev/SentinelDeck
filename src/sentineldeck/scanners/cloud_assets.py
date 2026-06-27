"""Passive cloud-storage exposure detection.

Finds references to S3, Google Cloud Storage, and Azure Blob buckets in a
domain's HTML and DNS records, then checks whether each one allows public
listing - a common and high-impact misconfiguration. The public-read check is a
single GET of the bucket's own public URL, the same request a browser makes.
"""
from __future__ import annotations

import re
import urllib.error
import urllib.request

USER_AGENT = "SentinelDeck/0.1"

# (provider, regex) - the first capture group is the bucket name.
_PATTERNS = [
    ("s3", re.compile(r"([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com", re.I)),
    ("s3", re.compile(r"s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])", re.I)),
    ("gcs", re.compile(r"storage\.googleapis\.com/([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])", re.I)),
    ("gcs", re.compile(r"([a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com", re.I)),
    ("azure", re.compile(r"([a-z0-9]{3,24})\.blob\.core\.windows\.net", re.I)),
]


def _bucket_url(provider: str, name: str) -> str:
    if provider == "s3":
        return f"https://{name}.s3.amazonaws.com/"
    if provider == "gcs":
        return f"https://storage.googleapis.com/{name}"
    return f"https://{name}.blob.core.windows.net/?comp=list"


def find_buckets(text: str) -> list[dict]:
    """Return de-duplicated bucket references found in ``text``."""
    seen: dict[tuple[str, str], dict] = {}
    for provider, pattern in _PATTERNS:
        for name in pattern.findall(text or ""):
            key = (provider, name.lower())
            if key not in seen:
                seen[key] = {"provider": provider, "name": name, "url": _bucket_url(provider, name)}
    return list(seen.values())


def _http_get(url: str, timeout: int = 10) -> tuple[int | None, str]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except Exception:  # noqa: BLE001 - unreachable bucket is inconclusive
        return None, ""


def check_public(bucket: dict, fetcher=_http_get) -> str:
    """Return 'public', 'private', or 'unknown' for a bucket's listing access."""
    status, body = fetcher(bucket["url"])
    if status is None:
        return "unknown"
    if status == 200 and ("<ListBucketResult" in body or "<EnumerationResults" in body or "<Contents>" in body):
        return "public"
    if status in (403, 401):
        return "private"
    if status == 200 and bucket["provider"] == "gcs":
        # GCS returns 200 with an XML listing only when public; otherwise 403.
        return "public" if "<ListBucketResult" in body else "private"
    return "private" if status in (403, 404) else "unknown"


def analyze_cloud_assets(text: str, fetcher=_http_get) -> dict:
    """Find cloud buckets referenced in ``text`` and test each for public listing."""
    buckets = find_buckets(text)
    for bucket in buckets:
        bucket["access"] = check_public(bucket, fetcher)
    return {"status": "ok", "buckets": buckets}
