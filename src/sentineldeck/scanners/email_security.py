from __future__ import annotations

import base64
import urllib.request
from collections.abc import Callable

from cryptography.hazmat.primitives.serialization import load_der_public_key

from sentineldeck.scanners.dns_lookup import ERROR, resolve

# Resolver signature: (name, record_type) -> (records, status).
Resolver = Callable[[str, str], "tuple[list[str], str]"]
# HTTP fetcher signature: (url) -> body text or None. Injectable for testing.
HttpFetcher = Callable[[str], "str | None"]
USER_AGENT = "SentinelDeck/0.1"

# Best-effort DKIM selector probes. Absence is inconclusive, so DKIM findings
# are always reported with indeterminate confidence.
COMMON_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2",
    "mail", "dkim", "s1", "s2", "mandrill", "zoho", "protonmail", "fm1",
)


def extract_spf_policy(record: str | None) -> str | None:
    if not record:
        return None
    mechanisms = record.lower().split()
    for mechanism in ("-all", "~all", "?all", "+all"):
        if mechanism in mechanisms:
            return mechanism
    return None


def count_spf_lookups(record: str | None) -> int:
    """Count mechanisms that trigger a DNS lookup (RFC 7208 caps this at 10)."""
    if not record:
        return 0
    count = 0
    for token in record.lower().split():
        if token.startswith(("include:", "a:", "mx:", "exists:", "redirect=", "ptr:")):
            count += 1
        elif token in ("a", "mx", "ptr"):
            count += 1
    return count


def extract_dmarc_tag(record: str | None, tag: str) -> str | None:
    if not record:
        return None
    for part in record.split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == tag.lower():
            return value.strip() or None
    return None


def extract_dmarc_policy(record: str | None) -> str | None:
    value = extract_dmarc_tag(record, "p")
    return value.lower() if value else None


def _lookup_versioned(resolver: Resolver, name: str, version_prefix: str) -> dict:
    """Look up a TXT record and detect the one carrying ``version_prefix``."""
    records, status = resolver(name, "TXT")
    matched = [r for r in records if r.lower().replace(" ", "").startswith(version_prefix)]
    return {"present": bool(matched), "record": matched[0] if matched else None, "status": status}


def _http_get(url: str, timeout: int = 10) -> str | None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read(20000).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - a missing policy is just no policy
        return None


def dkim_key_bits(record: str) -> int | None:
    """Decode a DKIM record's public key and return its size in bits."""
    key = extract_dmarc_tag(record, "p")
    if not key:
        return None
    try:
        return getattr(load_der_public_key(base64.b64decode(key.replace(" ", ""))), "key_size", None)
    except Exception:  # noqa: BLE001 - malformed or unusual keys are non-fatal
        return None


def fetch_mta_sts_policy(domain: str, fetcher: HttpFetcher) -> dict:
    """Fetch and parse the MTA-STS policy file served over HTTPS."""
    body = fetcher(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
    if not body:
        return {"fetched": False, "mode": None, "valid": False}
    fields: dict[str, str] = {}
    for line in body.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields.setdefault(key.strip().lower(), value.strip())
    mode = (fields.get("mode") or "").lower() or None
    valid = fields.get("version", "").lower() == "stsv1" and mode in ("enforce", "testing", "none")
    return {"fetched": True, "mode": mode, "valid": valid}


def _probe_dkim(domain: str, resolver: Resolver, selectors: tuple[str, ...]) -> dict:
    found: list[str] = []
    key_bits: int | None = None
    any_error = False
    for selector in selectors:
        records, status = resolver(f"{selector}._domainkey.{domain}", "TXT")
        if status == ERROR:
            any_error = True
        for record in records:
            if "v=dkim1" in record.lower() or "k=rsa" in record.lower() or "p=" in record.lower():
                found.append(selector)
                if key_bits is None:
                    key_bits = dkim_key_bits(record)
                break
    return {
        "present": bool(found),
        "checked_selectors": list(selectors),
        "found_selectors": found,
        "key_bits": key_bits,
        "status": ERROR if (any_error and not found) else "ok",
    }


def analyze_email_security(
    domain: str, resolver: Resolver = resolve, http_fetcher: HttpFetcher = _http_get
) -> dict:
    mx_records, mx_status = resolver(domain, "MX")
    txt_records, txt_status = resolver(domain, "TXT")
    dmarc_records, dmarc_status = resolver(f"_dmarc.{domain}", "TXT")

    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]
    dmarc_policy_records = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]
    spf_record = spf_records[0] if spf_records else None
    dmarc_record = dmarc_policy_records[0] if dmarc_policy_records else None

    # When MTA-STS is advertised in DNS, fetch and validate the HTTPS policy file.
    mta_sts = _lookup_versioned(resolver, f"_mta-sts.{domain}", "v=stsv1")
    if mta_sts["present"]:
        mta_sts["policy"] = fetch_mta_sts_policy(domain, http_fetcher)

    return {
        "mx": {
            "present": bool(mx_records),
            "records": mx_records,
            "status": mx_status,
        },
        "spf": {
            "present": bool(spf_records),
            "records": spf_records,
            "policy": extract_spf_policy(spf_record),
            "lookup_count": count_spf_lookups(spf_record),
            "multiple": len(spf_records) > 1,
            "status": txt_status,
        },
        "dmarc": {
            "present": bool(dmarc_policy_records),
            "records": dmarc_policy_records,
            "policy": extract_dmarc_policy(dmarc_record),
            "pct": extract_dmarc_tag(dmarc_record, "pct"),
            "subdomain_policy": (extract_dmarc_tag(dmarc_record, "sp") or "").lower() or None,
            "rua": extract_dmarc_tag(dmarc_record, "rua"),
            "status": dmarc_status,
        },
        "dkim": _probe_dkim(domain, resolver, COMMON_DKIM_SELECTORS),
        "mta_sts": mta_sts,
        "tls_rpt": _lookup_versioned(resolver, f"_smtp._tls.{domain}", "v=tlsrptv1"),
        "bimi": _lookup_versioned(resolver, f"default._bimi.{domain}", "v=bimi1"),
    }
