from __future__ import annotations

from collections.abc import Callable

from sentineldeck.scanners.dns_lookup import ERROR, resolve

# Resolver signature: (name, record_type) -> (records, status).
Resolver = Callable[[str, str], "tuple[list[str], str]"]

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


def _probe_dkim(domain: str, resolver: Resolver, selectors: tuple[str, ...]) -> dict:
    found: list[str] = []
    any_error = False
    for selector in selectors:
        records, status = resolver(f"{selector}._domainkey.{domain}", "TXT")
        if status == ERROR:
            any_error = True
        if any("v=dkim1" in r.lower() or "k=rsa" in r.lower() or "p=" in r.lower() for r in records):
            found.append(selector)
    return {
        "present": bool(found),
        "checked_selectors": list(selectors),
        "found_selectors": found,
        "status": ERROR if (any_error and not found) else "ok",
    }


def analyze_email_security(domain: str, resolver: Resolver = resolve) -> dict:
    mx_records, mx_status = resolver(domain, "MX")
    txt_records, txt_status = resolver(domain, "TXT")
    dmarc_records, dmarc_status = resolver(f"_dmarc.{domain}", "TXT")

    spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]
    dmarc_policy_records = [r for r in dmarc_records if r.lower().startswith("v=dmarc1")]
    spf_record = spf_records[0] if spf_records else None
    dmarc_record = dmarc_policy_records[0] if dmarc_policy_records else None

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
        "mta_sts": _lookup_versioned(resolver, f"_mta-sts.{domain}", "v=stsv1"),
        "tls_rpt": _lookup_versioned(resolver, f"_smtp._tls.{domain}", "v=tlsrptv1"),
        "bimi": _lookup_versioned(resolver, f"default._bimi.{domain}", "v=bimi1"),
    }
