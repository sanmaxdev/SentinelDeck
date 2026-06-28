from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from sentineldeck.models import ScanReport
from sentineldeck.remediation import attach_remediations
from sentineldeck.risk.scoring import build_findings, compute_passes, grade, score_findings
from sentineldeck.scanners.archive import archive_history
from sentineldeck.scanners.blocklists import check_blocklists
from sentineldeck.scanners.cloud_assets import analyze_cloud_assets
from sentineldeck.scanners.dns_hygiene import analyze_dns_hygiene
from sentineldeck.scanners.dns_lookup import Resolver, resolve  # noqa: F401 - resolve re-exported for tests
from sentineldeck.scanners.domain import normalize_domain, resolve_domain
from sentineldeck.scanners.domain_intel import analyze_domain_intel
from sentineldeck.scanners.email_security import analyze_email_security
from sentineldeck.scanners.fingerprint import detect_vulnerable_js, fetch_page, fingerprint
from sentineldeck.scanners.http_headers import (
    check_http_redirect,
    check_security_txt,
    evaluate_headers,
    fetch_headers,
    missing_security_headers,
    trace_redirects,
)
from sentineldeck.scanners.ip_intel import analyze_ip_intel
from sentineldeck.scanners.ports import scan_ports
from sentineldeck.scanners.reputation import check_reputation
from sentineldeck.scanners.subdomains import discover_subdomains, fetch_hostsearch
from sentineldeck.scanners.takeover import detect_takeovers
from sentineldeck.scanners.tls import inspect_tls
from sentineldeck.scanners.tls_config import analyze_tls_config
from sentineldeck.scanners.typosquat import detect_typosquats
from sentineldeck.scanners.web_content import analyze_web_content
from sentineldeck.suppressions import apply_suppressions

DEFAULT_TIMEOUT = 10

# Human-readable labels for live scan progress, keyed by the internal probe name.
STAGE_LABELS = {
    "dns": "DNS resolution",
    "http": "HTTP security headers",
    "redirect": "HTTP to HTTPS redirect",
    "security_txt": "security.txt",
    "tls": "TLS certificate",
    "email": "Email authentication (SPF, DKIM, DMARC, MTA-STS)",
    "dns_hygiene": "DNS hygiene (CAA, DNSSEC, NS, IPv6, DANE)",
    "domain_intel": "Domain registration (RDAP)",
    "subdomains": "Certificate-transparency subdomains",
    "page": "Technology fingerprint",
    "redirect_chain": "Redirect chain",
    "typosquat": "Lookalike domains (typosquatting)",
    "reputation": "Threat reputation",
    "archive": "Archive history (Wayback)",
    "tls_config": "TLS configuration",
    "ports": "Open ports (active)",
    "blocklists": "DNS blocklists",
}


def scan_domain(
    target: str,
    timeout: int = DEFAULT_TIMEOUT,
    suppressions: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
    active: bool = False,
) -> ScanReport:
    domain = normalize_domain(target)
    report = ScanReport.empty(domain)

    def _notify(label: str) -> None:
        if progress is not None:
            try:
                progress(label)
            except Exception:  # noqa: BLE001 - progress is cosmetic, never break a scan
                pass

    # A single resolver is shared by the DNS-backed probes so that, on a network
    # where direct port-53 DNS is blocked, the first failure trips its DoH
    # circuit breaker once and the remaining lookups skip straight to DoH.
    resolver = Resolver()

    # Every probe is independent and I/O-bound (DNS, HTTP, TLS, RDAP), so we run
    # them concurrently and the whole scan finishes close to the slowest one.
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            "dns": pool.submit(resolve_domain, domain),
            "http": pool.submit(fetch_headers, domain, timeout),
            "redirect": pool.submit(check_http_redirect, domain, timeout),
            "security_txt": pool.submit(check_security_txt, domain, timeout),
            "tls": pool.submit(inspect_tls, domain, timeout),
            "email": pool.submit(analyze_email_security, domain, resolver),
            "dns_hygiene": pool.submit(analyze_dns_hygiene, domain, resolver),
            "domain_intel": pool.submit(analyze_domain_intel, domain, timeout),
            "subdomains": pool.submit(discover_subdomains, domain, timeout, host_fetcher=fetch_hostsearch),
            "page": pool.submit(fetch_page, domain, timeout),
            "redirect_chain": pool.submit(trace_redirects, domain, timeout),
            "typosquat": pool.submit(detect_typosquats, domain, resolver),
            "reputation": pool.submit(check_reputation, domain),
            "archive": pool.submit(archive_history, domain),
            "tls_config": pool.submit(analyze_tls_config, domain),
            "blocklists": pool.submit(check_blocklists, domain),
        }
        if active:
            futures["ports"] = pool.submit(scan_ports, domain)
        name_by_future = {future: name for name, future in futures.items()}
        results: dict = {}
        # Report each surface as it finishes, so the user sees live progress.
        for future in as_completed(name_by_future):
            name = name_by_future[future]
            results[name] = future.result()
            _notify(STAGE_LABELS.get(name, name))

    # Takeover detection needs the discovered hostnames, so it runs after the
    # concurrent block, reusing the same DoH-aware resolver.
    subdomains = results["subdomains"]
    hosts = subdomains.get("subdomains", []) if subdomains.get("status") == "ok" else []
    if hosts:
        takeover = detect_takeovers(hosts, resolver=resolver, timeout=timeout)
        _notify("Subdomain takeover")
    else:
        takeover = {"status": "skipped", "candidates": [], "checked": 0}

    http = {**results["http"], **results["redirect"], "security_txt": results["security_txt"]}
    headers = http.get("headers", {})
    cookies = http.get("cookies", [])

    # The homepage HTML drives technology fingerprinting, vulnerable-JS detection,
    # and cloud-bucket discovery.
    page = results["page"]
    if page.get("reachable"):
        technologies = {
            "status": "ok",
            "detected": fingerprint(page),
            "vulnerable_js": detect_vulnerable_js(page.get("body", "")),
        }
    else:
        technologies = {"status": "error", "detected": [], "vulnerable_js": []}

    cloud = analyze_cloud_assets(page.get("body", ""))
    if cloud.get("buckets"):
        _notify("Cloud storage exposure")

    web_content = analyze_web_content(domain, page)
    _notify("Web content (links, social, WAF, robots)")

    addresses = results["dns"].get("addresses") or []
    ip_intel = analyze_ip_intel(addresses[0] if addresses else None, timeout)
    if addresses and addresses[0].count(".") == 3:
        reverse = ".".join(reversed(addresses[0].split("."))) + ".in-addr.arpa"
        ptr, _ = resolver(reverse, "PTR")
        ip_intel["hostnames"] = ptr
    _notify("IP intelligence (geo, ASN)")

    dns_hygiene_result = results["dns_hygiene"]
    dns_records = {
        "A": addresses,
        "AAAA": dns_hygiene_result.get("ipv6", {}).get("records", []),
        "MX": results["email"].get("mx", {}).get("records", []),
        "NS": dns_hygiene_result.get("ns", {}).get("records", []),
        "SOA": dns_hygiene_result.get("soa", {}).get("records", []),
        "TXT": dns_hygiene_result.get("txt", {}).get("records", []),
        "CAA": dns_hygiene_result.get("caa", {}).get("records", []),
    }

    report.checks = {
        "dns": results["dns"],
        "http": http,
        "missing_security_headers": missing_security_headers(headers),
        "header_issues": evaluate_headers(headers, cookies),
        "tls": results["tls"],
        "email_security": results["email"],
        "dns_hygiene": results["dns_hygiene"],
        "domain_intel": results["domain_intel"],
        "subdomains": results["subdomains"],
        "takeover": takeover,
        "technologies": technologies,
        "cloud_assets": cloud,
        "redirect_chain": results["redirect_chain"],
        "web_content": web_content,
        "ip_intel": ip_intel,
        "typosquatting": results["typosquat"],
        "reputation": results["reputation"],
        "archive": results["archive"],
        "tls_config": results["tls_config"],
        "ports": results.get("ports", {"status": "skipped", "open": []}),
        "blocklists": results["blocklists"],
        "dns_records": dns_records,
    }
    report.findings = build_findings(report.checks)
    report.checks["passes"] = compute_passes(report.checks)
    attach_remediations(report.findings, domain)
    if suppressions:
        apply_suppressions(report.findings, suppressions)
    report.risk_score = score_findings(report.findings)
    report.grade = grade(report.risk_score)
    return report
