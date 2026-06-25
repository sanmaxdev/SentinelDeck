from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from sentineldeck.models import ScanReport
from sentineldeck.risk.scoring import build_findings, grade, score_findings
from sentineldeck.scanners.dns_hygiene import analyze_dns_hygiene
from sentineldeck.scanners.dns_lookup import Resolver, resolve  # noqa: F401 - resolve re-exported for tests
from sentineldeck.scanners.domain import normalize_domain, resolve_domain
from sentineldeck.scanners.domain_intel import analyze_domain_intel
from sentineldeck.scanners.email_security import analyze_email_security
from sentineldeck.scanners.http_headers import (
    check_http_redirect,
    check_security_txt,
    evaluate_headers,
    fetch_headers,
    missing_security_headers,
)
from sentineldeck.scanners.tls import inspect_tls

DEFAULT_TIMEOUT = 10


def scan_domain(target: str, timeout: int = DEFAULT_TIMEOUT) -> ScanReport:
    domain = normalize_domain(target)
    report = ScanReport.empty(domain)

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
        }
        results = {name: future.result() for name, future in futures.items()}

    http = {**results["http"], **results["redirect"], "security_txt": results["security_txt"]}
    headers = http.get("headers", {})
    cookies = http.get("cookies", [])

    report.checks = {
        "dns": results["dns"],
        "http": http,
        "missing_security_headers": missing_security_headers(headers),
        "header_issues": evaluate_headers(headers, cookies),
        "tls": results["tls"],
        "email_security": results["email"],
        "dns_hygiene": results["dns_hygiene"],
        "domain_intel": results["domain_intel"],
    }
    report.findings = build_findings(report.checks)
    report.risk_score = score_findings(report.findings)
    report.grade = grade(report.risk_score)
    return report
