from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from sentineldeck.models import ScanReport
from sentineldeck.risk.scoring import build_findings, grade, score_findings
from sentineldeck.scanners.domain import normalize_domain, resolve_domain
from sentineldeck.scanners.email_security import analyze_email_security
from sentineldeck.scanners.http_headers import (
    check_http_redirect,
    evaluate_headers,
    fetch_headers,
    missing_security_headers,
)
from sentineldeck.scanners.tls import inspect_tls

DEFAULT_TIMEOUT = 10


def scan_domain(target: str, timeout: int = DEFAULT_TIMEOUT) -> ScanReport:
    domain = normalize_domain(target)
    report = ScanReport.empty(domain)

    # The scanners are independent and I/O-bound (DNS, HTTP, TLS, more DNS),
    # so run them concurrently to keep total scan time close to the slowest one.
    with ThreadPoolExecutor(max_workers=5) as pool:
        dns_future = pool.submit(resolve_domain, domain)
        http_future = pool.submit(fetch_headers, domain, timeout)
        redirect_future = pool.submit(check_http_redirect, domain, timeout)
        tls_future = pool.submit(inspect_tls, domain, timeout)
        email_future = pool.submit(analyze_email_security, domain)

        dns = dns_future.result()
        http = {**http_future.result(), **redirect_future.result()}
        tls = tls_future.result()
        email_security = email_future.result()

    headers = http.get("headers", {})
    report.checks = {
        "dns": dns,
        "http": http,
        "missing_security_headers": missing_security_headers(headers),
        "header_issues": evaluate_headers(headers),
        "tls": tls,
        "email_security": email_security,
    }
    report.findings = build_findings(report.checks)
    report.risk_score = score_findings(report.findings)
    report.grade = grade(report.risk_score)
    return report
