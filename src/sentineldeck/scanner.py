from __future__ import annotations

from sentineldeck.models import ScanReport
from sentineldeck.risk.scoring import build_findings, grade, score_findings
from sentineldeck.scanners.domain import normalize_domain, resolve_domain
from sentineldeck.scanners.email_security import analyze_email_security
from sentineldeck.scanners.http_headers import fetch_headers, missing_security_headers
from sentineldeck.scanners.tls import inspect_tls


def scan_domain(target: str) -> ScanReport:
    domain = normalize_domain(target)
    report = ScanReport.empty(domain)

    dns = resolve_domain(domain)
    http = fetch_headers(domain)
    tls = inspect_tls(domain)
    email_security = analyze_email_security(domain)

    report.checks = {
        "dns": dns,
        "http": http,
        "missing_security_headers": missing_security_headers(http.get("headers", {})),
        "tls": tls,
        "email_security": email_security,
    }
    report.findings = build_findings(report.checks)
    report.risk_score = score_findings(report.findings)
    report.grade = grade(report.risk_score)
    return report
