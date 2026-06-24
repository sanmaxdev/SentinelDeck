from __future__ import annotations

from sentineldeck.models import Finding
from sentineldeck.scanners.http_headers import SECURITY_HEADERS

SEVERITY_POINTS = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 0}


def grade(score: int) -> str:
    if score >= 80:
        return "F"
    if score >= 60:
        return "D"
    if score >= 40:
        return "C"
    if score >= 20:
        return "B"
    return "A"


def score_findings(findings: list[Finding]) -> int:
    return min(100, sum(SEVERITY_POINTS.get(f.severity.lower(), 0) for f in findings))


def build_findings(checks: dict) -> list[Finding]:
    findings: list[Finding] = []

    dns = checks.get("dns", {})
    if not dns.get("resolved"):
        findings.append(Finding(
            id="dns-unresolved",
            title="Domain does not resolve",
            severity="high",
            description="The supplied domain could not be resolved through DNS.",
            recommendation="Verify the domain spelling and DNS zone configuration.",
            evidence=dns,
        ))

    http = checks.get("http", {})
    if not http.get("reachable"):
        findings.append(Finding(
            id="https-unreachable",
            title="HTTPS endpoint is unreachable",
            severity="medium",
            description="SentinelDeck could not reach the HTTPS endpoint for this domain.",
            recommendation="Confirm the web server is online and port 443 is serving the correct host.",
            evidence={"error": http.get("error")},
        ))
    else:
        missing = checks.get("missing_security_headers", {})
        for header, advice in missing.items():
            severity = "medium" if header in {"strict-transport-security", "content-security-policy"} else "low"
            findings.append(Finding(
                id=f"missing-{header}",
                title=f"Missing {header} header",
                severity=severity,
                description=f"The HTTPS response does not include {header}.",
                recommendation=advice,
                evidence={"checked_header": header, "known_headers": sorted(SECURITY_HEADERS)},
            ))

    tls = checks.get("tls", {})
    if not tls.get("valid"):
        findings.append(Finding(
            id="tls-invalid",
            title="TLS certificate check failed",
            severity="high",
            description="The TLS certificate could not be validated or inspected.",
            recommendation="Install a valid certificate from a trusted CA and verify the full chain.",
            evidence={"error": tls.get("error")},
        ))
    elif tls.get("days_remaining") is not None and tls["days_remaining"] < 30:
        findings.append(Finding(
            id="tls-expiring-soon",
            title="TLS certificate expires soon",
            severity="medium",
            description="The TLS certificate has less than 30 days remaining.",
            recommendation="Renew the certificate before expiry to avoid downtime and browser warnings.",
            evidence={"days_remaining": tls.get("days_remaining"), "expires_at": tls.get("expires_at")},
        ))

    email = checks.get("email_security", {})
    if email:
        mx = email.get("mx", {})
        spf = email.get("spf", {})
        dmarc = email.get("dmarc", {})
        if not mx.get("present"):
            findings.append(Finding(
                id="mx-missing",
                title="No MX records found",
                severity="medium",
                description="The domain does not publish MX records for receiving email.",
                recommendation="Publish correct MX records if the domain sends or receives business email.",
                evidence=mx,
            ))
        if not spf.get("present"):
            findings.append(Finding(
                id="spf-missing",
                title="SPF record is missing",
                severity="medium",
                description="The domain does not publish an SPF record to restrict allowed mail senders.",
                recommendation="Add an SPF TXT record that lists approved sending services and ends with -all or ~all.",
                evidence=spf,
            ))
        elif spf.get("policy") in {None, "+all", "?all", "~all"}:
            findings.append(Finding(
                id="spf-weak-policy",
                title="SPF policy is weak",
                severity="low",
                description="The SPF record does not use a strict fail policy.",
                recommendation="Review sending sources and move toward a stricter -all policy when safe.",
                evidence=spf,
            ))
        if not dmarc.get("present"):
            findings.append(Finding(
                id="dmarc-missing",
                title="DMARC record is missing",
                severity="medium",
                description="The domain does not publish DMARC, making spoofed-email handling unclear.",
                recommendation="Add a DMARC TXT record at _dmarc with at least p=none for monitoring, then move to quarantine or reject.",
                evidence=dmarc,
            ))
        elif dmarc.get("policy") in {None, "none"}:
            findings.append(Finding(
                id="dmarc-monitor-only",
                title="DMARC is monitor-only",
                severity="low",
                description="The domain publishes DMARC but does not request enforcement.",
                recommendation="After monitoring legitimate mail flow, move DMARC policy to quarantine or reject.",
                evidence=dmarc,
            ))

    return findings
