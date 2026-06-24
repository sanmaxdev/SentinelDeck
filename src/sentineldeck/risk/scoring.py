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

    return findings
