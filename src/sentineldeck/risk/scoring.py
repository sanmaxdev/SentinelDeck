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
    # Indeterminate findings are surfaced for context but never counted, so an
    # inconclusive check can never inflate a client's risk score.
    return min(
        100,
        sum(
            SEVERITY_POINTS.get(f.severity.lower(), 0)
            for f in findings
            if f.confidence != "indeterminate"
        ),
    )


def _email_confidence(section: dict) -> str:
    return "indeterminate" if section.get("status") == "error" else "confirmed"


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
        if http.get("https_redirect") is False:
            findings.append(Finding(
                id="no-https-redirect",
                title="HTTP does not redirect to HTTPS",
                severity="medium",
                description="Plain HTTP requests are not redirected to HTTPS, leaving traffic exposed.",
                recommendation="Configure a 301 redirect from http:// to https:// for all paths.",
                evidence={"http_status": http.get("http_status")},
            ))
        for issue in checks.get("header_issues", []):
            findings.append(Finding(
                id=issue["id"],
                title=issue["title"],
                severity=issue["severity"],
                description=issue["description"],
                recommendation=issue["recommendation"],
                evidence=issue.get("evidence", {}),
            ))
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
        reason = tls.get("reason")
        title, recommendation = _tls_failure_copy(reason)
        findings.append(Finding(
            id=f"tls-{reason}" if reason else "tls-invalid",
            title=title,
            severity="high",
            description="The TLS certificate could not be validated as trusted for this host.",
            recommendation=recommendation,
            evidence={
                "error": tls.get("error"),
                "reason": reason,
                "expires_at": tls.get("expires_at"),
                "days_remaining": tls.get("days_remaining"),
            },
        ))
    else:
        if tls.get("expired"):
            findings.append(Finding(
                id="tls-expired",
                title="TLS certificate has expired",
                severity="high",
                description="The TLS certificate is past its expiry date and browsers will reject it.",
                recommendation="Renew and reinstall the certificate immediately to restore trusted HTTPS.",
                evidence={"days_remaining": tls.get("days_remaining"), "expires_at": tls.get("expires_at")},
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
        protocol = tls.get("protocol")
        if protocol and tls.get("protocol_outdated"):
            findings.append(Finding(
                id="tls-outdated-protocol",
                title="Outdated TLS protocol negotiated",
                severity="medium",
                description=f"The server negotiated {protocol}, which is deprecated and insecure.",
                recommendation="Disable TLS 1.0/1.1 and require TLS 1.2 or higher.",
                evidence={"protocol": protocol},
            ))

    email = checks.get("email_security", {})
    if email:
        findings.extend(_email_findings(email))

    return findings


def _tls_failure_copy(reason: str | None) -> tuple[str, str]:
    table = {
        "expired": (
            "TLS certificate has expired",
            "Renew and reinstall the certificate immediately to restore trusted HTTPS.",
        ),
        "self-signed": (
            "TLS certificate is self-signed",
            "Replace the self-signed certificate with one from a trusted certificate authority.",
        ),
        "hostname-mismatch": (
            "TLS certificate does not match the hostname",
            "Issue a certificate whose subject or SAN list covers this exact hostname.",
        ),
        "untrusted": (
            "TLS certificate chain is not trusted",
            "Install the full certificate chain from a trusted CA, including intermediates.",
        ),
        "unreachable": (
            "TLS service is unreachable",
            "Confirm the server is online and listening for TLS on port 443.",
        ),
    }
    return table.get(reason or "", (
        "TLS certificate check failed",
        "Install a valid certificate from a trusted CA and verify the full chain.",
    ))


def _email_findings(email: dict) -> list[Finding]:
    findings: list[Finding] = []
    mx = email.get("mx", {})
    spf = email.get("spf", {})
    dmarc = email.get("dmarc", {})
    dkim = email.get("dkim", {})

    if not mx.get("present"):
        findings.append(Finding(
            id="mx-missing",
            title="No MX records found",
            severity="medium",
            description="The domain does not publish MX records for receiving email.",
            recommendation="Publish correct MX records if the domain sends or receives business email.",
            evidence=mx,
            confidence=_email_confidence(mx),
        ))

    if not spf.get("present"):
        findings.append(Finding(
            id="spf-missing",
            title="SPF record is missing",
            severity="medium",
            description="The domain does not publish an SPF record to restrict allowed mail senders.",
            recommendation="Add an SPF TXT record that lists approved sending services and ends with -all or ~all.",
            evidence=spf,
            confidence=_email_confidence(spf),
        ))
    else:
        if spf.get("multiple"):
            findings.append(Finding(
                id="spf-multiple-records",
                title="Multiple SPF records published",
                severity="medium",
                description="More than one SPF record exists; receivers treat this as a permerror and ignore SPF.",
                recommendation="Merge all sending sources into a single SPF TXT record.",
                evidence=spf,
            ))
        if spf.get("lookup_count", 0) > 10:
            findings.append(Finding(
                id="spf-too-many-lookups",
                title="SPF exceeds the 10 DNS-lookup limit",
                severity="medium",
                description="The SPF record requires more than 10 DNS lookups, causing a permerror for receivers.",
                recommendation="Flatten includes or remove unused sources to stay within 10 lookups.",
                evidence={"lookup_count": spf.get("lookup_count")},
            ))
        if spf.get("policy") in {None, "+all", "?all", "~all"}:
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
            recommendation=(
                "Add a DMARC TXT record at _dmarc with at least p=none for monitoring, "
                "then move to quarantine or reject."
            ),
            evidence=dmarc,
            confidence=_email_confidence(dmarc),
        ))
    else:
        if dmarc.get("policy") in {None, "none"}:
            findings.append(Finding(
                id="dmarc-monitor-only",
                title="DMARC is monitor-only",
                severity="low",
                description="The domain publishes DMARC but does not request enforcement.",
                recommendation="After monitoring legitimate mail flow, move DMARC policy to quarantine or reject.",
                evidence=dmarc,
            ))
        pct = dmarc.get("pct")
        if pct is not None and str(pct).isdigit() and int(pct) < 100:
            findings.append(Finding(
                id="dmarc-partial-coverage",
                title="DMARC enforcement is partial",
                severity="low",
                description=f"DMARC applies its policy to only {pct}% of mail (pct<100).",
                recommendation="Raise pct to 100 once legitimate mail flow is confirmed.",
                evidence=dmarc,
            ))

    if dkim and not dkim.get("present"):
        findings.append(Finding(
            id="dkim-not-detected",
            title="No DKIM signature detected",
            severity="info",
            description="No DKIM key was found at common selectors; the domain may sign with a custom selector.",
            recommendation="Confirm DKIM is configured for every sending service and note the selector in use.",
            evidence=dkim,
            confidence="indeterminate",
        ))

    return findings
