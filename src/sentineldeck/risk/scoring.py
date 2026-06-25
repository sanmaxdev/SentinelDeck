from __future__ import annotations

from sentineldeck.models import Finding
from sentineldeck.scanners.http_headers import SECURITY_HEADERS
from sentineldeck.scanners.tls import WEAK_SIGNATURE_HASHES

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
            if f.confidence != "indeterminate" and not f.suppressed
        ),
    )


def _is_scored(finding: Finding) -> bool:
    return (
        finding.confidence != "indeterminate"
        and not finding.suppressed
        and SEVERITY_POINTS.get(finding.severity.lower(), 0) > 0
    )


def quick_wins(findings: list[Finding]) -> list[Finding]:
    """Scored findings ordered by how much risk each one removes, highest first."""
    return sorted(
        (f for f in findings if _is_scored(f)),
        key=lambda f: SEVERITY_POINTS.get(f.severity.lower(), 0),
        reverse=True,
    )


def path_to_grade(findings: list[Finding], target_grade: str = "A") -> list[Finding]:
    """The smallest set of fixes that reaches ``target_grade``.

    Grades are score bands, so we greedily retire the highest-impact findings
    until the remaining score drops into the target band. Returns the findings to
    fix, in fix order; empty when the target is already met.
    """
    ceiling = _grade_ceiling(target_grade)
    remaining = score_findings(findings)
    plan: list[Finding] = []
    for finding in quick_wins(findings):
        if remaining <= ceiling:
            break
        remaining -= SEVERITY_POINTS.get(finding.severity.lower(), 0)
        plan.append(finding)
    return plan


def _grade_ceiling(target_grade: str) -> int:
    # Highest score that still earns the target grade (mirrors grade()).
    return {"A": 19, "B": 39, "C": 59, "D": 79, "F": 100}.get(target_grade.upper(), 19)


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

        security_txt = http.get("security_txt", {})
        if security_txt and security_txt.get("present") is False:
            findings.append(Finding(
                id="no-security-txt",
                title="No security.txt published",
                severity="info",
                description="The site does not publish a /.well-known/security.txt contact policy (RFC 9116).",
                recommendation="Publish a security.txt with a security contact and disclosure policy.",
                evidence={"url": security_txt.get("url")},
            ))

    findings.extend(_tls_findings(checks.get("tls", {})))

    email = checks.get("email_security", {})
    if email:
        findings.extend(_email_findings(email))

    dns_hygiene = checks.get("dns_hygiene", {})
    if dns_hygiene:
        findings.extend(_dns_hygiene_findings(dns_hygiene))

    domain_intel = checks.get("domain_intel", {})
    if domain_intel:
        findings.extend(_domain_intel_findings(domain_intel))

    subdomains = checks.get("subdomains", {})
    if subdomains:
        findings.extend(_subdomain_findings(subdomains))

    takeover = checks.get("takeover", {})
    if takeover:
        findings.extend(_takeover_findings(takeover))

    return findings


def _takeover_findings(takeover: dict) -> list[Finding]:
    findings: list[Finding] = []
    for candidate in takeover.get("candidates", []):
        host = candidate.get("subdomain", "")
        service = candidate.get("service", "a third-party service")
        cname = candidate.get("cname", "")
        findings.append(Finding(
            id=f"subdomain-takeover:{host}",
            title=f"Possible subdomain takeover: {host}",
            severity="high",
            description=(
                f"{host} points via CNAME to {service} ({cname}), but the target serves an "
                "unclaimed-resource page. An attacker could register that resource and serve "
                "content from this subdomain."
            ),
            recommendation=(
                "Remove the dangling DNS record, or reclaim the resource on the provider so it "
                "can no longer be taken over."
            ),
            evidence=candidate,
        ))
    return findings


def _tls_findings(tls: dict) -> list[Finding]:
    findings: list[Finding] = []
    if not tls:
        return findings

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

    # Certificate-quality checks apply to whatever leaf the server presented,
    # whether or not the chain validated.
    key_type, key_bits = tls.get("key_type"), tls.get("key_bits")
    if key_bits is not None and (
        (key_type == "RSA" and key_bits < 2048) or (key_type in ("EC", "DSA") and key_bits < 256)
    ):
        findings.append(Finding(
            id="tls-weak-key",
            title="TLS certificate uses a weak key",
            severity="high",
            description=f"The certificate public key is {key_type} {key_bits}-bit, below modern strength.",
            recommendation="Reissue the certificate with at least an RSA-2048 or ECDSA-P256 key.",
            evidence={"key_type": key_type, "key_bits": key_bits},
        ))

    signature = tls.get("signature_algorithm")
    if signature in WEAK_SIGNATURE_HASHES:
        findings.append(Finding(
            id="tls-weak-signature",
            title="TLS certificate uses a weak signature",
            severity="high",
            description=f"The certificate is signed with {signature.upper()}, which is cryptographically broken.",
            recommendation="Reissue the certificate with a SHA-256 (or stronger) signature.",
            evidence={"signature_algorithm": signature},
        ))

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

    # Advanced inbound-mail hardening, only relevant when the domain receives mail.
    mta_sts = email.get("mta_sts", {})
    tls_rpt = email.get("tls_rpt", {})
    bimi = email.get("bimi", {})

    if mx.get("present") and mta_sts and not mta_sts.get("present"):
        findings.append(Finding(
            id="mta-sts-missing",
            title="MTA-STS is not configured",
            severity="info",
            description="The domain does not publish MTA-STS, so sending servers cannot require TLS for inbound mail.",
            recommendation="Publish an MTA-STS policy to require TLS for inbound email.",
            evidence=mta_sts,
            confidence=_email_confidence(mta_sts),
        ))

    if mx.get("present") and tls_rpt and not tls_rpt.get("present"):
        findings.append(Finding(
            id="tls-rpt-missing",
            title="No SMTP TLS Reporting (TLS-RPT)",
            severity="info",
            description="No TLS-RPT record is published, so you receive no reports about inbound TLS failures.",
            recommendation="Publish a TLS-RPT record to receive inbound SMTP TLS failure reports.",
            evidence=tls_rpt,
            confidence=_email_confidence(tls_rpt),
        ))

    if bimi and not bimi.get("present") and dmarc.get("policy") in {"quarantine", "reject"}:
        findings.append(Finding(
            id="bimi-missing",
            title="No BIMI record published",
            severity="info",
            description=(
                "DMARC is enforced but no BIMI record is published, so your logo "
                "will not show in supporting inboxes."
            ),
            recommendation="Publish a BIMI record (and a VMC) to display your brand logo in supporting mail clients.",
            evidence=bimi,
            confidence=_email_confidence(bimi),
        ))

    return findings


def _dns_hygiene_findings(hygiene: dict) -> list[Finding]:
    findings: list[Finding] = []
    caa = hygiene.get("caa", {})
    dnssec = hygiene.get("dnssec", {})

    if not caa.get("present"):
        findings.append(Finding(
            id="caa-missing",
            title="No CAA records",
            severity="low",
            description="Without CAA records, any certificate authority may issue certificates for the domain.",
            recommendation="Publish CAA records naming only the CAs you use.",
            evidence=caa,
            confidence="indeterminate" if caa.get("status") == "error" else "confirmed",
        ))

    if not dnssec.get("enabled"):
        findings.append(Finding(
            id="dnssec-disabled",
            title="DNSSEC is not enabled",
            severity="info",
            description="DNSSEC is not enabled, so DNS responses for this domain are not cryptographically signed.",
            recommendation="Enable DNSSEC at your DNS provider and registrar to protect against DNS spoofing.",
            evidence=dnssec,
            confidence="indeterminate" if dnssec.get("status") == "error" else "confirmed",
        ))

    return findings


def _domain_intel_findings(intel: dict) -> list[Finding]:
    findings: list[Finding] = []
    if intel.get("status") != "ok":
        return findings

    expires_in = intel.get("expires_in_days")
    if expires_in is not None and expires_in < 30:
        findings.append(Finding(
            id="domain-expiring-soon",
            title="Domain registration expires soon",
            severity="medium",
            description=f"The domain registration expires in {expires_in} days.",
            recommendation="Renew the domain registration and enable auto-renew to avoid losing the domain.",
            evidence={"expires": intel.get("expires"), "registrar": intel.get("registrar")},
        ))

    age_days = intel.get("age_days")
    if age_days is not None and age_days < 30:
        findings.append(Finding(
            id="domain-newly-registered",
            title="Domain was registered very recently",
            severity="low",
            description=f"The domain was registered {age_days} days ago; new domains are common in phishing.",
            recommendation="Confirm this domain is legitimate and expected for the organisation.",
            evidence={"created": intel.get("created"), "registrar": intel.get("registrar")},
        ))

    return findings


def _subdomain_findings(subdomains: dict) -> list[Finding]:
    findings: list[Finding] = []
    if subdomains.get("status") != "ok":
        return findings

    count = subdomains.get("count", 0)
    if count > 0:
        findings.append(Finding(
            id="subdomains-discovered",
            title=f"{count} subdomain(s) found in certificate transparency logs",
            severity="info",
            description=(
                "Certificate transparency logs publicly record every hostname issued a "
                "certificate. These make up the attack surface beyond the scanned host."
            ),
            recommendation="Review the list and retire or protect any host that should not be public.",
            evidence={
                "count": count,
                "sample": subdomains.get("subdomains", [])[:25],
                "source": subdomains.get("source"),
            },
        ))

    sensitive = subdomains.get("sensitive", [])
    if sensitive:
        findings.append(Finding(
            id="sensitive-subdomains-exposed",
            title="Potentially sensitive subdomains are publicly visible",
            severity="low",
            description=(
                "Subdomains named like dev, staging, admin, or vpn suggest non-production or "
                "internal systems that are exposed in certificate transparency logs."
            ),
            recommendation="Confirm these hosts are meant to be public; restrict or take down any that are not.",
            evidence={"subdomains": sensitive},
        ))

    return findings
