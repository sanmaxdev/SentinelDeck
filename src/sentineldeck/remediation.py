"""Turn a finding into a concrete, copy-paste fix.

Most scanners stop at "you are missing X". SentinelDeck goes one step further:
for every finding it can, it emits the exact DNS record, HTTP header, or config
snippet that resolves it, plus an authoritative reference. The output is a plain
dict so it rides along in the JSON report and renders in the HTML report.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sentineldeck.models import Finding

# A fix is {"title", "snippet", "kind", "references"}. ``kind`` drives syntax
# styling in the report: "dns", "http", "config", or "text".
Fix = dict[str, Any]
Builder = Callable[[Finding, str], "Fix | None"]


def _fix(title: str, snippet: str, kind: str, *references: str) -> Fix:
    return {"title": title, "snippet": snippet.strip(), "kind": kind, "references": list(references)}


# --- HTTP headers -----------------------------------------------------------

def _hsts(finding: Finding, target: str) -> Fix:
    return _fix(
        "Send HSTS on every HTTPS response",
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n\n"
        "# nginx\nadd_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\" always;\n"
        "# apache / litespeed (.htaccess)\nHeader always set Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"",
        "http",
        "RFC 6797",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
    )


def _csp(finding: Finding, target: str) -> Fix:
    return _fix(
        "Start with a strict Content-Security-Policy, then loosen as needed",
        "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'\n\n"
        "# Deploy in report-only mode first to find breakage:\n"
        "Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report",
        "http",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
    )


def _generic_header(finding: Finding, target: str) -> Fix | None:
    header = (finding.evidence or {}).get("checked_header") or finding.id.removeprefix("missing-")
    defaults = {
        "x-content-type-options": "nosniff",
        "x-frame-options": "SAMEORIGIN",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=(), microphone=(), camera=()",
    }
    value = defaults.get(header)
    if not value:
        return None
    return _fix(
        f"Add the {header} header",
        f"{header}: {value}\n\n# nginx\nadd_header {header} \"{value}\" always;",
        "http",
        "https://owasp.org/www-project-secure-headers/",
    )


def _no_https_redirect(finding: Finding, target: str) -> Fix:
    return _fix(
        "Redirect all HTTP traffic to HTTPS with a 301",
        "# nginx\nserver {\n  listen 80;\n  server_name "
        f"{target} www.{target};\n  return 301 https://$host$request_uri;\n}}\n\n"
        "# apache / litespeed (.htaccess)\nRewriteEngine On\n"
        "RewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
        "config",
    )


def _insecure_cookies(finding: Finding, target: str) -> Fix:
    return _fix(
        "Set Secure, HttpOnly, and SameSite on session cookies",
        "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/\n\n"
        "# Tokens read by JavaScript (CSRF) keep Secure + SameSite but omit HttpOnly by design.",
        "http",
        "https://owasp.org/www-community/controls/SecureCookieAttribute",
    )


def _x_powered_by(finding: Finding, target: str) -> Fix:
    return _fix(
        "Stop advertising the backend version",
        "# PHP (php.ini)\nexpose_php = Off\n\n# nginx\nproxy_hide_header X-Powered-By;\n"
        "# apache / litespeed (.htaccess)\nHeader always unset X-Powered-By",
        "config",
        "CWE-200",
    )


def _server_disclosure(finding: Finding, target: str) -> Fix:
    return _fix(
        "Suppress the Server version banner",
        "# nginx\nserver_tokens off;\n\n# apache\nServerTokens Prod\nServerSignature Off",
        "config",
        "CWE-200",
    )


# --- Email authentication ---------------------------------------------------

def _spf_missing(finding: Finding, target: str) -> Fix:
    return _fix(
        "Publish a single SPF TXT record at the apex",
        f"{target}.    IN  TXT  \"v=spf1 include:_spf.your-provider.com -all\"\n\n"
        "# Replace the include with your real sender(s). Use -all once you have confirmed every source.",
        "dns",
        "RFC 7208",
    )


def _spf_weak(finding: Finding, target: str) -> Fix:
    record = ((finding.evidence or {}).get("records") or ["v=spf1 ... ~all"])[0]
    hardened = record.replace("~all", "-all").replace("?all", "-all").replace("+all", "-all")
    return _fix(
        "Move SPF to a hard fail once senders are confirmed",
        f"# from\n{record}\n# to\n{hardened}",
        "dns",
        "RFC 7208",
    )


def _dmarc_missing(finding: Finding, target: str) -> Fix:
    return _fix(
        "Publish DMARC at _dmarc, start at p=none for monitoring",
        f"_dmarc.{target}.    IN  TXT  \"v=DMARC1; p=none; rua=mailto:dmarc@{target}; fo=1\"\n\n"
        "# Watch the aggregate reports, then move p to quarantine and finally reject.",
        "dns",
        "RFC 7489",
    )


def _dmarc_monitor(finding: Finding, target: str) -> Fix:
    return _fix(
        "Raise DMARC enforcement past monitor-only",
        f"# from\nv=DMARC1; p=none; rua=mailto:dmarc@{target}\n"
        f"# to (after reviewing reports)\nv=DMARC1; p=reject; rua=mailto:dmarc@{target}; fo=1",
        "dns",
        "RFC 7489",
    )


def _mx_missing(finding: Finding, target: str) -> Fix:
    return _fix(
        "Publish MX records for your mail provider",
        f"{target}.    IN  MX  10 mail.your-provider.com.\n"
        "# Use the exact host(s) and priorities from your email provider.",
        "dns",
    )


def _caa_missing(finding: Finding, target: str) -> Fix:
    return _fix(
        "Restrict certificate issuance with CAA records",
        f"{target}.    IN  CAA  0 issue \"letsencrypt.org\"\n"
        f"{target}.    IN  CAA  0 issuewild \";\"\n"
        f"{target}.    IN  CAA  0 iodef \"mailto:security@{target}\"\n"
        "# List every CA you actually use; the wildcard \";\" forbids wildcard issuance.",
        "dns",
        "RFC 8659",
    )


def _security_txt(finding: Finding, target: str) -> Fix:
    return _fix(
        "Publish /.well-known/security.txt",
        f"# https://{target}/.well-known/security.txt\n"
        f"Contact: mailto:security@{target}\nExpires: 2027-01-01T00:00:00Z\n"
        f"Policy: https://{target}/security-policy\nPreferred-Languages: en",
        "text",
        "RFC 9116",
    )


def _takeover(finding: Finding, target: str) -> Fix:
    evidence = finding.evidence or {}
    host = evidence.get("subdomain", "the-subdomain." + target)
    cname = evidence.get("cname", "the-dangling-target")
    service = evidence.get("service", "the service")
    return _fix(
        "Remove the dangling record or reclaim the resource",
        f"# Option 1 - delete the dangling CNAME:\n"
        f"{host}.    IN  CNAME  {cname}.    # <-- remove this record\n\n"
        f"# Option 2 - re-create the {service} resource so the name is no longer claimable.",
        "dns",
        "https://owasp.org/www-community/attacks/Subdomain_takeover",
    )


def _dnssec(finding: Finding, target: str) -> Fix:
    return _fix(
        "Enable DNSSEC at your DNS provider and registrar",
        "1. Turn on DNSSEC signing in your DNS host (one click at most managed providers).\n"
        "2. Copy the generated DS record into your registrar.\n"
        "3. Verify with: dig +dnssec DS " + target,
        "text",
        "RFC 4033",
    )


# --- Dispatch ---------------------------------------------------------------

_BUILDERS: dict[str, Builder] = {
    "missing-strict-transport-security": _hsts,
    "missing-content-security-policy": _csp,
    "no-https-redirect": _no_https_redirect,
    "insecure-cookies": _insecure_cookies,
    "info-disclosure-x-powered-by": _x_powered_by,
    "info-disclosure-server": _server_disclosure,
    "spf-missing": _spf_missing,
    "spf-weak-policy": _spf_weak,
    "dmarc-missing": _dmarc_missing,
    "dmarc-monitor-only": _dmarc_monitor,
    "mx-missing": _mx_missing,
    "caa-missing": _caa_missing,
    "no-security-txt": _security_txt,
    "dnssec-disabled": _dnssec,
}


def remediation_for(finding: Finding, target: str) -> Fix | None:
    """Return a concrete fix for ``finding`` on ``target``, or ``None``."""
    builder = _BUILDERS.get(finding.id)
    if builder is not None:
        return builder(finding, target)
    if finding.id.startswith("missing-"):
        return _generic_header(finding, target)
    if finding.id.startswith("subdomain-takeover"):
        return _takeover(finding, target)
    return None


def attach_remediations(findings: list[Finding], target: str) -> None:
    """Populate ``finding.remediation`` in place for every finding with a fix."""
    for finding in findings:
        finding.remediation = remediation_for(finding, target)
