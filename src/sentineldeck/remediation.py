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


def _mta_sts(finding: Finding, target: str) -> Fix:
    return _fix(
        "Publish MTA-STS: a DNS record plus a policy file served over HTTPS",
        f"# 1) DNS TXT record\n_mta-sts.{target}.    IN  TXT  \"v=STSv1; id=20260101000000\"\n\n"
        f"# 2) https://mta-sts.{target}/.well-known/mta-sts.txt\n"
        f"version: STSv1\nmode: enforce\nmx: mail.{target}\nmax_age: 604800",
        "dns",
        "RFC 8461",
    )


def _tls_rpt(finding: Finding, target: str) -> Fix:
    return _fix(
        "Publish a TLS-RPT record to receive inbound TLS failure reports",
        f"_smtp._tls.{target}.    IN  TXT  \"v=TLSRPTv1; rua=mailto:tlsrpt@{target}\"",
        "dns",
        "RFC 8460",
    )


def _bimi(finding: Finding, target: str) -> Fix:
    return _fix(
        "Publish a BIMI record pointing at your logo",
        f"default._bimi.{target}.    IN  TXT  \"v=BIMI1; l=https://{target}/bimi-logo.svg; a=https://{target}/vmc.pem\"\n"
        "# The logo must be a square SVG Tiny PS; a VMC (a=) is required by Gmail and others.",
        "dns",
        "https://bimigroup.org/",
    )


def _single_ns(finding: Finding, target: str) -> Fix:
    return _fix(
        "Add at least one more nameserver",
        f"# Use two or more nameservers, ideally on separate networks:\n"
        f"{target}.    IN  NS  ns1.your-dns-provider.example.\n"
        f"{target}.    IN  NS  ns2.your-dns-provider.example.",
        "dns",
    )


def _no_ipv6(finding: Finding, target: str) -> Fix:
    return _fix(
        "Publish AAAA records for IPv6",
        f"{target}.    IN  AAAA  2001:db8::1    # replace with your server's IPv6 address",
        "dns",
    )


def _dane(finding: Finding, target: str) -> Fix:
    return _fix(
        "Publish a TLSA record (requires DNSSEC)",
        f"_443._tcp.{target}.    IN  TLSA  3 1 1 <sha256-of-the-cert-public-key>\n"
        "# 3 1 1 = DANE-EE, SubjectPublicKeyInfo, SHA-256. Generate the hash from your leaf cert.",
        "dns",
        "RFC 6698",
    )


def _dkim_weak(finding: Finding, target: str) -> Fix:
    return _fix(
        "Rotate the DKIM key to 2048-bit RSA",
        "openssl genrsa -out dkim.key 2048\n"
        "openssl rsa -in dkim.key -pubout -outform der | openssl base64 -A\n\n"
        f"selector2._domainkey.{target}.  IN  TXT  \"v=DKIM1; k=rsa; p=<new-base64-key>\"",
        "dns",
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


def _cors_wildcard(finding: Finding, target: str) -> Fix:
    return _fix(
        "Replace the wildcard CORS origin with a trusted allowlist",
        "# Never pair a wildcard origin with credentials. Echo only trusted origins:\n"
        f"Access-Control-Allow-Origin: https://app.{target}\n"
        "Access-Control-Allow-Credentials: true   # only for the allowlisted origin",
        "http",
        "https://developer.mozilla.org/docs/Web/HTTP/CORS",
    )


def _cors_open(finding: Finding, target: str) -> Fix:
    return _fix(
        "Restrict the CORS origin",
        f"Access-Control-Allow-Origin: https://app.{target}    # not *",
        "http",
    )


def _referrer_unsafe(finding: Finding, target: str) -> Fix:
    return _fix(
        "Tighten the Referrer-Policy",
        "Referrer-Policy: strict-origin-when-cross-origin",
        "http",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
    )


def _hsts_preload(finding: Finding, target: str) -> Fix:
    return _fix(
        "Make HSTS preload-eligible",
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\n"
        "# then submit the domain at https://hstspreload.org",
        "http",
        "RFC 6797",
    )


def _cookie_samesite(finding: Finding, target: str) -> Fix:
    return _fix(
        "Add SameSite to cookies",
        "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax",
        "http",
    )


def _coop(finding: Finding, target: str) -> Fix:
    return _fix(
        "Set a Cross-Origin-Opener-Policy",
        "Cross-Origin-Opener-Policy: same-origin",
        "http",
        "https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
    )


def _vulnerable_js(finding: Finding, target: str) -> Fix:
    evidence = finding.evidence or {}
    lib = evidence.get("library", "the library")
    return _fix(
        f"Upgrade {lib} to a patched release",
        f"# {evidence.get('advisory', 'Known vulnerability in this version.')}\n"
        f"# Upgrade {lib} and re-deploy the bundled asset (or bump the CDN <script> URL):\n"
        f"npm install {lib}@latest",
        "config",
    )


def _cloud_bucket(finding: Finding, target: str) -> Fix:
    evidence = finding.evidence or {}
    provider = evidence.get("provider", "s3")
    name = evidence.get("name", "your-bucket")
    if provider == "s3":
        snippet = (
            f"aws s3api put-public-access-block --bucket {name} \\\n"
            "  --public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        )
    elif provider == "gcs":
        snippet = f"gsutil iam ch -d allUsers gs://{name}\n# remove allUsers / allAuthenticatedUsers"
    else:
        snippet = f"# Azure: set container '{name}' public access level to Private (no anonymous access)."
    return _fix("Remove public access from the bucket", snippet, "config")


def _redirect_downgrade(finding: Finding, target: str) -> Fix:
    return _fix(
        "Keep every redirect on HTTPS",
        "# Redirect straight to the canonical HTTPS URL; never hop through http://\n"
        f"# nginx\nreturn 301 https://{target}$request_uri;",
        "config",
    )


# --- Dispatch ---------------------------------------------------------------

_BUILDERS: dict[str, Builder] = {
    "redirect-downgrades-to-http": _redirect_downgrade,
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
    "mta-sts-missing": _mta_sts,
    "mta-sts-policy-invalid": _mta_sts,
    "mta-sts-not-enforced": _mta_sts,
    "tls-rpt-missing": _tls_rpt,
    "bimi-missing": _bimi,
    "dkim-weak-key": _dkim_weak,
    "cors-credentials-wildcard": _cors_wildcard,
    "cors-open": _cors_open,
    "referrer-policy-unsafe": _referrer_unsafe,
    "hsts-not-preloadable": _hsts_preload,
    "cookie-no-samesite": _cookie_samesite,
    "no-coop": _coop,
    "caa-missing": _caa_missing,
    "single-nameserver": _single_ns,
    "no-ipv6": _no_ipv6,
    "dane-missing": _dane,
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
    if finding.id.startswith("vulnerable-js-library"):
        return _vulnerable_js(finding, target)
    if finding.id.startswith("cloud-bucket-public"):
        return _cloud_bucket(finding, target)
    return None


def attach_remediations(findings: list[Finding], target: str) -> None:
    """Populate ``finding.remediation`` in place for every finding with a fix."""
    for finding in findings:
        finding.remediation = remediation_for(finding, target)
