from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from sentineldeck.models import ScanReport
from sentineldeck.remediation import attach_remediations
from sentineldeck.risk.scoring import build_findings, compute_passes, grade, score_findings
from sentineldeck.scanners.archive import archive_history
from sentineldeck.scanners.asn import analyze_asn
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
from sentineldeck.scanners.internetdb import analyze_internetdb
from sentineldeck.scanners.ip_intel import analyze_ip_intel
from sentineldeck.scanners.ip_rdap import analyze_ip_rdap
from sentineldeck.scanners.kev import filter_kev
from sentineldeck.scanners.ports import scan_ports
from sentineldeck.scanners.reputation import check_reputation
from sentineldeck.scanners.reverse_ip import reverse_ip
from sentineldeck.scanners.saas_stack import detect_saas
from sentineldeck.scanners.subdomains import discover_subdomains, fetch_hostsearch
from sentineldeck.scanners.takeover import detect_takeovers
from sentineldeck.scanners.target import classify_target, is_private_ip
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
    "ip_intel": "IP intelligence (geo, ASN)",
    "ip_rdap": "Network allocation (RDAP)",
    "reverse_ip": "Reverse IP (hosted domains)",
    "internetdb": "Exposure & CVEs (Shodan InternetDB)",
    "asn": "Network footprint (ASN)",
}


def _summary(name: str, result) -> str:
    """A short, human one-liner about what a probe found, for the live console."""
    if not isinstance(result, dict):
        return ""
    if result.get("status") == "error":
        return " :: error"
    try:
        if name == "dns":
            n = len(result.get("addresses") or [])
            return f" :: {n} address(es)" if n else " :: no A record"
        if name == "http":
            if not result.get("reachable"):
                return " :: unreachable"
            return f" :: {result.get('status')} ({result.get('response_time_ms', '?')} ms)"
        if name == "tls":
            if not result.get("reachable"):
                return " :: unreachable"
            return f" :: {result.get('protocol', '?')}, {'valid' if result.get('valid') else 'untrusted'}"
        if name == "tls_config":
            return f" :: grade {result.get('grade')}" if result.get("status") == "ok" else ""
        if name == "email":
            on = [k.upper() for k in ("spf", "dmarc", "dkim") if (result.get(k) or {}).get("present")]
            return f" :: {', '.join(on) or 'none'}"
        if name == "subdomains":
            return f" :: {result.get('count', 0)} found" if result.get("status") == "ok" else ""
        if name == "typosquat":
            return f" :: {len(result.get('registered', []))} registered"
        if name == "blocklists":
            blocked = result.get("blocked_security") or []
            return f" :: blocked by {', '.join(blocked)}" if blocked else " :: clean"
        if name == "domain_intel":
            return f" :: {str(result.get('registrar', ''))[:28]}" if result.get("status") == "ok" else ""
        if name == "redirect_chain":
            return f" :: {result.get('count', 0)} hop(s)"
        if name == "archive":
            return f" :: since {result.get('first')}" if result.get("snapshots") else " :: none"
        if name == "ports":
            return f" :: {len(result.get('open', []))} open" if result.get("status") == "ok" else ""
        if name == "page":
            return " :: fetched" if result.get("reachable") else " :: unreachable"
        if name == "ip_intel":
            place = ", ".join(x for x in (result.get("city"), result.get("country")) if x)
            if place:
                return f" :: {place}"
            return f" :: AS{result.get('asn')}" if result.get("asn") else ""
        if name == "ip_rdap":
            tag = result.get("org") or result.get("cidr")
            return f" :: {str(tag)[:28]}" if tag else ""
        if name == "reverse_ip":
            return f" :: {result.get('count', 0)} domain(s)"
        if name == "internetdb":
            np_, nv = len(result.get("ports") or []), len(result.get("vulns") or [])
            return f" :: {np_} port(s), {nv} CVE(s)" if (np_ or nv) else " :: clean"
        if name == "asn":
            return f" :: AS{result.get('asn')}, {result.get('prefix_count', 0)} prefix(es)" if result.get("asn") else ""
        if name == "reputation":
            return " :: listed" if (result.get("listed") or result.get("malicious")) else " :: clean"
    except Exception:  # noqa: BLE001 - a summary must never break a scan
        return ""
    return ""


def _safe(fn, fallback):
    """Run a surface and degrade it to ``fallback`` on failure, so a single
    broken probe never aborts the whole scan."""
    try:
        return fn()
    except Exception:  # noqa: BLE001 - one failed surface should not abort the scan
        return fallback


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
    # Typosquatting makes ~30 bulk existence checks; a short timeout keeps the
    # scan snappy where direct DNS is slow or blocked, at the cost of possibly
    # missing a very slow-resolving lookalike.
    typo_resolver = Resolver(timeout=2.0)

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
            "typosquat": pool.submit(detect_typosquats, domain, typo_resolver),
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
            try:
                results[name] = future.result()
            except Exception as exc:  # noqa: BLE001 - one failed probe must not abort the scan
                results[name] = {"status": "error", "error": str(exc)}
            _notify(STAGE_LABELS.get(name, name) + _summary(name, results[name]))

    # Takeover detection needs the discovered hostnames, so it runs after the
    # concurrent block, reusing the same DoH-aware resolver.
    subdomains = results["subdomains"]
    hosts = subdomains.get("subdomains", []) if subdomains.get("status") == "ok" else []
    if hosts:
        takeover = _safe(
            lambda: detect_takeovers(hosts, resolver=resolver, timeout=timeout),
            {"status": "error", "candidates": [], "checked": 0},
        )
        _candidates = takeover.get("candidates", [])
        _notify("Subdomain takeover" + (f" :: {len(_candidates)} candidate(s)" if _candidates else " :: none"))
    else:
        takeover = {"status": "skipped", "candidates": [], "checked": 0}

    http = {**results["http"], **results["redirect"], "security_txt": results["security_txt"]}
    headers = http.get("headers", {})
    cookies = http.get("cookies", [])

    # The homepage HTML drives technology fingerprinting, vulnerable-JS detection,
    # and cloud-bucket discovery.
    page = results["page"]
    if page.get("reachable"):
        technologies = _safe(
            lambda: {
                "status": "ok",
                "detected": fingerprint(page),
                "vulnerable_js": detect_vulnerable_js(page.get("body", "")),
            },
            {"status": "error", "detected": [], "vulnerable_js": []},
        )
    else:
        technologies = {"status": "error", "detected": [], "vulnerable_js": []}

    cloud = _safe(lambda: analyze_cloud_assets(page.get("body", "")), {"status": "error", "buckets": []})
    if cloud.get("buckets"):
        _notify(f"Cloud storage exposure :: {len(cloud['buckets'])} bucket(s)")

    web_content = _safe(lambda: analyze_web_content(domain, page), {"status": "error"})
    _waf = web_content.get("waf") or []
    _notify("Web content (links, social, WAF, robots)" + (f" :: WAF {', '.join(_waf)}" if _waf else ""))

    addresses = results["dns"].get("addresses") or []
    ip_intel = _safe(lambda: analyze_ip_intel(addresses[0] if addresses else None, timeout), {"status": "error"})
    if addresses and addresses[0].count(".") == 3:
        ptr = _safe(lambda: resolver(".".join(reversed(addresses[0].split("."))) + ".in-addr.arpa", "PTR")[0], [])
        if ptr:
            ip_intel["hostnames"] = ptr
    _place = ", ".join(x for x in (ip_intel.get("city"), ip_intel.get("country")) if x)
    _notify("IP intelligence (geo, ASN)" + (f" :: {_place}" if _place else ""))

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

    # Passive exposure + known CVEs for the resolved host, plus the SaaS footprint
    # the domain leaks through its TXT / SPF / MX records.
    if addresses:
        internetdb = _safe(
            lambda: analyze_internetdb(addresses[0], timeout),
            {"status": "error", "ports": [], "vulns": []},
        )
    else:
        internetdb = {"status": "skipped", "ports": [], "vulns": []}
    if internetdb.get("vulns"):
        internetdb["kev"] = filter_kev(internetdb["vulns"])
    _notify("Exposure & CVEs (Shodan InternetDB)" + _summary("internetdb", internetdb))

    if addresses:
        asn_footprint = _safe(lambda: analyze_asn(addresses[0], timeout), {"status": "error"})
    else:
        asn_footprint = {"status": "skipped"}
    _notify("Network footprint (ASN)" + _summary("asn", asn_footprint))

    spf_record = (results["email"].get("spf") or {}).get("record") or ""
    spf_includes = [t.split(":", 1)[1] for t in spf_record.split() if t.lower().startswith("include:")]
    saas = _safe(
        lambda: detect_saas(dns_records.get("TXT"), spf_includes, dns_records.get("MX")),
        {"status": "ok", "count": 0, "services": []},
    )
    if saas.get("count"):
        _notify(f"SaaS footprint :: {saas['count']} service(s)")

    report.checks = {
        "dns": results["dns"],
        "internetdb": internetdb,
        "asn_footprint": asn_footprint,
        "saas_stack": saas,
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


def scan_ip(
    target: str,
    timeout: int = DEFAULT_TIMEOUT,
    suppressions: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
    active: bool = False,
) -> ScanReport:
    """Scan a bare IP address. Reuses the probes that make sense for a host and
    adds network-allocation (RDAP) and reverse-IP (hosted domains) intelligence.
    Domain-only surfaces (email, subdomains, typosquatting, DNS records) are
    skipped. For a private/reserved IP the internet data sources are skipped and
    only the locally reachable surfaces (HTTP, TLS, ports) run.
    """
    ip = target.strip().strip("[]")
    report = ScanReport.empty(ip)
    private = is_private_ip(ip)

    def _notify(label: str) -> None:
        if progress is not None:
            try:
                progress(label)
            except Exception:  # noqa: BLE001 - progress is cosmetic, never break a scan
                pass

    resolver = Resolver()

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {
            "http": pool.submit(fetch_headers, ip, timeout),
            "redirect": pool.submit(check_http_redirect, ip, timeout),
            "security_txt": pool.submit(check_security_txt, ip, timeout),
            "tls": pool.submit(inspect_tls, ip, timeout),
            "tls_config": pool.submit(analyze_tls_config, ip),
            "page": pool.submit(fetch_page, ip, timeout),
            "redirect_chain": pool.submit(trace_redirects, ip, timeout),
        }
        if not private:
            futures["ip_intel"] = pool.submit(analyze_ip_intel, ip, timeout)
            futures["ip_rdap"] = pool.submit(analyze_ip_rdap, ip)
            futures["reverse_ip"] = pool.submit(reverse_ip, ip)
            futures["reputation"] = pool.submit(check_reputation, ip)
            futures["internetdb"] = pool.submit(analyze_internetdb, ip, timeout)
            futures["asn"] = pool.submit(analyze_asn, ip, timeout)
        if active:
            futures["ports"] = pool.submit(scan_ports, ip)

        name_by_future = {future: name for name, future in futures.items()}
        results: dict = {}
        for future in as_completed(name_by_future):
            name = name_by_future[future]
            try:
                results[name] = future.result()
            except Exception as exc:  # noqa: BLE001 - one failed probe must not abort the scan
                results[name] = {"status": "error", "error": str(exc)}
            _notify(STAGE_LABELS.get(name, name) + _summary(name, results[name]))

    http = {**results["http"], **results["redirect"], "security_txt": results["security_txt"]}
    headers = http.get("headers", {})
    cookies = http.get("cookies", [])

    page = results["page"]
    if page.get("reachable"):
        technologies = _safe(
            lambda: {
                "status": "ok",
                "detected": fingerprint(page),
                "vulnerable_js": detect_vulnerable_js(page.get("body", "")),
            },
            {"status": "error", "detected": [], "vulnerable_js": []},
        )
    else:
        technologies = {"status": "error", "detected": [], "vulnerable_js": []}

    cloud = _safe(lambda: analyze_cloud_assets(page.get("body", "")), {"status": "error", "buckets": []})
    web_content = _safe(lambda: analyze_web_content(ip, page), {"status": "error"})

    ip_intel = results.get("ip_intel", {"status": "skipped"})
    if not private and isinstance(ip_intel, dict) and ip.count(".") == 3:
        ptr = _safe(lambda: resolver(".".join(reversed(ip.split("."))) + ".in-addr.arpa", "PTR")[0], [])
        if ptr:
            ip_intel["hostnames"] = ptr

    internetdb = results.get("internetdb", {"status": "skipped", "ports": [], "vulns": []})
    if internetdb.get("vulns"):
        internetdb["kev"] = filter_kev(internetdb["vulns"])

    report.checks = {
        "target_type": "ip",
        # The target is already an address, so resolution is trivially satisfied;
        # this keeps the scoring engine from flagging it as "unresolved".
        "dns": {"resolved": True, "addresses": [ip]},
        "internetdb": internetdb,
        "asn_footprint": results.get("asn", {"status": "skipped"}),
        "http": http,
        "missing_security_headers": missing_security_headers(headers),
        "header_issues": evaluate_headers(headers, cookies),
        "tls": results["tls"],
        "tls_config": results["tls_config"],
        "redirect_chain": results["redirect_chain"],
        "technologies": technologies,
        "cloud_assets": cloud,
        "web_content": web_content,
        "ip_intel": ip_intel,
        "ip_rdap": results.get("ip_rdap", {"status": "skipped"}),
        "reverse_ip": results.get("reverse_ip", {"status": "skipped", "domains": []}),
        "reputation": results.get("reputation", {"status": "skipped"}),
        "ports": results.get("ports", {"status": "skipped", "open": []}),
    }
    report.findings = build_findings(report.checks)
    report.checks["passes"] = compute_passes(report.checks)
    attach_remediations(report.findings, ip)
    if suppressions:
        apply_suppressions(report.findings, suppressions)
    report.risk_score = score_findings(report.findings)
    report.grade = grade(report.risk_score)
    return report


def scan_target(
    target: str,
    timeout: int = DEFAULT_TIMEOUT,
    suppressions: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
    active: bool = False,
) -> ScanReport:
    """Scan a domain or an IP address, picking the right pipeline automatically."""
    kind, value = classify_target(target)
    runner = scan_ip if kind == "ip" else scan_domain
    return runner(value, timeout, suppressions, progress, active)
