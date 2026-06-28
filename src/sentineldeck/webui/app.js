"use strict";

const $ = (s) => document.querySelector(s);
const form = $("#scan-form"), input = $("#domain"), btn = $("#scan-btn");
const intro = $("#intro"), prog = $("#progress"), errBox = $("#error"), results = $("#results");
const SEV = { critical: "var(--crit)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", info: "var(--info)" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
let source = null;

$("#foot-version").textContent = "SentinelDeck dashboard";
document.querySelectorAll(".chip").forEach((c) =>
  c.addEventListener("click", () => { input.value = c.dataset.domain; form.requestSubmit(); }));

form.addEventListener("submit", (e) => {
  e.preventDefault();
  const domain = input.value.trim();
  if (domain) startScan(domain);
});

const show = (el) => el.classList.remove("hidden");
const hide = (el) => el.classList.add("hidden");
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function startScan(domain) {
  if (source) source.close();
  hide(intro); hide(errBox); hide(results);
  $("#progress-domain").textContent = domain;
  $("#progress-steps").innerHTML = "";
  show(prog);
  btn.disabled = true; btn.textContent = "Scanning…";

  source = new EventSource(`/api/scan?domain=${encodeURIComponent(domain)}`);
  source.addEventListener("progress", (ev) => {
    const li = document.createElement("li");
    li.textContent = JSON.parse(ev.data).label;
    $("#progress-steps").appendChild(li);
  });
  source.addEventListener("done", (ev) => {
    source.close(); source = null;
    render(JSON.parse(ev.data));
    finish();
  });
  source.addEventListener("failed", (ev) => {
    source.close(); source = null;
    let msg = "Scan failed.";
    try { msg = JSON.parse(ev.data).message; } catch (_) {}
    errBox.textContent = msg; show(errBox); finish();
  });
  source.addEventListener("error", () => {
    if (!source) return;            // already finished/closed cleanly
    source.close(); source = null;
    errBox.textContent = "Connection to the scanner was lost."; show(errBox); finish();
  });
}

function finish() { hide(prog); btn.disabled = false; btn.textContent = "Scan"; }

function render(report) {
  const checks = report.checks || {};
  const findings = (report.findings || []).filter((f) => !f.suppressed);
  renderHero(report, findings);
  renderFindings(findings);
  $("#cards").innerHTML = [
    cardStack(checks.technologies),
    cardReputation(checks.reputation),
    cardTLS(checks.tls),
    cardTLSConfig(checks.tls_config),
    cardEmail(checks.email_security),
    cardDNS(checks.dns_hygiene, checks.dns),
    cardIP(checks.ip_intel),
    cardPorts(checks.ports),
    cardSubdomains(checks.subdomains),
    cardTyposquat(checks.typosquatting),
    cardHeaders(checks.missing_security_headers, checks.header_issues),
    cardWebContent(checks.web_content),
    cardRedirects(checks.redirect_chain),
    cardDomain(checks.domain_intel),
    cardCloud(checks.cloud_assets),
    cardArchive(checks.archive),
  ].filter(Boolean).join("");
  show(results);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function renderHero(report, findings) {
  const g = (report.grade || "?").toUpperCase();
  const color = `var(--${g})`;
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const pills = SEV_ORDER.filter((s) => counts[s]).map((s) =>
    `<span class="sev-pill"><span class="sev-dot" style="background:${SEV[s]}"></span>${counts[s]} ${s}</span>`).join("");
  $("#hero").innerHTML = `
    <div class="grade" style="color:${color}">${esc(g)}</div>
    <div class="hero-meta">
      <h2>${esc(report.target)}</h2>
      <div class="score">Risk ${esc(report.risk_score)}/100 &middot; ${findings.length} findings &middot; grade ${esc(g)}</div>
      <div class="sev-row">${pills || '<span class="muted">No scored issues. Clean posture.</span>'}</div>
    </div>`;
}

function renderFindings(findings) {
  const scored = findings.slice().sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  $("#findings").innerHTML = scored.map((f) => {
    const color = SEV[f.severity] || "var(--info)";
    const fix = f.remediation ? `
      <div class="fix-label">Fix${f.remediation.kind ? " &middot; " + esc(f.remediation.kind) : ""}</div>
      <pre>${esc(f.remediation.snippet)}</pre>` : "";
    return `
      <div class="finding" style="border-left-color:${color}">
        <div class="finding-head" onclick="this.parentNode.querySelector('.finding-body').classList.toggle('hidden')">
          <span class="sev-tag" style="background:${color};color:#0a0a0f">${esc(f.severity)}</span>
          <span class="finding-title">${esc(f.title)}</span>
        </div>
        <div class="finding-body hidden">
          <div>${esc(f.description)}</div>
          ${f.recommendation ? `<div style="margin-top:8px">${esc(f.recommendation)}</div>` : ""}
          ${fix}
        </div>
      </div>`;
  }).join("") || '<div class="muted">No findings.</div>';
}

/* --- cards --------------------------------------------------------------- */
const card = (title, body) => `<div class="card"><h3>${title}</h3>${body}</div>`;
const row = (k, v, cls) => `<div class="row"><span class="k">${esc(k)}</span><span class="v ${cls || ""}">${v}</span></div>`;
const yn = (b) => b ? `<span class="v ok">yes</span>` : `<span class="v bad">no</span>`;
const flag = (label, ok) => `<div class="row"><span class="k">${esc(label)}</span>${yn(ok)}</div>`;

function cardStack(t) {
  if (!t || t.status !== "ok") return "";
  const tags = (t.detected || []).map((d) =>
    `<span class="tag">${esc(d.name)}${d.version ? " " + esc(d.version) : ""}</span>`).join("");
  const vulns = (t.vulnerable_js || []).map((v) =>
    `<span class="tag" style="border-color:var(--high);color:var(--high)">${esc(v.library)} ${esc(v.version)}</span>`).join("");
  if (!tags && !vulns) return card("Technology", '<div class="muted">No technologies fingerprinted.</div>');
  return card("Technology stack", `<div class="tags">${tags}${vulns}</div>`);
}

function cardTLS(tls) {
  if (!tls) return "";
  if (!tls.reachable) return card("TLS", '<div class="muted">No TLS connection.</div>');
  return card("TLS certificate",
    flag("Valid &amp; trusted", tls.valid) +
    (tls.protocol ? row("Protocol", esc(tls.protocol), tls.protocol_outdated ? "bad" : "ok") : "") +
    (tls.days_remaining != null ? row("Expires in", esc(tls.days_remaining) + " days", tls.days_remaining < 14 ? "bad" : "") : "") +
    (tls.key_type ? row("Key", esc(tls.key_type) + " " + esc(tls.key_bits || "")) : "") +
    (tls.signature_algorithm ? row("Signature", esc(tls.signature_algorithm)) : "") +
    (tls.issuer_org ? row("Issuer", esc(tls.issuer_org)) : "") +
    flag("Hostname match", tls.hostname_match));
}

function cardEmail(e) {
  if (!e) return "";
  const line = (label, sec) => {
    if (!sec) return flag(label, false);
    const extra = sec.policy ? ` (${esc(sec.policy)})` : "";
    return `<div class="row"><span class="k">${label}</span>${sec.present ? `<span class="v ok">yes${extra}</span>` : `<span class="v bad">no</span>`}</div>`;
  };
  return card("Email authentication",
    line("MX", e.mx) + line("SPF", e.spf) + line("DMARC", e.dmarc) +
    flag("DKIM", e.dkim && e.dkim.present) + flag("MTA-STS", e.mta_sts && e.mta_sts.present) +
    flag("TLS-RPT", e.tls_rpt && e.tls_rpt.present));
}

function cardDNS(h, dns) {
  if (!h) return "";
  return card("DNS",
    (dns && dns.addresses ? row("A records", esc(dns.addresses.length)) : "") +
    flag("CAA", h.caa && h.caa.present) + flag("DNSSEC", h.dnssec && h.dnssec.enabled) +
    (h.ns ? row("Nameservers", esc(h.ns.count), h.ns.count < 2 ? "warn" : "") : "") +
    flag("IPv6 (AAAA)", h.ipv6 && h.ipv6.present) + flag("DANE/TLSA", h.dane && h.dane.present));
}

function cardSubdomains(s) {
  if (!s || s.status !== "ok") return "";
  const hosts = (s.subdomains || []).slice(0, 12).map((h) =>
    `<span class="tag"${(s.sensitive || []).includes(h) ? ' style="border-color:var(--medium);color:var(--medium)"' : ""}>${esc(h)}</span>`).join("");
  return card("Subdomains",
    row("Discovered", esc(s.count)) +
    row("Sensitive", esc((s.sensitive || []).length), (s.sensitive || []).length ? "warn" : "") +
    `<div class="row"><span class="k">Source</span><span class="v muted">${esc(s.source)}</span></div>` +
    (hosts ? `<div class="tags" style="margin-top:10px">${hosts}</div>` : ""));
}

function cardHeaders(missing, issues) {
  if (!missing && !issues) return "";
  const miss = Object.keys(missing || {});
  const tags = miss.map((h) => `<span class="tag" style="border-color:var(--medium);color:var(--medium)">${esc(h)}</span>`).join("");
  return card("HTTP security headers",
    row("Missing", esc(miss.length), miss.length ? "warn" : "ok") +
    row("Misconfigured", esc((issues || []).length), (issues || []).length ? "warn" : "ok") +
    (tags ? `<div class="tags" style="margin-top:10px">${tags}</div>` : ""));
}

function cardDomain(d) {
  if (!d || d.status !== "ok") return "";
  const years = d.age_days != null ? (d.age_days / 365).toFixed(1) + " yrs" : "?";
  return card("Domain (RDAP)",
    (d.registrar ? row("Registrar", esc(d.registrar)) : "") +
    row("Age", years) +
    (d.expires_in_days != null ? row("Expires in", esc(d.expires_in_days) + " days", d.expires_in_days < 30 ? "bad" : "") : ""));
}

function cardCloud(c) {
  if (!c || !(c.buckets || []).length) return "";
  const rows = c.buckets.map((b) =>
    row(`${esc(b.provider.toUpperCase())} ${esc(b.name)}`, esc(b.access), b.access === "public" ? "bad" : "ok")).join("");
  return card("Cloud storage", rows);
}

function cardIP(ip) {
  if (!ip || ip.status !== "ok") return "";
  const loc = [ip.city, ip.region, ip.country].filter(Boolean).join(", ");
  return card("Server / IP intel",
    row("IP", esc(ip.ip)) +
    (loc ? row("Location", esc(loc)) : "") +
    (ip.org ? row("Org", esc(ip.org)) : "") +
    (ip.isp ? row("ISP", esc(ip.isp)) : "") +
    (ip.asn ? row("ASN", esc(ip.asn)) : ""));
}

function cardRedirects(rc) {
  if (!rc || !(rc.hops || []).length) return "";
  const hops = rc.hops.map((h) =>
    `<div class="row"><span class="k">${esc(h.status)}</span><span class="v muted">${esc(h.url)}</span></div>`).join("");
  return card("Redirect chain",
    row("Hops", esc(rc.count)) +
    (rc.downgrade ? row("Downgrade", "HTTPS&rarr;HTTP", "bad") : "") + hops);
}

function cardTLSConfig(t) {
  if (!t || t.status !== "ok") return "";
  const protos = t.protocols || {};
  const rows = Object.keys(protos).map((k) => {
    const weak = k === "TLSv1" || k === "TLSv1.1";
    return `<div class="row"><span class="k">${esc(k)}</span>${
      protos[k] === true ? `<span class="v ${weak ? "bad" : "ok"}">supported</span>`
                         : `<span class="v muted">no</span>`}</div>`;
  }).join("");
  return card("TLS configuration",
    (t.grade ? row("Config grade", esc(t.grade), t.grade === "old" ? "bad" : "ok") : "") + rows);
}

function cardPorts(p) {
  if (!p || p.status !== "ok") return "";
  const rows = (p.open || []).map((o) =>
    row(`${esc(o.port)} ${esc(o.service)}`, o.risky ? "risky" : "open", o.risky ? "bad" : "ok")).join("");
  return card("Open ports (active)",
    row("Scanned", esc(p.scanned)) + row("Open", esc((p.open || []).length)) + rows);
}

function cardReputation(r) {
  if (!r || r.status !== "ok") return "";
  const listed = r.listed
    ? `<span class="v bad">listed (${esc((r.sources || []).join(", "))})</span>`
    : `<span class="v ok">clean</span>`;
  return card("Threat reputation",
    `<div class="row"><span class="k">Status</span>${listed}</div>` +
    (r.listed ? row("Malicious URLs", esc(r.url_count)) : ""));
}

function cardTyposquat(t) {
  if (!t || t.status !== "ok") return "";
  const reg = t.registered || [];
  const tags = reg.slice(0, 16).map((r) =>
    `<span class="tag" style="border-color:var(--medium);color:var(--medium)">${esc(r.domain)}</span>`).join("");
  return card("Lookalike domains",
    row("Variants checked", esc(t.checked)) +
    row("Registered", esc(reg.length), reg.length ? "warn" : "ok") +
    (tags ? `<div class="tags" style="margin-top:10px">${tags}</div>` : ""));
}

function cardArchive(a) {
  if (!a || a.status !== "ok" || !a.snapshots) return "";
  return card("Archive history",
    (a.first ? row("First archived", esc(a.first)) : "") +
    row("Snapshots", esc(a.snapshots) + (a.truncated ? "+" : "")));
}

function cardWebContent(w) {
  if (!w || w.status !== "ok") return "";
  const waf = (w.waf || []).length
    ? `<span class="v ok">${w.waf.map(esc).join(", ")}</span>`
    : `<span class="v muted">none detected</span>`;
  const links = w.links || {}, robots = w.robots || {}, sitemap = w.sitemap || {};
  const social = Object.keys(w.social || {}).length;
  return card("Web content",
    `<div class="row"><span class="k">WAF / CDN</span>${waf}</div>` +
    row("Links", `${esc(links.internal || 0)} internal / ${esc(links.external || 0)} external`) +
    row("robots.txt", robots.present ? "yes" : "no", robots.present ? "ok" : "") +
    row("sitemap.xml", sitemap.present ? `${esc(sitemap.urls)} urls` : "no", sitemap.present ? "ok" : "") +
    row("Social tags", esc(social), social ? "ok" : ""));
}
