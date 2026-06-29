"use strict";

const $ = (s) => document.querySelector(s);
const form = $("#scan-form"), input = $("#domain"), btn = $("#scan-btn");
const intro = $("#intro"), prog = $("#progress"), errBox = $("#error"), results = $("#results");
const SEV = { critical: "var(--crit)", high: "var(--high)", medium: "var(--medium)", low: "var(--low)", info: "var(--info)" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
let source = null;

/* theme */
document.documentElement.setAttribute("data-theme", localStorage.getItem("sd-theme") || "dark");
$("#theme-btn").addEventListener("click", () => {
  const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("sd-theme", next); } catch (_) {}
});

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

let consoleStart = 0, consoleTimer = null;
const elapsed = () => ((performance.now() - consoleStart) / 1000).toFixed(1);

function consoleLine(html, cls) {
  const body = $("#console-body");
  const cursor = document.getElementById("console-cursor");
  const line = document.createElement("div");
  line.className = "cline" + (cls ? " " + cls : "");
  line.innerHTML = html;
  body.insertBefore(line, cursor);
  body.scrollTop = body.scrollHeight;
}

const ts = () => `<span class="ts">[+${elapsed()}s]</span> `;

function stopTimer() {
  if (consoleTimer) { clearInterval(consoleTimer); consoleTimer = null; }
}

function startScan(domain) {
  if (source) source.close();
  hide(intro); hide(errBox); hide(results);
  $("#progress-domain").textContent = domain;
  const active = document.getElementById("active-scan").checked;
  $("#console-body").innerHTML = '<span id="console-cursor" class="cursor">█</span>';
  show(prog);
  btn.disabled = true; btn.textContent = "SCANNING…";

  consoleStart = performance.now();
  consoleLine(`<span class="ts">$</span> sentineldeck scan ${esc(domain)}${active ? " --active" : ""}`, "cmd");
  consoleLine(`${ts()}dispatching probes &middot; passive recon`, "muted-line");
  stopTimer();
  consoleTimer = setInterval(() => { $("#console-timer").textContent = "+" + elapsed() + "s"; }, 100);

  source = new EventSource(`/api/scan?domain=${encodeURIComponent(domain)}${active ? "&active=1" : ""}`);
  source.addEventListener("progress", (ev) => {
    consoleLine(ts() + esc(JSON.parse(ev.data).label), "ok-line");
  });
  source.addEventListener("done", (ev) => {
    source.close(); source = null;
    const report = JSON.parse(ev.data);
    const g = (report.grade || "?").toUpperCase();
    consoleLine(`${ts()}scan complete :: grade ${esc(g)} :: ${(report.findings || []).length} findings`, "done-line");
    stopTimer();
    setTimeout(() => {
      try {
        render(report);
      } catch (err) {
        hide(results);
        errBox.textContent = "RENDER ERROR // " + (err && err.message ? err.message : err);
        show(errBox);
      }
      finish();
    }, 650);
  });
  source.addEventListener("failed", (ev) => {
    source.close(); source = null;
    let msg = "SCAN FAILED.";
    try { msg = JSON.parse(ev.data).message; } catch (_) {}
    consoleLine(`${ts()}ERROR :: ${esc(msg)}`, "err-line");
    stopTimer();
    errBox.textContent = msg; show(errBox); finish();
  });
  source.addEventListener("error", () => {
    if (!source) return;
    source.close(); source = null;
    consoleLine(`${ts()}connection to the scanner was lost`, "err-line");
    stopTimer();
    errBox.textContent = "CONNECTION TO THE SCANNER WAS LOST."; show(errBox); finish();
  });
}

function finish() { hide(prog); btn.disabled = false; btn.textContent = "SCAN"; }

function render(report) {
  const checks = report.checks || {};
  const findings = (report.findings || []).filter((f) => !f.suppressed);
  renderHero(report, findings);
  renderFindings(findings);
  $("#cards").innerHTML = [
    cardPasses(checks.passes),
    cardStack(checks.technologies),
    cardReputation(checks.reputation),
    cardBlocklists(checks.blocklists),
    cardTLS(checks.tls),
    cardTLSConn(checks.tls),
    cardTLSConfig(checks.tls_config),
    cardEmail(checks.email_security),
    cardDNS(checks.dns_hygiene, checks.dns),
    cardDNSRecords(checks.dns_records),
    cardIP(checks.ip_intel),
    cardMap(checks.ip_intel),
    cardServerStatus(checks.http),
    cardHostNames(checks.ip_intel),
    cardPorts(checks.ports),
    cardSubdomains(checks.subdomains),
    cardTyposquat(checks.typosquatting),
    cardHeaders(checks.missing_security_headers, checks.header_issues),
    cardHeadersRaw(checks.http),
    cardCookies(checks.http),
    cardFirewall(checks.web_content),
    cardSocial(checks.web_content),
    cardRobots(checks.web_content),
    cardPages(checks.web_content),
    cardLinks(checks.web_content),
    cardSecurityTxt(checks.http),
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
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const pills = SEV_ORDER.filter((s) => counts[s]).map((s) =>
    `<span class="sev-pill"><span class="sev-dot" style="background:${SEV[s]}"></span>${counts[s]} ${s.toUpperCase()}</span>`).join("");
  $("#hero").innerHTML =
    `<div class="grade-box"><div class="grade-letter" style="color:var(--${g})">${esc(g)}</div><div class="grade-cap">GRADE</div></div>` +
    `<div class="hero-meta">
       <div class="hero-target">${esc(report.target)}</div>
       <div class="hero-score">RISK ${esc(report.risk_score)}/100 // ${findings.length} FINDINGS</div>
       <div class="hero-sev">${pills || '<span class="muted">NO SCORED ISSUES // CLEAN POSTURE</span>'}</div>
     </div>` +
    `<div class="hero-radar">${radarSVG(computeDimensions(report.checks || {}))}</div>`;
}

/* --- posture radar (unique telemetry view) ------------------------------- */
function pct(items) {
  let s = 0;
  for (const [cond, w] of items) if (cond) s += w;
  return Math.min(100, s);
}

function computeDimensions(c) {
  const tls = c.tls || {}, tc = c.tls_config || {}, em = c.email_security || {}, dh = c.dns_hygiene || {};
  const missing = c.missing_security_headers || {};
  const rep = c.reputation || {}, bl = c.blocklists || {}, tk = c.takeover || {}, cloud = c.cloud_assets || {};
  const dmarcEnforced = ["quarantine", "reject"].includes((em.dmarc || {}).policy);
  const publicBuckets = (cloud.buckets || []).filter((b) => b.access === "public").length;
  return [
    { label: "TLS", score: pct([[tls.valid, 40], [tc.status === "ok" && !(tc.weak_protocols || []).length, 30], [tls.forward_secrecy, 30]]) },
    { label: "EMAIL", score: pct([[(em.spf || {}).present, 25], [dmarcEnforced, 35], [(em.dkim || {}).present, 20], [(em.mta_sts || {}).present, 20]]) },
    { label: "DNS", score: pct([[(dh.dnssec || {}).enabled, 40], [(dh.caa || {}).present, 30], [(dh.ipv6 || {}).present, 15], [((dh.ns || {}).count || 0) >= 2, 15]]) },
    { label: "HEADERS", score: Math.round(Math.max(0, 6 - Object.keys(missing).length) / 6 * 100) },
    { label: "SURFACE", score: Math.max(0, 100 - ((tk.candidates || []).length * 50) - (publicBuckets * 40)) },
    { label: "TRUST", score: (rep.listed || (bl.blocked_security || []).length) ? 15 : 100 },
  ];
}

function radarSVG(dims) {
  const size = 200, cx = size / 2, cy = size / 2, R = 70, n = dims.length;
  const ang = (i) => (Math.PI * 2 * i / n) - Math.PI / 2;
  const pt = (i, r) => [cx + Math.cos(ang(i)) * r, cy + Math.sin(ang(i)) * r];
  const ring = (f) => dims.map((_, i) => pt(i, R * f).map((v) => v.toFixed(1)).join(",")).join(" ");
  const grid = [0.25, 0.5, 0.75, 1].map((f) => `<polygon points="${ring(f)}" class="rg"/>`).join("");
  const axes = dims.map((_, i) => { const [x, y] = pt(i, R); return `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" class="rg"/>`; }).join("");
  const data = dims.map((d, i) => pt(i, R * (d.score / 100)).map((v) => v.toFixed(1)).join(",")).join(" ");
  const dots = dims.map((d, i) => { const [x, y] = pt(i, R * (d.score / 100)); return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2" class="rdot"/>`; }).join("");
  const labels = dims.map((d, i) => { const [x, y] = pt(i, R + 14); return `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" class="rl" text-anchor="middle" dominant-baseline="middle">${esc(d.label)}</text>`; }).join("");
  return `<svg viewBox="0 0 ${size} ${size}" class="radar" style="max-width:210px">${grid}${axes}<polygon points="${data}" class="rd"/>${dots}${labels}</svg>`;
}

function renderFindings(findings) {
  const scored = findings.slice().sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  $("#findings").innerHTML = scored.map((f) => {
    const color = SEV[f.severity] || "var(--info)";
    const fix = f.remediation ? `
      <div class="fix-label">FIX${f.remediation.kind ? " // " + esc(f.remediation.kind) : ""}</div>
      <pre>${esc(f.remediation.snippet)}</pre>` : "";
    return `
      <div class="finding" style="border-left-color:${color}">
        <div class="finding-head">
          <span class="sev-tag" style="background:${color}">${esc(f.severity)}</span>
          <span class="finding-title" onclick="this.closest('.finding').querySelector('.finding-body').classList.toggle('hidden')">${esc(f.title)}</span>
          <span class="finding-id">${esc(f.id)}</span>
        </div>
        <div class="finding-body hidden">
          <div>${esc(f.description)}</div>
          ${f.recommendation ? `<div style="margin-top:8px">${esc(f.recommendation)}</div>` : ""}
          ${fix}
        </div>
      </div>`;
  }).join("") || '<div class="muted">NO FINDINGS.</div>';
}

/* --- cards --------------------------------------------------------------- */
const card = (title, body) => `<div class="card"><h3>${title}</h3>${body}</div>`;
const row = (k, v, cls) => `<div class="row"><span class="k">${esc(k)}</span><span class="v ${cls || ""}">${v}</span></div>`;
const yn = (b) => b ? `<span class="v ok">yes</span>` : `<span class="v bad">no</span>`;
const flag = (label, ok) => `<div class="row"><span class="k">${esc(label)}</span>${yn(ok)}</div>`;

function cardStack(t) {
  if (!t || t.status !== "ok") return "";
  const tags = (t.detected || []).map((d) => `<span class="tag">${esc(d.name)}${d.version ? " " + esc(d.version) : ""}</span>`).join("");
  const vulns = (t.vulnerable_js || []).map((v) => `<span class="tag" style="border-color:var(--high);color:var(--high)">${esc(v.library)} ${esc(v.version)}</span>`).join("");
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
    (tls.serial ? row("Serial", esc(tls.serial.slice(0, 20)) + (tls.serial.length > 20 ? "…" : "")) : "") +
    (tls.fingerprint_sha256 ? row("SHA-256", esc(tls.fingerprint_sha256.slice(0, 20)) + "…") : "") +
    (tls.extended_key_usage && tls.extended_key_usage.length ? row("Key usage", esc(tls.extended_key_usage.join(", "))) : "") +
    flag("Hostname match", tls.hostname_match));
}

function cardTLSConn(tls) {
  if (!tls || !tls.reachable || !tls.cipher_suite) return "";
  return card("TLS connection",
    row("Cipher suite", esc(tls.cipher_suite)) +
    (tls.cipher_bits ? row("Strength", esc(tls.cipher_bits) + "-bit") : "") +
    (tls.alpn ? row("ALPN", esc(tls.alpn)) : "") +
    flag("Forward secrecy", tls.forward_secrecy));
}

function cardTLSConfig(t) {
  if (!t || t.status !== "ok") return "";
  const protos = t.protocols || {};
  const rows = Object.keys(protos).map((k) => {
    const weak = k === "TLSv1" || k === "TLSv1.1";
    return `<div class="row"><span class="k">${esc(k)}</span>${protos[k] === true ? `<span class="v ${weak ? "bad" : "ok"}">supported</span>` : `<span class="v muted">no</span>`}</div>`;
  }).join("");
  return card("TLS configuration", (t.grade ? row("Config grade", esc(t.grade), t.grade === "old" ? "bad" : "ok") : "") + rows);
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
  return card("DNS hygiene",
    (dns && dns.addresses ? row("A records", esc(dns.addresses.length)) : "") +
    flag("CAA", h.caa && h.caa.present) + flag("DNSSEC", h.dnssec && h.dnssec.enabled) +
    (h.ns ? row("Nameservers", esc(h.ns.count), h.ns.count < 2 ? "warn" : "") : "") +
    flag("IPv6 (AAAA)", h.ipv6 && h.ipv6.present) + flag("DANE/TLSA", h.dane && h.dane.present));
}

function cardDNSRecords(d) {
  if (!d) return "";
  const block = (label, list) => {
    if (!list || !list.length) return "";
    const rows = list.slice(0, 8).map((r) => `<div class="dns-rec">${esc(r)}</div>`).join("");
    return `<div class="dns-group"><div class="dns-type">${label}</div>${rows}</div>`;
  };
  const body = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA"].map((t) => block(t, d[t])).join("");
  return body ? card("DNS records", body) : "";
}

function cardIP(ip) {
  if (!ip || ip.status !== "ok") return "";
  const loc = [ip.city, ip.region, ip.country].filter(Boolean).join(", ");
  return card("Server / IP intel",
    row("IP", esc(ip.ip)) +
    (loc ? row("Location", esc(loc)) : "") +
    (ip.timezone ? row("Timezone", esc(ip.timezone)) : "") +
    (ip.org ? row("Org", esc(ip.org)) : "") +
    (ip.isp ? row("ISP", esc(ip.isp)) : "") +
    (ip.asn ? row("ASN", esc(ip.asn)) : ""));
}

// Continents as [lon, lat] polygons (equirectangular). Rough but recognisable;
// rendered as a dot matrix so coastlines read as a real world map, not blobs.
const CONTINENTS = [
  [[-168, 66], [-156, 71], [-128, 71], [-95, 73], [-82, 73], [-62, 66], [-56, 52], [-66, 46], [-71, 41], [-76, 34], [-81, 25], [-91, 18], [-98, 16], [-106, 21], [-114, 28], [-124, 37], [-125, 43], [-130, 50], [-140, 59], [-154, 59], [-166, 61]],
  [[-54, 60], [-42, 60], [-20, 68], [-18, 76], [-30, 83], [-46, 82], [-58, 76], [-56, 67]],
  [[-81, 9], [-70, 12], [-60, 5], [-50, 0], [-35, -6], [-38, -13], [-43, -23], [-48, -25], [-49, -33], [-58, -39], [-66, -45], [-69, -52], [-74, -53], [-73, -44], [-71, -33], [-71, -20], [-76, -14], [-81, -4], [-80, 2]],
  [[-9, 38], [-9, 44], [-4, 48], [-5, 58], [6, 63], [12, 66], [24, 71], [30, 70], [42, 67], [60, 67], [60, 55], [48, 52], [40, 47], [28, 46], [25, 40], [15, 37], [3, 37]],
  [[-17, 14], [-16, 22], [-9, 31], [1, 37], [11, 37], [23, 32], [33, 31], [36, 22], [43, 12], [51, 11], [44, -2], [40, -12], [33, -22], [26, -34], [18, -35], [11, -16], [9, 4], [-8, 4], [-15, 7]],
  [[40, 47], [55, 52], [70, 55], [90, 58], [110, 53], [128, 50], [142, 48], [155, 58], [170, 67], [180, 68], [170, 71], [140, 73], [110, 77], [78, 76], [58, 70], [45, 55]],
  [[66, 24], [72, 21], [70, 16], [75, 8], [80, 8], [81, 15], [88, 21], [90, 22], [88, 26], [78, 30], [70, 27]],
  [[97, 28], [100, 14], [104, 9], [107, 11], [109, 1], [114, 5], [120, 6], [122, 14], [121, 23], [122, 31], [128, 35], [124, 40], [120, 38], [110, 22], [102, 18], [99, 22]],
  [[95, 5], [120, 5], [141, -2], [141, -9], [118, -9], [98, -2]],
  [[114, -22], [122, -18], [130, -12], [143, -12], [147, -20], [153, -28], [150, -38], [140, -38], [130, -32], [123, -34], [115, -34], [113, -26]],
  [[166, -46], [175, -41], [178, -37], [173, -41], [167, -45]],
  [[43, -12], [50, -16], [50, -25], [44, -25], [43, -18]],
  [[130, 31], [142, 40], [145, 44], [140, 43], [131, 33]],
];

function inPoly(lon, lat, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const xi = poly[i][0], yi = poly[i][1], xj = poly[j][0], yj = poly[j][1];
    if (((yi > lat) !== (yj > lat)) && (lon < (xj - xi) * (lat - yi) / (yj - yi) + xi)) inside = !inside;
  }
  return inside;
}

function cardMap(ip) {
  if (!ip || ip.status !== "ok" || ip.lat == null || ip.lon == null) return "";
  const W = 300, H = 150, COLS = 78, ROWS = 36, dx = W / COLS, dy = H / ROWS;
  let dots = "";
  for (let r = 0; r < ROWS; r++) {
    for (let c = 0; c < COLS; c++) {
      const lon = -180 + ((c + 0.5) / COLS) * 360, lat = 90 - ((r + 0.5) / ROWS) * 180;
      if (CONTINENTS.some((p) => inPoly(lon, lat, p))) {
        dots += `<rect x="${(c * dx).toFixed(1)}" y="${(r * dy).toFixed(1)}" width="1.5" height="1.5" class="md"/>`;
      }
    }
  }
  const px = ((Number(ip.lon) + 180) / 360) * W, py = ((90 - Number(ip.lat)) / 180) * H;
  const loc = [ip.city, ip.country].filter(Boolean).join(", ");
  return card("Server location", `
    <svg viewBox="0 0 ${W} ${H}" class="map" xmlns="http://www.w3.org/2000/svg">${dots}
      <line x1="${px.toFixed(1)}" y1="0" x2="${px.toFixed(1)}" y2="${H}" class="mx"/>
      <line x1="0" y1="${py.toFixed(1)}" x2="${W}" y2="${py.toFixed(1)}" class="mx"/>
      <circle cx="${px.toFixed(1)}" cy="${py.toFixed(1)}" r="6" class="mpc"/>
      <circle cx="${px.toFixed(1)}" cy="${py.toFixed(1)}" r="2.5" class="mp"/>
    </svg>
    <div class="muted" style="margin-top:8px">${esc(loc)} // ${esc(ip.lat)}, ${esc(ip.lon)}</div>`);
}

function cardServerStatus(http) {
  if (!http || !http.reachable) return "";
  return card("Server status",
    flag("Online", true) +
    (http.status != null ? row("Status code", esc(http.status), http.status < 400 ? "ok" : "warn") : "") +
    (http.response_time_ms != null ? row("Response time", esc(http.response_time_ms) + " ms") : ""));
}

function cardHostNames(ip) {
  if (!ip || !(ip.hostnames || []).length) return "";
  return card("Host names", ip.hostnames.map((h) => row("PTR", esc(h))).join(""));
}

function cardPorts(p) {
  if (!p || p.status !== "ok") return "";
  const rows = (p.open || []).map((o) => row(`${esc(o.port)} ${esc(o.service)}`, o.risky ? "risky" : "open", o.risky ? "bad" : "ok")).join("");
  return card("Open ports (active)", row("Scanned", esc(p.scanned)) + row("Open", esc((p.open || []).length)) + rows);
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

function cardTyposquat(t) {
  if (!t || t.status !== "ok") return "";
  const reg = t.registered || [];
  const tags = reg.slice(0, 16).map((r) => `<span class="tag" style="border-color:var(--medium);color:var(--medium)">${esc(r.domain)}</span>`).join("");
  return card("Lookalike domains",
    row("Variants checked", esc(t.checked)) +
    row("Registered", esc(reg.length), reg.length ? "warn" : "ok") +
    (tags ? `<div class="tags" style="margin-top:10px">${tags}</div>` : ""));
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

function cardHeadersRaw(http) {
  const headers = (http && http.headers) || {};
  const keys = Object.keys(headers);
  if (!keys.length) return "";
  const rows = keys.slice(0, 22).map((k) =>
    `<div class="row"><span class="k">${esc(k)}</span><span class="v" style="max-width:60%">${esc(String(headers[k]).slice(0, 60))}</span></div>`).join("");
  return card("HTTP headers", rows);
}

function cardCookies(http) {
  const cookies = (http && http.cookies) || [];
  if (!cookies.length) return "";
  const rows = cookies.slice(0, 10).map((c) => {
    const name = c.split("=")[0];
    const secure = /secure/i.test(c) && /httponly/i.test(c);
    return row(name, secure ? "secure" : "weak flags", secure ? "ok" : "warn");
  }).join("");
  return card("Cookies", rows);
}

function cardFirewall(w) {
  if (!w || w.status !== "ok") return "";
  const waf = w.waf || [];
  return card("Firewall / WAF",
    `<div class="row"><span class="k">Detected</span>${waf.length ? `<span class="v ok">${waf.map(esc).join(", ")}</span>` : `<span class="v muted">none detected</span>`}</div>`);
}

function cardSocial(w) {
  const tags = (w && w.social) || {};
  if (!Object.keys(tags).length) return "";
  const img = tags["og:image"] || tags["twitter:image"];
  const rows = ["og:title", "og:description", "twitter:card"].filter((k) => tags[k])
    .map((k) => row(k, esc(String(tags[k]).slice(0, 50)))).join("");
  const preview = img ? `<img class="og-preview" src="${esc(img)}" alt="" loading="lazy" onerror="this.style.display='none'">` : "";
  return card("Social tags", rows + preview);
}

function cardRobots(w) {
  const robots = (w && w.robots) || {};
  if (!robots.present) return "";
  const dis = (robots.disallows || []).slice(0, 10).map((p) => `<div class="dns-rec">Disallow ${esc(p)}</div>`).join("");
  return card("Crawl rules (robots.txt)",
    row("Sitemaps", esc((robots.sitemaps || []).length)) + row("Disallow rules", esc(robots.disallow_count)) + dis);
}

function cardPages(w) {
  const sitemap = (w && w.sitemap) || {};
  if (!sitemap.present || !(sitemap.pages || []).length) return "";
  const pages = sitemap.pages.slice(0, 12).map((p) => `<div class="dns-rec">${esc(p)}</div>`).join("");
  return card("Pages (sitemap)", row("URLs", esc(sitemap.urls)) + pages);
}

function cardLinks(w) {
  const links = (w && w.links) || {};
  if (links.internal == null) return "";
  const ext = (links.external_domains || []).slice(0, 12).map((d) => `<span class="tag">${esc(d)}</span>`).join("");
  return card("Linked pages",
    row("Internal links", esc(links.internal)) + row("External domains", esc(links.external)) +
    (ext ? `<div class="tags" style="margin-top:10px">${ext}</div>` : ""));
}

function cardSecurityTxt(http) {
  const st = http && http.security_txt;
  if (!st) return "";
  return card("security.txt",
    `<div class="row"><span class="k">Present</span>${st.present ? `<span class="v ok">yes</span>` : `<span class="v warn">no</span>`}</div>`);
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

function cardBlocklists(b) {
  if (!b || b.status !== "ok" || !(b.results || []).length) return "";
  const rows = b.results.map((r) => {
    const v = r.blocked === true ? `<span class="v bad">blocked</span>`
      : r.blocked === false ? `<span class="v ok">not blocked</span>` : `<span class="v muted">unknown</span>`;
    return `<div class="row"><span class="k">${esc(r.filter)}</span>${v}</div>`;
  }).join("");
  return card("DNS block lists", rows);
}

function cardRedirects(rc) {
  if (!rc || !(rc.hops || []).length) return "";
  const hops = rc.hops.map((h) => `<div class="row"><span class="k">${esc(h.status)}</span><span class="v muted">${esc(h.url)}</span></div>`).join("");
  return card("Redirect chain", row("Hops", esc(rc.count)) + (rc.downgrade ? row("Downgrade", "HTTPS&rarr;HTTP", "bad") : "") + hops);
}

function cardDomain(d) {
  if (!d || d.status !== "ok") return "";
  const years = d.age_days != null ? (d.age_days / 365).toFixed(1) + " yrs" : "?";
  return card("Domain (RDAP)",
    (d.registrar ? row("Registrar", esc(d.registrar)) : "") + row("Age", years) +
    (d.expires_in_days != null ? row("Expires in", esc(d.expires_in_days) + " days", d.expires_in_days < 30 ? "bad" : "") : ""));
}

function cardCloud(c) {
  if (!c || !(c.buckets || []).length) return "";
  return card("Cloud storage", c.buckets.map((b) => row(`${esc(b.provider.toUpperCase())} ${esc(b.name)}`, esc(b.access), b.access === "public" ? "bad" : "ok")).join(""));
}

function cardArchive(a) {
  if (!a || a.status !== "ok" || !a.snapshots) return "";
  return card("Archive history",
    (a.first ? row("First archived", esc(a.first)) : "") + row("Snapshots", esc(a.snapshots) + (a.truncated ? "+" : "")));
}

function cardPasses(passes) {
  if (!passes || !passes.length) return "";
  return card(`Passes [${passes.length}]`, `<div class="passes">${passes.map((p) => `<div class="pass-item">${esc(p)}</div>`).join("")}</div>`);
}
