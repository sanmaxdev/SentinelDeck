# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/), and the project aims
to follow semantic versioning once it reaches 1.0.

## [2.2.2] - 2026-06-29

### Added

- `python -m sentineldeck` now runs the CLI — a PATH-independent way to start it
  when pip does a user install and its Scripts directory is not on PATH (so the
  bare `sentineldeck` command is not found). The README documents the fallback.

## [2.2.1] - 2026-06-29

### Fixed

- `sentineldeck dashboard` no longer crashes with a stack trace when its port is
  already in use or blocked by the OS (for example Windows error 10013). It now
  falls back to another free port — and finally an OS-assigned one — and prints
  the address it actually bound.

## [2.2.0] - 2026-06-29

### Added

- Network footprint mapping. From the resolved host SentinelDeck now finds the
  owning autonomous system and every prefix it announces (via RIPEstat, free and
  keyless), so one domain or IP reveals the organisation's whole routed IP estate
  — the ASN, operator, total announced prefixes, and IPv4 address space — shown in
  a new dashboard card.

## [2.1.0] - 2026-06-29

### Added

- Exposure and CVE intelligence. Every scan now consults Shodan InternetDB (free,
  keyless) for the resolved host: the open ports, service tags, and the published
  CVEs already associated with it, returned passively without touching the host.
  Those CVEs are cross-referenced against the CISA Known Exploited Vulnerabilities
  catalog, so any that are confirmed exploited in the wild are highlighted and
  raise a scored finding. A new dashboard card shows the exposure surface with the
  KEV CVEs called out.
- SaaS footprint decoding. The TXT verification tokens, SPF includes, and MX hosts
  a domain publishes are decoded into the products the organisation actually uses
  (Microsoft 365, Google Workspace, Atlassian, Shopify, Stripe, Jamf, Loom, and
  many more) and shown in a new dashboard card — intelligence read out of records
  the scan already collected.

## [2.0.0] - 2026-06-29

### Added

- Scan an IP address, not just a domain. The search box and `sentineldeck scan`
  now accept a bare IP (v4 or v6) or a URL as well as a hostname, auto-detect
  which it is, and run an IP-focused recon pipeline: geolocation and ASN, the
  network allocation via RDAP (owning organisation, CIDR block, and the abuse
  contact for reporting a malicious host), reverse-IP hosted domains (what else
  lives on the address), reverse DNS, threat reputation, TLS, HTTP headers,
  technology fingerprint, and an optional active port scan. Domain-only surfaces
  (email authentication, subdomains, typosquatting) are skipped, and a private or
  reserved IP runs only the locally reachable surfaces.
- Two new dashboard cards: Network allocation (RDAP), including the abuse
  contact, and Reverse IP, listing the domains hosted on the address.

## [1.3.0] - 2026-06-29

### Added

- A live telemetry console in the web dashboard. While a scan runs, every surface
  streams in as a timestamped line with a short result summary (address count,
  TLS protocol, subdomains found, lookalikes registered, server location, and
  more), with a running elapsed clock and a blinking cursor, so you can watch the
  scan work instead of staring at a spinner.
- Packed the dashboard result cards into a masonry layout, so a tall card (like
  full DNS records) no longer stretches its shorter neighbours into empty space.

## [1.2.2] - 2026-06-29

### Fixed

- A single failing probe no longer aborts the whole scan. Every surface now
  degrades to an error state on its own, so one broken check can never take down
  the rest of the report.

### Changed

- Added type checking (mypy), test-coverage reporting, and a headless
  dashboard-render check to the test suite and CI, so a missing UI function or a
  type error is caught before release rather than after.

## [1.2.1] - 2026-06-29

### Fixed

- The dashboard could hang on "scanning" after a scan finished because the
  threat-reputation card renderer was missing. Restored it, and a render error
  now shows a message instead of leaving the page stuck.

## [1.2.0] - 2026-06-29

### Changed

- Redesigned the web dashboard with a terminal-style theme: monospace type, a
  grid-divided layout, and 90-degree corners.
- Added a dark / light mode toggle that remembers your choice.
- Added a security-posture radar (TLS, email, DNS, headers, surface, trust) and a
  server-location map drawn from continent outlines with a coordinate pin.
- Made the active-scan toggle clearly labelled, and removed the per-finding
  checkboxes from the findings list.

### Fixed

- Sped up the scan: typosquatting now uses a short-timeout resolver for its bulk
  lookups, and the certificate-transparency and archive lookups no longer retry
  for as long, so a slow source cannot stall the whole scan.

## [1.1.0] - 2026-06-29

### Added

- Much deeper data in the dashboard: full DNS records (A/AAAA/MX/NS/SOA/TXT),
  raw HTTP headers, cookies, social tags with an Open Graph image preview,
  robots.txt rules, sitemap pages, linked domains, a security.txt card, and a
  server-status card with response time.
- New checks: TLS connection detail (cipher suite, ALPN, forward secrecy) and
  certificate serial / SHA-256 fingerprint / extended key usage; reverse DNS host
  names; a server-location map; DNS blocklist checks (Cloudflare, Quad9, AdGuard,
  and others); and Cross-Origin-Resource-Policy / Embedder-Policy headers.
- A "Passes" roll-up that shows what the domain gets right.
- An active-scan toggle in the dashboard (off by default, runs the port scan).

## [1.0.0] - 2026-06-28

### Added

- Interactive remediation simulator in the web dashboard: tick a finding as
  fixed and the projected grade and risk score recompute live, the same idea as
  the HTML report's simulator, now in the browser dashboard.
- A web-dashboard preview in the README.

### Changed

- First stable release. SentinelDeck now spans DNS, email authentication, HTTP,
  TLS, certificate transparency, technology fingerprinting, infrastructure
  intelligence, and threat intelligence, delivered through a colored CLI and a
  local web dashboard, passive by default with an opt-in active mode.

## [0.9.0] - 2026-06-28

### Added

- TLS configuration depth: enumerates the protocol versions the server accepts
  (TLS 1.0 through 1.3), assigns a Mozilla-style configuration grade, and raises
  a finding when deprecated TLS 1.0/1.1 are still supported.
- Optional active port scan (`scan --active`): connects to common TCP ports and
  flags risky exposed services (databases, RDP, and the like). Off by default so
  the standard scan stays passive and safe to run on any domain.
- Dashboard cards for TLS configuration and open ports.

## [0.8.0] - 2026-06-28

### Added

- Typosquatting / lookalike-domain detection: generates misspelling and
  homoglyph variants of the domain and reports which are registered and resolve,
  with a finding and brand-protection guidance. A single scan becomes brand
  monitoring.
- Threat reputation: checks the domain against the abuse.ch URLhaus feed for
  malware/phishing listings (best-effort; degrades gracefully where the feed is
  unreachable).
- Wayback Machine archive history: first-archived year and snapshot count.
- New dashboard cards for lookalike domains, threat reputation, and archive
  history.

## [0.7.0] - 2026-06-28

### Added

- IP intelligence: geolocation, ASN, and hosting provider for the resolved
  address (a new dashboard card).
- Full redirect chain: every hop from http:// to the final URL, and a finding
  when the chain downgrades HTTPS to HTTP.
- Web-content checks from the homepage: WAF/CDN fingerprinting, internal vs
  external link analysis, Open Graph / Twitter social tags, robots.txt, and
  sitemap.xml. New dashboard cards for each.

## [0.6.0] - 2026-06-28

### Added

- A local web dashboard. `sentineldeck dashboard` starts a localhost-only server,
  opens your browser, and runs the same passive scan with live progress streamed
  over Server-Sent Events. Results render as a grid of cards: the grade, findings
  with copy-paste fixes, technology stack, TLS, email authentication, DNS,
  subdomains, security headers, domain registration, and cloud storage. It needs
  no extra dependencies and binds to 127.0.0.1 only.

## [0.5.0] - 2026-06-27

### Added

- Technology fingerprinting: identifies the CMS, framework, web server, CDN, and
  analytics from the homepage (headers + HTML), with versions where detectable.
  The detected stack shows in the scan summary and the JSON report.
- Vulnerable JavaScript detection: flags known-vulnerable library versions
  (jQuery, Bootstrap, lodash, moment, AngularJS, and more) from script tags,
  each with an advisory and an upgrade fix.
- Cloud-storage exposure: finds S3, Google Cloud Storage, and Azure Blob buckets
  referenced on the site and flags any that allow public listing (high), with a
  provider-specific lock-down fix.
- A passive-DNS subdomain source (HackerTarget) merged with certificate
  transparency for broader attack-surface coverage.

## [0.4.0] - 2026-06-25

### Added

- HTTP security-header depth: CORS misconfiguration (a wildcard origin with
  credentials is flagged high), Referrer-Policy quality, HSTS preload
  eligibility, cookie SameSite, and Cross-Origin-Opener-Policy. Each ships a
  copy-paste fix.
- Live scan progress. An interactive scan streams each surface (DNS, TLS, HTTP,
  email, certificate transparency) as it finishes, on stderr so piped output
  stays clean.
- A red ASCII-art SENTINELDECK banner on the home screen.
- New commands: `checks` lists every check; `explain <finding-id>` prints the
  copy-paste fix for a finding; `version` prints the installed version.
- `scan` now writes HTML, score-card, and badge output directly (`--html`,
  `--svg`, `--badge`) and prints the absolute path of every file it saves.

## [0.3.0] - 2026-06-25

### Added

- Email and DNS depth, closing gaps versus internet.nl: DKIM key-strength
  detection (flags keys under 2048-bit), MTA-STS policy fetch and validation
  (the HTTPS policy file, not just the DNS record), nameserver-redundancy
  (single-nameserver) checks, IPv6/AAAA readiness, and DANE/TLSA detection. Each
  carries a copy-paste fix.

## [0.2.0] - 2026-06-25

### Added

- A branded home screen. Running `sentineldeck` with no command now shows the
  logo, the available commands, quick-start examples, and a tip in the
  SentinelDeck colours, instead of an argument error.
- Colorized scan output. An interactive terminal shows a grade banner and
  severity-coloured findings; the raw JSON is still emitted when the output is
  piped or `--pretty` is passed, so automation is unaffected.

### Fixed

- The `cryptography` deprecation warnings no longer leak into scan output (the
  timezone-aware certificate accessors are used when available).

## [0.1.0] - 2026-06-25

First public release: one safe, passive scan turns a domain into a risk score,
an A to F grade, an attack-surface map, copy-paste fixes, and a client-ready
report.

### Added

- Suppressions file. `scan --suppress FILE` accepts findings you have reviewed
  (finding ids, one per line, globs and `#` comments allowed). Accepted findings
  still appear in the report under "Accepted" but are excluded from the score, so
  a known, accepted risk stops dragging the grade down on every re-scan.
- Email hardening checks for MTA-STS, TLS-RPT, and BIMI. The scan detects these
  records and, when relevant (MTA-STS and TLS-RPT for domains that receive mail,
  BIMI once DMARC is enforced), surfaces an informational finding with a
  copy-paste DNS fix. They never penalise the score.
- `monitor` command for scheduled monitoring. It scans a domain, diffs the
  result against the report saved from the previous run, and stores the new
  report as the latest, turning a cron job or scheduled task into a standing
  watch. With `--webhook` it posts an alert (Slack, Discord, or any custom
  endpoint) when the posture regresses, `--alert-on change` widens that to any
  change, and `--exit-code` fails the job on regression. The first run for a
  domain just establishes a baseline.
- Subdomain-takeover detection. After discovering subdomains, the scan resolves
  each CNAME and flags any that point to an unclaimed third-party service (GitHub
  Pages, Heroku, S3, Azure, Fastly, Shopify, and more) as a high-severity
  finding, confirmed by the provider's own "no such resource" page so false
  positives stay near zero. Passive and offline-testable.
- Subdomain discovery via certificate transparency. The scan now maps a domain's
  public attack surface by reading CT logs (crt.sh, with a CertSpotter fallback
  because crt.sh is frequently down), lists the hostnames in the JSON and a new
  Attack Surface section of the HTML report, and flags potentially sensitive
  names such as dev, staging, admin, and vpn. Passive and offline-testable.
- Remediation intelligence. Every finding now carries a concrete copy-paste fix
  (the exact DNS record, HTTP header, or server config) with an authoritative
  reference, in both the JSON and HTML reports. The HTML report gains an
  interactive Remediation Simulator: tick the fixes you plan to make and the
  projected score and grade update live, with a one-click "quick wins" that
  selects the fewest fixes needed to reach grade A.
- `diff` command that compares two saved scan reports and reports what is new,
  what was resolved, score and grade movement, and severity escalations. It
  renders a themed HTML change report (`--html`), emits the structured delta
  (`--json` / `-o`), and exits non-zero with `--exit-code` when the posture
  regresses. This is the foundation for scheduled monitoring and alerting.
- DNS-over-HTTPS fallback in the resolver: when direct port-53 DNS cannot reach a
  nameserver (blocked egress, captive portals, locked-down networks), the MX,
  SPF, DMARC, CAA, and DNSKEY lookups fall back to DoH over port 443 instead of
  degrading to unverified. The fallback runs only on a hard resolver failure and
  never overrides an authoritative answer.
- A shared per-scan resolver with a DoH circuit breaker: the first hard port-53
  failure trips it once, so the remaining email and DNS-hygiene lookups skip the
  direct timeout and go straight to DoH. On a blocked network a full scan drops
  from minutes to seconds.
- Deep TLS inspection using the `cryptography` library: the leaf certificate is
  parsed directly, so subject, SANs, key type and size, signature algorithm,
  self-signed status, and hostname match are reported even when the chain does
  not validate. Weak keys and weak signatures are flagged.
- DNS hygiene checks for CAA issuance control and DNSSEC.
- Domain intelligence via RDAP: registrar, registration age, and expiry, with
  findings for very new or soon-to-expire domains.
- HTTP checks for security.txt (RFC 9116), insecure cookies, and version
  disclosure via the `Server` and `X-Powered-By` headers.
- Security-header value validation (HSTS max-age, unsafe CSP directives, weak
  `X-Frame-Options`, and more) in addition to presence checks.
- Shareable SVG score card and embeddable grade badge, via `report --svg` and
  `report --badge`.
- `confidence` field on findings; inconclusive checks are reported but never
  counted toward the score.
- Concurrent scanning and a configurable `--timeout`.
- Passive baseline: DNS resolution, HTTP security headers, TLS validity and
  expiry, and SPF/DMARC/MX email checks, with JSON and HTML reports.

### Changed

- DNS is resolved in-process with `dnspython` (with a TCP fallback for large
  records) instead of shelling out to `dig`/`host`.
- HTML report restyled to a professional dark and red theme.
