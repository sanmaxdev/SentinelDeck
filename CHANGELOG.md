# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/), and the project aims
to follow semantic versioning once it reaches 1.0.

## [Unreleased]

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

### Changed

- DNS is resolved in-process with `dnspython` (with a TCP fallback for large
  records) instead of shelling out to `dig`/`host`.
- HTML report restyled to a professional dark and red theme.

## [0.1.0]

- Initial passive scanner: DNS resolution, HTTP security headers, TLS expiry,
  and SPF/DMARC/MX checks, with JSON and HTML reports.
