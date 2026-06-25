# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/), and the project aims
to follow semantic versioning once it reaches 1.0.

## [Unreleased]

### Added

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
