# Changelog

All notable changes to this project are documented here. The format is loosely
based on [Keep a Changelog](https://keepachangelog.com/), and the project aims
to follow semantic versioning once it reaches 1.0.

## [Unreleased]

### Added

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
