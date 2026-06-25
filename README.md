<h1 align="center">SentinelDeck</h1>

<p align="center">
  <strong>Passive attack-surface radar for small businesses, agencies, and security consultants.</strong><br>
  One safe scan turns a domain into a clear risk grade, structured JSON, and a client-ready report.
</p>

<p align="center">
  <img alt="CI" src="https://github.com/sanmaxdev/SentinelDeck/actions/workflows/ci.yml/badge.svg">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Status" src="https://img.shields.io/badge/status-alpha-orange">
</p>

---

SentinelDeck inspects the public-facing posture of a domain — DNS, HTTP, TLS,
and email authentication — using only the kind of normal lookups any browser or
mail server would make. No intrusive scanning, no exploitation, nothing a domain
owner would not expect. The result is a risk score, an A–F grade, and a set of
prioritised findings with concrete remediation steps.

It is built for the people who need that picture fast: an agency qualifying a
prospect, a consultant producing a client report, or a small team checking its
own footprint.

## Why SentinelDeck

- **Passive and safe by design** — only standard DNS / HTTP / TLS metadata, so
  you can run it against any domain you are authorised to assess.
- **Accurate, not noisy** — DNS is resolved in-process, certificates are parsed
  directly, and any check that cannot be determined is marked *unverified* and
  kept out of the score. A client never sees a guess presented as fact.
- **Report-ready** — export clean JSON for automation, a polished dark-themed
  HTML report for clients, and a shareable score card or badge.

## What it checks

| Area | Checks |
| --- | --- |
| **DNS** | Resolution, CAA issuance control, DNSSEC |
| **HTTP** | HTTPS reachability, HTTP→HTTPS redirect, security-header presence **and** value quality, security.txt, cookie flags, version disclosure |
| **TLS** | Trust and failure reason (expired / self-signed / hostname mismatch / untrusted), expiry, protocol version, key strength, signature algorithm, hostname match |
| **Email** | MX, SPF (policy, multiple records, 10-lookup limit), DMARC (policy, subdomain policy, enforcement coverage), DKIM detection |
| **Domain** | Registrar, registration age, and expiry via RDAP |

Every issue is scored by severity into a 0–100 risk score and an A–F grade.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Usage

Scan a domain and write a JSON report:

```bash
sentineldeck scan example.com --output reports/example.json
```

Render a client-ready HTML report, a shareable score card, and a badge:

```bash
sentineldeck report reports/example.json \
  --html reports/example.html \
  --svg  reports/example-card.svg \
  --badge reports/example-badge.svg
```

Track how a domain's posture changes between two scans:

```bash
sentineldeck diff reports/example-may.json reports/example-june.json \
  --html reports/example-change.html
```

`diff` shows what is new, what was resolved, score and grade movement, and any
severity escalations. It exits non-zero with `--exit-code` when the posture
regresses (a new high/critical finding or a higher score), so it drops straight
into a cron job or CI step for scheduled monitoring.

Useful flags: `--pretty` prints the full JSON to stdout, `--timeout` bounds the
HTTP/TLS probes, and `diff --json` / `diff -o` emit the structured delta.

## Example output

```json
{
  "target": "example.com",
  "risk_score": 27,
  "grade": "B",
  "findings": [
    { "id": "dmarc-missing", "severity": "medium", "confidence": "confirmed", "...": "..." }
  ]
}
```

## How it works

```
src/sentineldeck/
├── scanner.py          # runs every probe concurrently and assembles the report
├── scanners/           # one module per surface: dns, dns_hygiene, tls,
│                       #   http_headers, email_security, domain_intel
├── risk/scoring.py     # turns raw check results into scored findings
├── diff.py             # compares two reports into a structured change delta
├── reporters/          # json, html, svg (card + badge), and diff renderers
└── models.py           # Finding and ScanReport data models
```

Each scanner is independent and keeps its network call injectable, so the whole
suite is tested offline with mocked DNS and HTTP.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

CI runs the linter and test suite on Python 3.10, 3.11, and 3.12.

## Safety model

SentinelDeck is **passive-first**. It performs only normal DNS lookups and
standard HTTP/TLS metadata requests against the supplied domain. Use it only on
domains you own or are authorised to assess.

## Roadmap

- [x] Passive DNS, HTTP, TLS, and email checks
- [x] Deep certificate inspection, DNS hygiene, and domain intelligence
- [x] JSON, HTML, score card, and badge outputs
- [x] Scan-to-scan diffing and change reports (foundation for monitoring)
- [ ] PDF export
- [ ] Scheduled monitoring runner
- [ ] Telegram / email alerts

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). New checks
must be passive-safe and come with tests. Please also read our
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE)
