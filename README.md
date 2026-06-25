<div align="center">

<img src="assets/banner.svg" alt="SentinelDeck" width="820">

<p>
  <strong>Passive attack-surface radar for small businesses, agencies, and security consultants.</strong><br>
  One safe scan turns a domain into a clear risk grade, structured JSON, and a client-ready report.
</p>

<p>
  <a href="https://github.com/sanmaxdev/SentinelDeck/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/sanmaxdev/SentinelDeck/ci.yml?style=for-the-badge&labelColor=0a0a0f&color=dc2626&label=CI"></a>
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-dc2626?style=for-the-badge&labelColor=0a0a0f">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-dc2626?style=for-the-badge&labelColor=0a0a0f">
  <img alt="Scans" src="https://img.shields.io/badge/Scans-Passive%20only-dc2626?style=for-the-badge&labelColor=0a0a0f">
</p>

</div>

---

SentinelDeck inspects the public-facing posture of a domain across DNS, HTTP,
TLS, and email authentication, using only the kind of normal lookups any browser
or mail server would make. There is no intrusive scanning, no exploitation, and
nothing a domain owner would not expect. The result is a risk score, an A to F
grade, and a set of prioritised findings with concrete remediation steps.

It is built for the people who need that picture fast: an agency qualifying a
prospect, a consultant producing a client report, or a small team checking its
own footprint.

## Features

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>Passive and safe by design</h3>
      Only standard DNS, HTTP, TLS, and email lookups, the same requests any
      browser or mail server makes. Run it against any domain you are authorised
      to assess.
    </td>
    <td width="50%" valign="top">
      <h3>Accurate, with a confidence model</h3>
      DNS is resolved in-process and certificates are parsed directly. Any check
      that cannot be confirmed is marked unverified and kept out of the score, so
      a client never sees a guess presented as fact.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>Five surfaces in one pass</h3>
      DNS hygiene, HTTP security headers, TLS certificate quality, email
      authentication, and domain registration intelligence, scored together into
      a single picture.
    </td>
    <td width="50%" valign="top">
      <h3>Clear risk score and grade</h3>
      Every finding is weighted by severity into a 0 to 100 risk score and an A to
      F grade, each paired with a prioritised, plain-language remediation step.
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>Change tracking and monitoring</h3>
      Diff any two scans to see what is new, what was resolved, and how the grade
      moved. A non-zero exit code on regression drops straight into a cron job or
      CI step.
    </td>
    <td width="50%" valign="top">
      <h3>Report-ready outputs</h3>
      Structured JSON for automation, a polished dark and red HTML report for
      clients, a shareable score card, an embeddable grade badge, and an HTML
      change report.
    </td>
  </tr>
</table>

## What it checks

| Area | Checks |
| --- | --- |
| **DNS** | Resolution, CAA issuance control, DNSSEC |
| **HTTP** | HTTPS reachability, HTTP to HTTPS redirect, security-header presence **and** value quality, security.txt, cookie flags, version disclosure |
| **TLS** | Trust and failure reason (expired, self-signed, hostname mismatch, untrusted), expiry, protocol version, key strength, signature algorithm, hostname match |
| **Email** | MX, SPF (policy, multiple records, 10-lookup limit), DMARC (policy, subdomain policy, enforcement coverage), DKIM detection |
| **Domain** | Registrar, registration age, and expiry via RDAP |

Every issue is scored by severity into a 0 to 100 risk score and an A to F grade.

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

The `diff` command shows what is new, what was resolved, score and grade
movement, and any severity escalations. It exits non-zero with `--exit-code`
when the posture regresses (a new high or critical finding, or a higher score),
so it drops straight into a cron job or CI step for scheduled monitoring.

Useful flags: `--pretty` prints the full JSON to stdout, `--timeout` bounds the
HTTP and TLS probes, and `diff --json` or `diff -o` emit the structured delta.

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
standard HTTP and TLS metadata requests against the supplied domain. Use it only
on domains you own or are authorised to assess.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). New checks
must be passive-safe and come with tests. Please also read our
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE)
