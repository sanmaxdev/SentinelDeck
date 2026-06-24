# SentinelDeck

**SentinelDeck** is a passive attack-surface radar for small businesses, agencies, and security consultants.

It turns quick domain checks into clean JSON and client-ready HTML reports.

> Status: MVP foundation. Safe/passive checks only.

## What it checks now

- Domain format validation
- DNS resolution summary
- HTTPS reachability (HEAD with GET fallback) and HTTP→HTTPS redirect
- HTTP security headers — presence **and** value quality (HSTS max-age, unsafe CSP directives, weak X-Frame-Options, etc.)
- TLS certificate validity with a classified failure reason (expired, self-signed, hostname mismatch, untrusted) plus expiry and negotiated protocol
- Email-security posture via in-process DNS:
  - MX presence
  - SPF policy strength, multiple-record and 10-lookup-limit checks
  - DMARC policy, subdomain policy, and `pct` enforcement coverage
  - DKIM detection across common selectors
- Risk scoring with actionable findings, where **inconclusive checks are reported as `indeterminate` and never counted toward the score**
- JSON report export
- Client-ready HTML report export

### Accuracy notes

DNS is resolved in-process with [`dnspython`](https://www.dnspython.org/) (with
a TCP fallback for large SPF/DKIM records) instead of shelling out to `dig`/`host`,
which removes a whole class of false negatives in containers and CI. When a
check genuinely cannot be determined (e.g. DNS is unreachable), the related
finding is marked `indeterminate` so a client never sees an unverified issue
presented as fact.

## Install locally

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

## Run

```bash
sentineldeck scan example.com --output reports/example.json
sentineldeck report reports/example.json --html reports/example.html
```

The passive checks (DNS, HTTP, TLS, email) run concurrently, so a scan
finishes close to the speed of the slowest single check. Use `--timeout` to
bound how long the HTTP and TLS probes wait:

```bash
sentineldeck scan example.com --timeout 5 --output reports/example.json
```

Or without installing:

```bash
python3 -m sentineldeck.cli scan example.com --output reports/example.json
```

## Example output

```json
{
  "target": "example.com",
  "risk_score": 35,
  "grade": "B",
  "findings": []
}
```

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest -q
```

CI runs the linter and test suite against Python 3.10, 3.11, and 3.12.

## Safety model

SentinelDeck is **passive-first**. The MVP avoids intrusive vulnerability scanning. It only performs normal DNS lookups and HTTP/TLS metadata checks against the supplied domain.

## Roadmap

- [x] CLI skeleton
- [x] JSON report export
- [x] HTTP header checks
- [x] TLS expiry check
- [x] SPF/DMARC/MX checks
- [x] HTML report
- [x] DKIM detection and deeper SPF/DMARC analysis
- [x] TLS failure classification and protocol checks
- [x] Security-header value validation
- [ ] PDF export
- [ ] Screenshot evidence
- [ ] Scheduled monitoring
- [ ] Telegram/email alerts

## License

MIT
