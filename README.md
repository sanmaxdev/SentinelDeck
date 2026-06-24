# SentinelDeck

**SentinelDeck** is a passive attack-surface radar for small businesses, agencies, and security consultants.

It turns quick domain checks into clean JSON and client-ready HTML reports.

> Status: MVP foundation. Safe/passive checks only.

## What it checks now

- Domain format validation
- DNS resolution summary
- HTTPS reachability
- HTTP security headers
- TLS certificate expiry
- MX, SPF, and DMARC email-security posture
- Risk scoring with actionable findings
- JSON report export
- Client-ready HTML report export

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

## Safety model

SentinelDeck is **passive-first**. The MVP avoids intrusive vulnerability scanning. It only performs normal DNS lookups and HTTP/TLS metadata checks against the supplied domain.

## Roadmap

- [x] CLI skeleton
- [x] JSON report export
- [x] HTTP header checks
- [x] TLS expiry check
- [x] SPF/DMARC/MX checks
- [x] HTML report
- [ ] PDF export
- [ ] Screenshot evidence
- [ ] Scheduled monitoring
- [ ] Telegram/email alerts

## License

MIT
