from datetime import datetime, timezone

from sentineldeck.risk.scoring import build_findings
from sentineldeck.scanners.domain_intel import analyze_domain_intel

NOW = datetime(2026, 6, 24, tzinfo=timezone.utc)

RDAP = {
    "events": [
        {"eventAction": "registration", "eventDate": "2025-06-01T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-07-01T00:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]],
        }
    ],
}


def test_analyze_domain_intel_parses_rdap():
    out = analyze_domain_intel("example.com", fetcher=lambda d, t: RDAP, now=NOW)

    assert out["status"] == "ok"
    assert out["registrar"] == "Example Registrar"
    assert out["expires_in_days"] == 7
    assert out["age_days"] > 300


def test_domain_intel_findings_flag_expiry_and_newness():
    rdap = {
        "events": [
            {"eventAction": "registration", "eventDate": "2026-06-10T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-07-01T00:00:00Z"},
        ]
    }
    out = analyze_domain_intel("x.com", fetcher=lambda d, t: rdap, now=NOW)

    finding_ids = {f.id for f in build_findings({"domain_intel": out})}

    assert "domain-expiring-soon" in finding_ids
    assert "domain-newly-registered" in finding_ids


def test_domain_intel_error_yields_no_findings():
    out = analyze_domain_intel("x.com", fetcher=lambda d, t: None, now=NOW)

    assert out == {"status": "error"}
    finding_ids = {f.id for f in build_findings({"domain_intel": out})}
    assert "domain-expiring-soon" not in finding_ids
    assert "domain-newly-registered" not in finding_ids
