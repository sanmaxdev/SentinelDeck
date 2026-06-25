from functools import partial

from sentineldeck.scanners import dns_lookup
from sentineldeck.scanners.dns_lookup import ERROR, NXDOMAIN, OK, resolve
from sentineldeck.scanners.email_security import analyze_email_security


def doh(answers, status=0):
    return lambda name, record_type, timeout: {"Status": status, "Answer": answers}


def test_resolve_doh_parses_mx():
    records, status = dns_lookup._resolve_doh(
        "example.com", "MX", 5.0, doh([{"type": 15, "data": "10 mx1.example.com."}])
    )

    assert (records, status) == (["10 mx1.example.com."], OK)


def test_resolve_doh_strips_and_joins_txt_chunks():
    fetcher = doh([{"type": 16, "data": '"v=spf1 +a +mx " "include:spf.example.com ~all"'}])

    records, status = dns_lookup._resolve_doh("example.com", "TXT", 5.0, fetcher)

    assert (records, status) == (["v=spf1 +a +mx include:spf.example.com ~all"], OK)


def test_resolve_doh_filters_to_requested_type():
    # A CNAME hop and the A record share the Answer section; keep only the A.
    fetcher = doh([
        {"type": 5, "data": "cdn.example.com."},
        {"type": 1, "data": "93.184.216.34"},
    ])

    records, status = dns_lookup._resolve_doh("www.example.com", "A", 5.0, fetcher)

    assert (records, status) == (["93.184.216.34"], OK)


def test_resolve_doh_maps_nxdomain():
    out = dns_lookup._resolve_doh("nope.example.com", "MX", 5.0, doh([], status=3))

    assert out == ([], NXDOMAIN)


def test_resolve_doh_maps_servfail_to_error():
    out = dns_lookup._resolve_doh("example.com", "MX", 5.0, doh([], status=2))

    assert out == ([], ERROR)


def test_resolve_doh_no_answer_is_ok():
    out = dns_lookup._resolve_doh("example.com", "TXT", 5.0, doh([]))

    assert out == ([], OK)


def test_resolve_doh_failed_fetch_is_error():
    out = dns_lookup._resolve_doh("example.com", "MX", 5.0, lambda *a: None)

    assert out == ([], ERROR)


def test_resolve_falls_back_to_doh_when_direct_fails(monkeypatch):
    monkeypatch.setattr(dns_lookup, "_resolve_direct", lambda *a: ([], ERROR))
    fetcher = doh([{"type": 15, "data": "5 mail.example.com."}])

    records, status = resolve("example.com", "MX", doh_fetcher=fetcher)

    assert (records, status) == (["5 mail.example.com."], OK)


def test_resolve_skips_doh_when_direct_succeeds(monkeypatch):
    monkeypatch.setattr(dns_lookup, "_resolve_direct", lambda *a: (["1.2.3.4"], OK))

    def boom(*a):
        raise AssertionError("DoH must not run when direct DNS works")

    assert resolve("example.com", "A", doh_fetcher=boom) == (["1.2.3.4"], OK)


def test_resolve_respects_enable_doh_false(monkeypatch):
    monkeypatch.setattr(dns_lookup, "_resolve_direct", lambda *a: ([], ERROR))

    def boom(*a):
        raise AssertionError("DoH is disabled")

    assert resolve("example.com", "MX", doh_fetcher=boom, enable_doh=False) == ([], ERROR)


def test_email_security_resolves_via_doh_when_direct_is_blocked(monkeypatch):
    # The whole point: port-53 blocked, but email posture still resolves over 443.
    monkeypatch.setattr(dns_lookup, "_resolve_direct", lambda name, rt, t: ([], ERROR))
    answers = {
        ("example.com", "MX"): [{"type": 15, "data": "10 mail.example.com."}],
        ("example.com", "TXT"): [{"type": 16, "data": '"v=spf1 mx -all"'}],
    }

    def fetcher(name, record_type, timeout):
        return {"Status": 0, "Answer": answers.get((name, record_type), [])}

    out = analyze_email_security("example.com", resolver=partial(resolve, doh_fetcher=fetcher))

    assert out["mx"]["present"] is True
    assert out["spf"]["present"] is True
    assert out["spf"]["policy"] == "-all"


def test_resolver_trips_to_doh_after_first_direct_failure(monkeypatch):
    counts = {"direct": 0, "doh": 0}

    def fake_direct(name, record_type, timeout):
        counts["direct"] += 1
        return [], ERROR

    def fake_doh(name, record_type, timeout):
        counts["doh"] += 1
        return {"Status": 0, "Answer": [{"type": 15, "data": "5 mail.example.com."}]}

    monkeypatch.setattr(dns_lookup, "_resolve_direct", fake_direct)
    resolver = dns_lookup.Resolver(doh_fetcher=fake_doh)

    # First lookup tries direct (which fails), trips the breaker, then uses DoH.
    assert resolver("example.com", "MX") == (["5 mail.example.com."], OK)
    assert counts == {"direct": 1, "doh": 1}

    # Once tripped, later lookups skip the direct timeout entirely.
    resolver("example.com", "TXT")
    assert counts == {"direct": 1, "doh": 2}


def test_resolver_stays_direct_when_dns_works(monkeypatch):
    monkeypatch.setattr(dns_lookup, "_resolve_direct", lambda *a: (["1.2.3.4"], OK))

    def boom(*a):
        raise AssertionError("DoH must not run while direct DNS works")

    resolver = dns_lookup.Resolver(doh_fetcher=boom)

    assert resolver("example.com", "A") == (["1.2.3.4"], OK)
    assert resolver("example.com", "A") == (["1.2.3.4"], OK)


def test_resolver_retries_direct_when_doh_fails_after_trip(monkeypatch):
    counts = {"direct": 0}

    def fake_direct(name, record_type, timeout):
        counts["direct"] += 1
        return [], ERROR

    monkeypatch.setattr(dns_lookup, "_resolve_direct", fake_direct)
    resolver = dns_lookup.Resolver(doh_fetcher=lambda *a: None)  # DoH always fails

    assert resolver("example.com", "MX") == ([], ERROR)
    # Breaker tripped, but since DoH keeps failing it must fall back to direct.
    assert resolver("example.com", "TXT") == ([], ERROR)
    assert counts["direct"] == 2
