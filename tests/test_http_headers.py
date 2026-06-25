from sentineldeck.scanners.http_headers import evaluate_headers, missing_security_headers


def test_missing_security_headers_lists_absent_headers():
    missing = missing_security_headers({"strict-transport-security": "max-age=63072000"})

    assert "strict-transport-security" not in missing
    assert "content-security-policy" in missing


def test_evaluate_headers_flags_disabled_hsts():
    issues = {i["id"] for i in evaluate_headers({"strict-transport-security": "max-age=0"})}

    assert "hsts-ineffective" in issues


def test_evaluate_headers_flags_short_hsts():
    issues = {i["id"] for i in evaluate_headers({"strict-transport-security": "max-age=3600"})}

    assert "hsts-short-max-age" in issues


def test_evaluate_headers_flags_unsafe_csp():
    issues = {i["id"] for i in evaluate_headers({"content-security-policy": "default-src 'self' 'unsafe-inline'"})}

    assert "csp-unsafe-directives" in issues


def test_evaluate_headers_flags_invalid_nosniff_and_frame_options():
    headers = {"x-content-type-options": "sniff", "x-frame-options": "ALLOWALL"}

    issues = {i["id"] for i in evaluate_headers(headers)}

    assert "x-content-type-options-invalid" in issues
    assert "x-frame-options-invalid" in issues


def test_evaluate_headers_accepts_strong_configuration():
    headers = {
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "cross-origin-opener-policy": "same-origin",
    }

    assert evaluate_headers(headers) == []


def test_evaluate_headers_flags_cors_credentials_wildcard():
    issues = {i["id"]: i for i in evaluate_headers({
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
        "cross-origin-opener-policy": "same-origin",
    })}

    assert issues["cors-credentials-wildcard"]["severity"] == "high"


def test_evaluate_headers_flags_open_cors_and_unsafe_referrer():
    ids = {i["id"] for i in evaluate_headers({
        "access-control-allow-origin": "*",
        "referrer-policy": "unsafe-url",
    })}

    assert "cors-open" in ids
    assert "referrer-policy-unsafe" in ids


def test_evaluate_headers_flags_hsts_not_preloadable_but_accepts_preload():
    weak = {i["id"] for i in evaluate_headers({"strict-transport-security": "max-age=63072000"})}
    assert "hsts-not-preloadable" in weak

    strong = {i["id"] for i in evaluate_headers(
        {"strict-transport-security": "max-age=63072000; includeSubDomains; preload"}
    )}
    assert "hsts-not-preloadable" not in strong


def test_evaluate_headers_flags_cookie_without_samesite():
    ids = {i["id"] for i in evaluate_headers({}, cookies=["sid=x; Secure; HttpOnly"])}

    assert "cookie-no-samesite" in ids


def test_evaluate_headers_flags_missing_coop_only_when_reachable():
    assert "no-coop" in {i["id"] for i in evaluate_headers({"server": "nginx"})}
    # an unreachable site (no headers) must not produce a COOP finding
    assert "no-coop" not in {i["id"] for i in evaluate_headers({})}


def test_evaluate_headers_flags_insecure_cookies():
    issues = {i["id"] for i in evaluate_headers({}, cookies=["sid=abc; Path=/"])}

    assert "insecure-cookies" in issues


def test_evaluate_headers_accepts_hardened_cookies():
    issues = {i["id"] for i in evaluate_headers({}, cookies=["sid=abc; Secure; HttpOnly; SameSite=Lax"])}

    assert "insecure-cookies" not in issues


def test_evaluate_headers_flags_information_disclosure():
    issues = {i["id"] for i in evaluate_headers({"x-powered-by": "PHP/8.1", "server": "nginx/1.25.3"})}

    assert "info-disclosure-x-powered-by" in issues
    assert "info-disclosure-server-version" in issues
