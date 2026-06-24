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
        "strict-transport-security": "max-age=63072000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    }

    assert evaluate_headers(headers) == []


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
