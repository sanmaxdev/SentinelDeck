from sentineldeck.scanners.saas_stack import detect_saas


def test_detect_saas_from_txt():
    txt = [
        "shopify-verification=abc",
        "atlassian-domain-verification=xyz",
        "google-site-verification=123",
        "v=spf1 -all",
    ]
    out = detect_saas(txt_records=txt)
    names = {s["name"] for s in out["services"]}
    assert {"Shopify", "Atlassian", "Google Search Console"} <= names
    assert out["count"] == len(out["services"])


def test_detect_saas_from_spf_and_mx():
    out = detect_saas(spf_includes=["_spf.google.com", "sendgrid.net"], mx_records=["aspmx.l.google.com."])
    names = {s["name"] for s in out["services"]}
    assert "Google Workspace" in names
    assert "SendGrid" in names


def test_detect_saas_dedupes():
    # Google appears in both SPF and MX; it should be listed once.
    out = detect_saas(spf_includes=["_spf.google.com"], mx_records=["aspmx.l.google.com."])
    google = [s for s in out["services"] if s["name"] == "Google Workspace"]
    assert len(google) == 1


def test_detect_saas_empty():
    out = detect_saas()
    assert out["count"] == 0
    assert out["services"] == []
