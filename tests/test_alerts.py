from sentineldeck.alerts import build_alert, send_alert, should_alert
from sentineldeck.diff import diff_reports
from sentineldeck.models import Finding, ScanReport


def report(target, score, grade, findings):
    return ScanReport(
        target=target, generated_at="t", risk_score=score, grade=grade, checks={}, findings=findings
    )


def f(id, sev):
    return Finding(id=id, title=f"{id} title", severity=sev, description="d", recommendation="r")


def regressed_delta():
    return diff_reports(report("example.com", 5, "A", []), report("example.com", 30, "B", [f("tls-expired", "high")]))


def test_should_alert_regression_is_default():
    assert should_alert(regressed_delta()) is True

    improved = diff_reports(report("e", 30, "B", [f("x", "high")]), report("e", 5, "A", []))
    assert should_alert(improved) is False


def test_should_alert_modes_for_flat_churn():
    delta = diff_reports(report("e", 10, "A", [f("a", "low")]), report("e", 10, "A", [f("b", "low")]))

    assert delta.direction == "changed"
    assert should_alert(delta, "regression") is False
    assert should_alert(delta, "change") is True
    assert should_alert(delta, "always") is True


def test_build_alert_payload_has_message_and_delta():
    payload = build_alert(regressed_delta())

    assert "example.com" in payload["text"]
    assert "REGRESSED" in payload["text"]
    assert "[HIGH] tls-expired title" in payload["text"]
    assert payload["text"] == payload["content"]  # Slack and Discord both covered
    assert payload["delta"]["regressed"] is True


def test_send_alert_routes_through_sender():
    captured = {}

    def sender(url, payload, timeout):
        captured["url"] = url
        captured["payload"] = payload
        return True

    ok = send_alert("https://hooks.example/abc", regressed_delta(), sender=sender)

    assert ok is True
    assert captured["url"] == "https://hooks.example/abc"
    assert "REGRESSED" in captured["payload"]["text"]
