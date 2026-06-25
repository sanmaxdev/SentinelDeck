import sentineldeck.monitor as monitor_mod
from sentineldeck.cli import main
from sentineldeck.models import Finding, ScanReport


def make_report(score, grade, findings):
    return ScanReport(
        target="example.com",
        generated_at="2026-06-01T00:00:00+00:00",
        risk_score=score,
        grade=grade,
        checks={},
        findings=findings,
    )


def test_cli_monitor_baseline_then_regression(tmp_path, capsys, monkeypatch):
    state = tmp_path / "state"

    monkeypatch.setattr(
        monitor_mod, "scan_domain",
        lambda d, timeout=10: make_report(10, "A", [Finding("a", "A", "low", "d", "r")]),
    )
    rc = main(["monitor", "example.com", "--state-dir", str(state)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Baseline" in out
    assert (state / "example.com.json").exists()

    monkeypatch.setattr(
        monitor_mod, "scan_domain",
        lambda d, timeout=10: make_report(
            35, "B", [Finding("a", "A", "low", "d", "r"), Finding("tls-expired", "TLS expired", "high", "d", "r")]
        ),
    )
    rc = main(["monitor", "example.com", "--state-dir", str(state), "--exit-code"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "REGRESSED" in out
    assert "tls-expired" in out


def test_cli_monitor_writes_html_change_report(tmp_path, capsys, monkeypatch):
    state = tmp_path / "state"
    monkeypatch.setattr(monitor_mod, "scan_domain", lambda d, timeout=10: make_report(10, "A", []))
    main(["monitor", "example.com", "--state-dir", str(state)])

    monkeypatch.setattr(
        monitor_mod, "scan_domain",
        lambda d, timeout=10: make_report(30, "B", [Finding("tls-expired", "TLS expired", "high", "d", "r")]),
    )
    html = tmp_path / "change.html"
    rc = main(["monitor", "example.com", "--state-dir", str(state), "--html", str(html)])

    assert rc == 0
    assert html.exists()
    assert "SentinelDeck Change Report" in html.read_text(encoding="utf-8")
