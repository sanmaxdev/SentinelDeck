import json

from sentineldeck.cli import main
from sentineldeck.models import Finding, ScanReport


def _fake_report() -> ScanReport:
    return ScanReport(
        target="example.com",
        generated_at="2026-06-24T21:00:00+00:00",
        risk_score=24,
        grade="B",
        checks={"dns": {"resolved": True}},
        findings=[Finding("dmarc-missing", "DMARC record is missing", "medium", "No DMARC.", "Add DMARC.")],
    )


def test_cli_scan_prints_summary_to_stdout(monkeypatch, capsys):
    monkeypatch.setattr(
        "sentineldeck.cli.scan_domain", lambda target, timeout=10, suppressions=None: _fake_report()
    )

    exit_code = main(["scan", "example.com"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "SentinelDeck score: 24/100 grade=B findings=1" in captured.out


def test_cli_scan_writes_json_output_file(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(
        "sentineldeck.cli.scan_domain", lambda target, timeout=10, suppressions=None: _fake_report()
    )
    output = tmp_path / "out" / "example.json"

    exit_code = main(["scan", "example.com", "--output", str(output)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert output.exists()
    assert f"Report written: {output}" in captured.out
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["grade"] == "B"


def test_cli_scan_forwards_timeout(monkeypatch):
    seen = {}

    def fake_scan(target, timeout=10, suppressions=None):
        seen["timeout"] = timeout
        return _fake_report()

    monkeypatch.setattr("sentineldeck.cli.scan_domain", fake_scan)

    main(["scan", "example.com", "--timeout", "3"])

    assert seen["timeout"] == 3
