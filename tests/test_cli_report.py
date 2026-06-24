import json

from sentineldeck.cli import main
from sentineldeck.models import Finding, ScanReport


def test_cli_report_writes_html_from_json_report(tmp_path):
    report = ScanReport(
        target="example.com",
        generated_at="2026-06-24T21:00:00+00:00",
        risk_score=12,
        grade="A",
        checks={},
        findings=[Finding("x", "Test finding", "low", "Description", "Fix it")],
    )
    source = tmp_path / "scan.json"
    source.write_text(json.dumps(report.to_dict()), encoding="utf-8")
    output = tmp_path / "report.html"

    exit_code = main(["report", str(source), "--html", str(output)])

    assert exit_code == 0
    assert output.exists()
    assert "Test finding" in output.read_text(encoding="utf-8")
