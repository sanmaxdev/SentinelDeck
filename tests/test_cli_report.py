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


def _write_sample_report(tmp_path):
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
    return source


def test_cli_report_writes_svg_card_and_badge(tmp_path):
    source = _write_sample_report(tmp_path)
    card = tmp_path / "card.svg"
    badge = tmp_path / "badge.svg"

    exit_code = main(["report", str(source), "--svg", str(card), "--badge", str(badge)])

    assert exit_code == 0
    assert card.read_text(encoding="utf-8").startswith("<svg")
    assert badge.read_text(encoding="utf-8").startswith("<svg")


def test_cli_report_requires_an_output(tmp_path, capsys):
    source = _write_sample_report(tmp_path)

    exit_code = main(["report", str(source)])

    assert exit_code == 2
    assert "at least one" in capsys.readouterr().err
