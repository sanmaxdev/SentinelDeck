import json

from sentineldeck.models import Finding, ScanReport
from sentineldeck.reporters.json_report import write_json_report


def sample_report() -> ScanReport:
    return ScanReport(
        target="example.com",
        generated_at="2026-06-24T21:00:00+00:00",
        risk_score=17,
        grade="A",
        checks={"dns": {"resolved": True}},
        findings=[Finding("spf-missing", "SPF record is missing", "medium", "No SPF.", "Add SPF.")],
    )


def test_write_json_report_creates_parent_directory(tmp_path):
    output = tmp_path / "reports" / "scan.json"

    path = write_json_report(sample_report(), output)

    assert path == output
    assert output.exists()


def test_write_json_report_is_valid_roundtrippable_json(tmp_path):
    output = tmp_path / "scan.json"

    write_json_report(sample_report(), output)
    text = output.read_text(encoding="utf-8")
    data = json.loads(text)

    assert text.endswith("\n")
    assert data["target"] == "example.com"
    assert data["risk_score"] == 17
    assert data["findings"][0]["id"] == "spf-missing"
