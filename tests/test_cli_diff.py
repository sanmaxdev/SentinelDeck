import json

from sentineldeck.cli import main
from sentineldeck.models import Finding, ScanReport


def _write(tmp_path, name, score, grade, findings, when="2026-06-01T00:00:00+00:00"):
    report = ScanReport(
        target="example.com",
        generated_at=when,
        risk_score=score,
        grade=grade,
        checks={},
        findings=findings,
    )
    path = tmp_path / name
    path.write_text(json.dumps(report.to_dict()), encoding="utf-8")
    return path


def test_cli_diff_prints_summary(tmp_path, capsys):
    previous = _write(tmp_path, "old.json", 5, "A", [Finding("caa-missing", "No CAA", "low", "d", "r")])
    current = _write(tmp_path, "new.json", 30, "B", [Finding("tls-expired", "TLS expired", "high", "d", "r")])

    exit_code = main(["diff", str(previous), str(current)])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "change report" in out.lower()
    assert "REGRESSED" in out
    assert "tls-expired" in out
    assert "caa-missing" in out


def test_cli_diff_writes_json_and_html(tmp_path):
    previous = _write(tmp_path, "old.json", 5, "A", [])
    current = _write(tmp_path, "new.json", 30, "B", [Finding("tls-expired", "TLS expired", "high", "d", "r")])
    out_json = tmp_path / "delta.json"
    out_html = tmp_path / "delta.html"

    exit_code = main(["diff", str(previous), str(current), "-o", str(out_json), "--html", str(out_html)])

    assert exit_code == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["direction"] == "regressed"
    assert data["new_findings"][0]["id"] == "tls-expired"
    assert "SentinelDeck Change Report" in out_html.read_text(encoding="utf-8")


def test_cli_diff_exit_code_flags_regression(tmp_path):
    previous = _write(tmp_path, "old.json", 5, "A", [])
    current = _write(tmp_path, "new.json", 30, "B", [Finding("tls-expired", "TLS expired", "high", "d", "r")])

    assert main(["diff", str(previous), str(current), "--exit-code"]) == 1


def test_cli_diff_exit_code_zero_when_improved(tmp_path):
    previous = _write(tmp_path, "old.json", 30, "B", [Finding("tls-expired", "TLS expired", "high", "d", "r")])
    current = _write(tmp_path, "new.json", 5, "A", [])

    assert main(["diff", str(previous), str(current), "--exit-code"]) == 0
