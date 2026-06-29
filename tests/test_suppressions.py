import sentineldeck.cli as cli_mod
from sentineldeck.models import Finding, ScanReport
from sentineldeck.risk.scoring import score_findings
from sentineldeck.suppressions import apply_suppressions, is_suppressed, load_suppressions


def f(id, sev="medium", suppressed=False):
    return Finding(
        id=id, title=id, severity=sev, description="d", recommendation="r", suppressed=suppressed
    )


def test_load_suppressions_ignores_comments_and_blanks(tmp_path):
    path = tmp_path / "ignore.txt"
    path.write_text("# header\ninsecure-cookies\n\n  missing-*  # accepted\n", encoding="utf-8")

    assert load_suppressions(path) == ["insecure-cookies", "missing-*"]


def test_is_suppressed_supports_exact_and_glob():
    patterns = ["insecure-cookies", "subdomain-takeover:*"]

    assert is_suppressed("insecure-cookies", patterns)
    assert is_suppressed("subdomain-takeover:blog.example.com", patterns)
    assert not is_suppressed("dmarc-missing", patterns)


def test_apply_suppressions_marks_and_excludes_from_score():
    findings = [f("missing-content-security-policy", "medium"), f("insecure-cookies", "low")]
    assert score_findings(findings) == 17

    apply_suppressions(findings, ["insecure-cookies"])

    assert findings[1].suppressed is True
    assert score_findings(findings) == 12  # the accepted low finding no longer counts


def test_apply_suppressions_is_noop_for_empty_patterns():
    findings = [f("x", "medium")]

    apply_suppressions(findings, [])

    assert findings[0].suppressed is False


def test_cli_scan_loads_and_passes_suppressions(tmp_path, monkeypatch):
    sup = tmp_path / "ignore.txt"
    sup.write_text("insecure-cookies\nmissing-*\n", encoding="utf-8")
    captured = {}

    def fake_scan(target, timeout=10, suppressions=None, progress=None, active=False):
        captured["suppressions"] = suppressions
        return ScanReport(
            target="example.com", generated_at="t", risk_score=0, grade="A", checks={}, findings=[]
        )

    monkeypatch.setattr(cli_mod, "scan_target", fake_scan)
    rc = cli_mod.main(["scan", "example.com", "--suppress", str(sup)])

    assert rc == 0
    assert captured["suppressions"] == ["insecure-cookies", "missing-*"]


def test_cli_scan_errors_on_missing_suppress_file(tmp_path, capsys):
    rc = cli_mod.main(["scan", "example.com", "--suppress", str(tmp_path / "nope.txt")])

    assert rc == 2
    assert "suppressions file" in capsys.readouterr().err
