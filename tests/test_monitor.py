from sentineldeck.models import Finding, ScanReport
from sentineldeck.monitor import monitor_domain


def report(target, score, grade, findings, when="2026-06-01T00:00:00+00:00"):
    return ScanReport(
        target=target, generated_at=when, risk_score=score, grade=grade, checks={}, findings=findings
    )


def f(id, sev="medium"):
    return Finding(id=id, title=id, severity=sev, description="d", recommendation="r")


def test_first_run_is_baseline(tmp_path):
    rep = report("example.com", 10, "A", [f("a", "low")])

    out = monitor_domain("example.com", state_dir=tmp_path, scan_fn=lambda d, timeout=10: rep)

    assert out["baseline"] is True
    assert out["delta"] is None
    assert (tmp_path / "example.com.json").exists()


def test_second_run_diffs_against_saved_state(tmp_path):
    first = report("example.com", 10, "A", [f("a", "low")])
    monitor_domain("example.com", state_dir=tmp_path, scan_fn=lambda d, timeout=10: first)

    second = report("example.com", 35, "B", [f("a", "low"), f("tls-expired", "high")])
    out = monitor_domain("example.com", state_dir=tmp_path, scan_fn=lambda d, timeout=10: second)

    assert out["baseline"] is False
    assert out["delta"].direction == "regressed"
    assert {x.id for x in out["delta"].new_findings} == {"tls-expired"}


def test_state_is_updated_each_run(tmp_path):
    first = report("example.com", 10, "A", [])
    monitor_domain("example.com", state_dir=tmp_path, scan_fn=lambda d, timeout=10: first)
    second = report("example.com", 20, "B", [f("x", "medium")])
    monitor_domain("example.com", state_dir=tmp_path, scan_fn=lambda d, timeout=10: second)

    # A third run should diff against the second, not the first.
    third = report("example.com", 20, "B", [f("x", "medium")])
    out = monitor_domain("example.com", state_dir=tmp_path, scan_fn=lambda d, timeout=10: third)

    assert out["delta"].direction == "unchanged"


def test_target_is_normalized_for_state_filename(tmp_path):
    rep = report("example.com", 0, "A", [])

    monitor_domain("HTTPS://Example.com/path", state_dir=tmp_path, scan_fn=lambda d, timeout=10: rep)

    assert (tmp_path / "example.com.json").exists()
