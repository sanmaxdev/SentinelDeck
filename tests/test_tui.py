from sentineldeck import tui
from sentineldeck.models import Finding, ScanReport


def report(grade="C", score=49, findings=None):
    return ScanReport(
        target="acme.com", generated_at="t", risk_score=score, grade=grade,
        checks={}, findings=findings or [],
    )


def f(id, sev, suppressed=False):
    return Finding(
        id=id, title=f"{id} title", severity=sev, description="d", recommendation="r",
        suppressed=suppressed,
    )


def test_home_screen_lists_commands_and_is_plain_without_colour(monkeypatch):
    monkeypatch.setattr(tui, "_color_cache", False)

    out = tui.home_screen()

    assert "SentinelDeck" in out
    for cmd in ("scan", "report", "diff", "monitor"):
        assert cmd in out
    assert "COMMANDS" in out and "QUICK START" in out
    assert "\033[" not in out  # no ANSI escapes when colour is disabled


def test_fg_is_a_noop_when_colour_disabled(monkeypatch):
    monkeypatch.setattr(tui, "_color_cache", False)

    assert tui.fg("hi", tui.RED, bold=True) == "hi"


def test_fg_emits_truecolor_when_enabled(monkeypatch):
    monkeypatch.setattr(tui, "_color_cache", True)

    assert tui.fg("hi", (1, 2, 3), bold=True) == "\033[1;38;2;1;2;3mhi\033[0m"


def test_render_scan_summary_shows_grade_and_top_findings(monkeypatch):
    monkeypatch.setattr(tui, "_color_cache", False)
    rep = report("C", 49, [f("missing-hsts", "medium"), f("weak", "low"), f("note", "info")])

    out = tui.render_scan_summary(rep)

    assert "acme.com" in out
    assert "grade C" in out
    assert "risk 49/100" in out
    assert "missing-hsts title" in out  # a scored finding is listed
    assert "note title" not in out      # info findings are not in the "top issues" list


def test_render_scan_summary_celebrates_a_clean_posture(monkeypatch):
    monkeypatch.setattr(tui, "_color_cache", False)

    assert "Clean posture" in tui.render_scan_summary(report("A", 0, []))
