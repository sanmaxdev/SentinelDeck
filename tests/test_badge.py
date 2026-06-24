from sentineldeck.models import Finding, ScanReport
from sentineldeck.reporters.badge import (
    grade_color,
    render_badge_svg,
    render_card_svg,
    write_badge_svg,
    write_card_svg,
)


def sample_report(grade="C", score=42) -> ScanReport:
    return ScanReport(
        target="example.com",
        generated_at="2026-06-24T21:00:00+00:00",
        risk_score=score,
        grade=grade,
        checks={},
        findings=[
            Finding("a", "High issue", "high", "d", "r"),
            Finding("b", "Medium issue", "medium", "d", "r"),
        ],
    )


def test_grade_color_maps_known_grades():
    assert grade_color("A") == "#22c55e"
    assert grade_color("F") == "#ef4444"
    assert grade_color("?") == "#64748b"


def test_render_badge_includes_grade_and_color():
    svg = render_badge_svg(sample_report(grade="A"))

    assert svg.startswith("<svg")
    assert "Grade A" in svg
    assert "#22c55e" in svg


def test_render_card_includes_summary_fields():
    svg = render_card_svg(sample_report(grade="C", score=42))

    assert "example.com" in svg
    assert "42/100" in svg
    assert ">C<" in svg
    assert "High / Critical" in svg


def test_render_card_escapes_target():
    report = sample_report()
    report.target = "<script>alert(1)</script>"

    svg = render_card_svg(report)

    assert "<script>alert(1)</script>" not in svg
    assert "&lt;script&gt;" in svg


def test_write_helpers_create_files(tmp_path):
    badge = write_badge_svg(sample_report(), tmp_path / "out" / "badge.svg")
    card = write_card_svg(sample_report(), tmp_path / "out" / "card.svg")

    assert badge.exists() and card.exists()
    assert badge.read_text(encoding="utf-8").startswith("<svg")
