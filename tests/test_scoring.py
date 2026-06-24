from sentineldeck.models import Finding
from sentineldeck.risk.scoring import grade, score_findings


def test_score_findings_caps_at_100():
    findings = [Finding("x", "x", "critical", "x", "x") for _ in range(4)]
    assert score_findings(findings) == 100


def test_grade_boundaries():
    assert grade(0) == "A"
    assert grade(20) == "B"
    assert grade(40) == "C"
    assert grade(60) == "D"
    assert grade(80) == "F"
