"""Compare two SentinelDeck scans of the same domain.

A single scan is a snapshot; the value for a consultant or agency tracking a
client over time is the *change* between snapshots. This module turns two
``ScanReport`` objects into a structured ``ReportDelta`` — what appeared, what
was fixed, and whether the overall risk moved — without any network access, so
it is fully deterministic and offline-testable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from sentineldeck.models import Finding, ScanReport

# Severity ranking, highest first. Used to decide whether a same-id finding
# became more or less serious between scans, and to sort the change lists.
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
# A new finding at one of these severities is what a monitoring run should
# alert on, and what flips ``regressed`` / the optional non-zero exit code.
ALERT_SEVERITIES = {"critical", "high"}


@dataclass(slots=True)
class SeverityChange:
    id: str
    title: str
    previous_severity: str
    current_severity: str

    @property
    def escalated(self) -> bool:
        return SEVERITY_RANK.get(self.current_severity.lower(), 0) > SEVERITY_RANK.get(
            self.previous_severity.lower(), 0
        )

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "escalated": self.escalated}


@dataclass(slots=True)
class ReportDelta:
    target: str
    previous_target: str
    previous_generated_at: str
    current_generated_at: str
    previous_score: int
    current_score: int
    previous_grade: str
    current_grade: str
    new_findings: list[Finding] = field(default_factory=list)
    resolved_findings: list[Finding] = field(default_factory=list)
    persisting_findings: list[Finding] = field(default_factory=list)
    severity_changes: list[SeverityChange] = field(default_factory=list)

    @property
    def score_delta(self) -> int:
        return self.current_score - self.previous_score

    @property
    def direction(self) -> str:
        # Risk score is what a client reads first, so it drives the headline.
        # A flat score with churned findings is reported as "changed" so the
        # summary never claims "no change" while findings moved underneath it.
        if self.current_score > self.previous_score:
            return "regressed"
        if self.current_score < self.previous_score:
            return "improved"
        if self.new_findings or self.resolved_findings or self.severity_changes:
            return "changed"
        return "unchanged"

    @property
    def alerting_findings(self) -> list[Finding]:
        # New, conclusively-observed high/critical issues — the signal a
        # scheduled monitor should notify on.
        return [
            f
            for f in self.new_findings
            if f.severity.lower() in ALERT_SEVERITIES and f.confidence != "indeterminate"
        ]

    @property
    def regressed(self) -> bool:
        return self.direction == "regressed" or bool(self.alerting_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "previous_target": self.previous_target,
            "previous_generated_at": self.previous_generated_at,
            "current_generated_at": self.current_generated_at,
            "previous_score": self.previous_score,
            "current_score": self.current_score,
            "score_delta": self.score_delta,
            "previous_grade": self.previous_grade,
            "current_grade": self.current_grade,
            "direction": self.direction,
            "regressed": self.regressed,
            "new_findings": [f.to_dict() for f in self.new_findings],
            "resolved_findings": [f.to_dict() for f in self.resolved_findings],
            "persisting_findings": [f.to_dict() for f in self.persisting_findings],
            "severity_changes": [c.to_dict() for c in self.severity_changes],
            "alerting_findings": [f.to_dict() for f in self.alerting_findings],
        }


def _by_id(findings: list[Finding]) -> dict[str, Finding]:
    # Findings are emitted at most once per id within a report; if a report ever
    # carries a duplicate id, the later one wins, which is harmless for diffing.
    return {f.id: f for f in findings}


def _sort_key(finding: Finding) -> tuple[int, str]:
    return (-SEVERITY_RANK.get(finding.severity.lower(), 0), finding.id)


def diff_reports(previous: ScanReport, current: ScanReport) -> ReportDelta:
    """Compute the change from ``previous`` to ``current``.

    Findings are matched by their stable ``id`` (e.g. ``tls-expired``). The two
    reports are assumed to describe the same target; a mismatch is preserved in
    the delta rather than rejected, so callers can surface it.
    """
    old = _by_id(previous.findings)
    new = _by_id(current.findings)

    new_findings = [new[i] for i in new.keys() - old.keys()]
    resolved_findings = [old[i] for i in old.keys() - new.keys()]
    persisting_findings = [new[i] for i in new.keys() & old.keys()]

    severity_changes = [
        SeverityChange(
            id=i,
            title=new[i].title,
            previous_severity=old[i].severity,
            current_severity=new[i].severity,
        )
        for i in new.keys() & old.keys()
        if old[i].severity.lower() != new[i].severity.lower()
    ]

    return ReportDelta(
        target=current.target,
        previous_target=previous.target,
        previous_generated_at=previous.generated_at,
        current_generated_at=current.generated_at,
        previous_score=previous.risk_score,
        current_score=current.risk_score,
        previous_grade=previous.grade,
        current_grade=current.grade,
        new_findings=sorted(new_findings, key=_sort_key),
        resolved_findings=sorted(resolved_findings, key=_sort_key),
        persisting_findings=sorted(persisting_findings, key=_sort_key),
        severity_changes=sorted(severity_changes, key=lambda c: c.id),
    )
