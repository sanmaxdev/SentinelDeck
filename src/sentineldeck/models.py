from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    description: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanReport:
    target: str
    generated_at: str
    risk_score: int
    grade: str
    checks: dict[str, Any]
    findings: list[Finding]

    @classmethod
    def empty(cls, target: str) -> "ScanReport":
        return cls(
            target=target,
            generated_at=datetime.now(timezone.utc).isoformat(),
            risk_score=0,
            grade="A",
            checks={},
            findings=[],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "risk_score": self.risk_score,
            "grade": self.grade,
            "checks": self.checks,
            "findings": [finding.to_dict() for finding in self.findings],
        }
