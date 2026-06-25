"""Accept known findings via a suppressions file so re-scans do not renoise.

A suppressions file lists finding ids that have been reviewed and accepted, one
per line, with ``#`` comments allowed. Matching findings are marked suppressed:
they still appear in the report under "Accepted", but are excluded from the
score, so an accepted risk never keeps dragging the grade down. Patterns may use
shell globs, e.g. ``subdomain-takeover:*`` or ``missing-*``.
"""
from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from sentineldeck.models import Finding


def load_suppressions(path: str | Path) -> list[str]:
    patterns: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            patterns.append(line)
    return patterns


def is_suppressed(finding_id: str, patterns: list[str]) -> bool:
    return any(fnmatch(finding_id, pattern) for pattern in patterns)


def apply_suppressions(findings: list[Finding], patterns: list[str]) -> None:
    """Mark each finding whose id matches a pattern as suppressed, in place."""
    if not patterns:
        return
    for finding in findings:
        if is_suppressed(finding.id, patterns):
            finding.suppressed = True
