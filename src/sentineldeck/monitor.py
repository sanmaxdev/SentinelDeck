"""Scheduled monitoring: scan, compare to the last run, and persist the latest.

`monitor` is built to be run on a schedule (cron, a CI job, Windows Task
Scheduler). Each run scans the domain, diffs it against the report saved from
the previous run, then stores the new report as the latest. Combined with a
webhook it turns the diff engine into a standing watch that alerts when a
domain's posture regresses.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from sentineldeck.diff import diff_reports
from sentineldeck.models import ScanReport
from sentineldeck.reporters.html_report import read_json_report
from sentineldeck.reporters.json_report import write_json_report
from sentineldeck.scanner import scan_domain
from sentineldeck.scanners.domain import normalize_domain

DEFAULT_STATE_DIR = ".sentineldeck"

ScanFn = Callable[..., ScanReport]


def _state_path(state_dir: str | Path, domain: str) -> Path:
    return Path(state_dir) / f"{domain}.json"


def monitor_domain(
    target: str,
    state_dir: str | Path = DEFAULT_STATE_DIR,
    scan_fn: ScanFn | None = None,
    timeout: int = 10,
) -> dict[str, Any]:
    """Scan ``target``, diff against the last saved run, and persist the result.

    Returns ``{domain, baseline, current, delta}``. On the first run for a domain
    there is nothing to compare against, so ``baseline`` is ``True`` and ``delta``
    is ``None``. The new report always replaces the saved state.
    """
    scan = scan_fn or scan_domain
    domain = normalize_domain(target)
    state = _state_path(state_dir, domain)

    previous = read_json_report(state) if state.exists() else None
    current = scan(domain, timeout=timeout)
    delta = diff_reports(previous, current) if previous is not None else None

    write_json_report(current, state)
    return {"domain": domain, "baseline": previous is None, "current": current, "delta": delta}
