from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from sentineldeck.models import ScanReport

if TYPE_CHECKING:
    from sentineldeck.diff import ReportDelta


def write_json_report(report: ScanReport, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def write_json_delta(delta: ReportDelta, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(delta.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
