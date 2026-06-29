"""CISA Known Exploited Vulnerabilities. A CVE on this list is confirmed
exploited in the wild and is a top remediation priority. We ship a snapshot
(data/kev_cves.json) and load it lazily, only when a scan actually has CVEs to
check, so a clean scan pays nothing.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_KEV_FILE = Path(__file__).resolve().parent.parent / "data" / "kev_cves.json"


@lru_cache(maxsize=1)
def _load() -> tuple[str, frozenset[str]]:
    try:
        data = json.loads(_KEV_FILE.read_text(encoding="utf-8"))
        return data.get("date", ""), frozenset(c.upper() for c in data.get("cves", []))
    except Exception:  # noqa: BLE001 - a missing snapshot just means no KEV flagging
        return "", frozenset()


def kev_date() -> str:
    """The release date of the bundled KEV snapshot."""
    return _load()[0]


def filter_kev(cves) -> list[str]:
    """Return the subset of ``cves`` that are on the CISA KEV list, upper-cased."""
    known = _load()[1]
    return sorted({str(c).upper() for c in cves if str(c).upper() in known})
