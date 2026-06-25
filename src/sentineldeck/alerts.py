"""Alert delivery for monitoring.

A regression is only useful if someone hears about it. ``send_alert`` POSTs a
compact message plus the full structured delta to a webhook URL, which works
with Slack and Discord incoming webhooks and any custom endpoint. The HTTP call
is injectable so alert formatting and routing are tested offline.
"""
from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from typing import Any

from sentineldeck.diff import ReportDelta

USER_AGENT = "SentinelDeck/0.1"

Sender = Callable[[str, "dict[str, Any]", int], bool]

DIRECTION_LABEL = {
    "regressed": "REGRESSED",
    "improved": "improved",
    "changed": "changed",
    "unchanged": "unchanged",
}


def should_alert(delta: ReportDelta, mode: str = "regression") -> bool:
    """Decide whether ``delta`` warrants an alert under ``mode``."""
    if mode == "always":
        return True
    if mode == "change":
        return delta.direction != "unchanged"
    return delta.regressed


def build_alert(delta: ReportDelta) -> dict[str, Any]:
    """A webhook payload: a human message plus the full structured delta."""
    sign = "+" if delta.score_delta > 0 else ""
    lines = [
        f"SentinelDeck: {delta.target} {DIRECTION_LABEL.get(delta.direction, delta.direction)}",
        f"Risk {delta.previous_score} -> {delta.current_score} ({sign}{delta.score_delta}), "
        f"grade {delta.previous_grade} -> {delta.current_grade}",
    ]
    if delta.alerting_findings:
        lines.append(f"{len(delta.alerting_findings)} new high/critical:")
        lines.extend(f"  - [{f.severity.upper()}] {f.title}" for f in delta.alerting_findings)
    elif delta.new_findings or delta.resolved_findings:
        lines.append(
            f"{len(delta.new_findings)} new finding(s), {len(delta.resolved_findings)} resolved"
        )
    text = "\n".join(lines)
    # "text" is read by Slack, "content" by Discord, "delta" by custom receivers.
    return {"text": text, "content": text, "delta": delta.to_dict()}


def _post(url: str, payload: dict[str, Any], timeout: int = 10) -> bool:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json", "User-Agent": USER_AGENT}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return 200 <= response.status < 300
    except Exception:  # noqa: BLE001 - a failed alert must never crash the monitor
        return False


def send_alert(url: str, delta: ReportDelta, sender: Sender = _post, timeout: int = 10) -> bool:
    """Build and deliver the alert for ``delta`` to ``url``. Returns success."""
    return sender(url, build_alert(delta), timeout)
