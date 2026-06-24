from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from sentineldeck.models import Finding, ScanReport

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_LABELS = {
    "critical": "Critical Findings",
    "high": "High Findings",
    "medium": "Medium Findings",
    "low": "Low Findings",
    "info": "Informational Findings",
}


def report_from_dict(data: dict[str, Any]) -> ScanReport:
    findings = [
        Finding(
            id=item.get("id", "unknown"),
            title=item.get("title", "Untitled finding"),
            severity=item.get("severity", "info"),
            description=item.get("description", ""),
            recommendation=item.get("recommendation", ""),
            evidence=item.get("evidence", {}),
            confidence=item.get("confidence", "confirmed"),
        )
        for item in data.get("findings", [])
    ]
    return ScanReport(
        target=data.get("target", "unknown"),
        generated_at=data.get("generated_at", ""),
        risk_score=int(data.get("risk_score", 0)),
        grade=data.get("grade", "A"),
        checks=data.get("checks", {}),
        findings=findings,
    )


def read_json_report(path: str | Path) -> ScanReport:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return report_from_dict(data)


def _severity_counts(report: ScanReport) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in report.findings:
        severity = finding.severity.lower()
        counts[severity if severity in counts else "info"] += 1
    return counts


def _render_finding(finding: Finding) -> str:
    evidence = escape(json.dumps(finding.evidence, indent=2, sort_keys=True))
    severity = escape(finding.severity.lower())
    unverified = (
        '<span class="badge badge-info">UNVERIFIED</span>'
        if finding.confidence == "indeterminate"
        else ""
    )
    return f"""
    <article class="finding finding-{severity}">
      <div class="finding-meta">
        <span class="badge badge-{severity}">{escape(finding.severity.upper())}</span>
        {unverified}
        <code>{escape(finding.id)}</code>
      </div>
      <h3>{escape(finding.title)}</h3>
      <p>{escape(finding.description)}</p>
      <h4>Recommendation</h4>
      <p>{escape(finding.recommendation)}</p>
      <details>
        <summary>Evidence</summary>
        <pre>{evidence}</pre>
      </details>
    </article>
    """


def _render_severity_section(report: ScanReport, severity: str) -> str:
    findings = [finding for finding in report.findings if finding.severity.lower() == severity]
    if not findings:
        return ""
    rendered = "\n".join(_render_finding(finding) for finding in findings)
    return f"""
    <section class="severity-section" id="{severity}">
      <h2>{SEVERITY_LABELS[severity]}</h2>
      {rendered}
    </section>
    """


def render_html_report(report: ScanReport) -> str:
    counts = _severity_counts(report)
    sections = "\n".join(_render_severity_section(report, severity) for severity in SEVERITY_ORDER)
    no_findings = "<section class=\"severity-section\"><h2>No findings</h2><p>No issues were detected by the enabled checks.</p></section>" if not report.findings else ""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelDeck Security Report - {escape(report.target)}</title>
  <style>
    :root {{ color-scheme: dark; --bg:#08111f; --panel:#101c2f; --panel2:#13243d; --text:#edf5ff; --muted:#9fb3c8; --accent:#38bdf8; --low:#22c55e; --medium:#f59e0b; --high:#fb7185; --critical:#ef4444; }}
    * {{ box-sizing: border-box; }}
    body {{ margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: radial-gradient(circle at top left, #12345c 0, var(--bg) 38%); color:var(--text); }}
    main {{ max-width:1120px; margin:0 auto; padding:48px 22px; }}
    .hero {{ border:1px solid rgba(148,163,184,.24); background:linear-gradient(135deg, rgba(56,189,248,.14), rgba(16,28,47,.94)); border-radius:28px; padding:34px; box-shadow:0 24px 70px rgba(0,0,0,.35); }}
    .eyebrow {{ color:var(--accent); text-transform:uppercase; letter-spacing:.18em; font-size:12px; font-weight:700; }}
    h1 {{ font-size:42px; margin:10px 0 6px; }}
    h2 {{ margin-top:34px; }}
    .muted {{ color:var(--muted); }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-top:24px; }}
    .card {{ background:rgba(16,28,47,.86); border:1px solid rgba(148,163,184,.18); border-radius:20px; padding:18px; }}
    .card span {{ display:block; color:var(--muted); font-size:13px; }}
    .card strong {{ display:block; font-size:28px; margin-top:6px; }}
    .finding {{ background:var(--panel); border:1px solid rgba(148,163,184,.18); border-radius:20px; margin:16px 0; padding:22px; }}
    .finding-meta {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
    code, pre {{ background:#07101d; color:#c7d2fe; border-radius:10px; }}
    code {{ padding:4px 7px; }}
    pre {{ overflow:auto; padding:14px; }}
    .badge {{ border-radius:999px; padding:5px 10px; font-size:12px; font-weight:800; }}
    .badge-low {{ background:rgba(34,197,94,.17); color:#86efac; }}
    .badge-medium {{ background:rgba(245,158,11,.18); color:#fcd34d; }}
    .badge-high {{ background:rgba(251,113,133,.18); color:#fda4af; }}
    .badge-critical {{ background:rgba(239,68,68,.2); color:#fecaca; }}
    .badge-info {{ background:rgba(56,189,248,.16); color:#bae6fd; }}
    footer {{ color:var(--muted); margin-top:36px; font-size:13px; }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="eyebrow">SentinelDeck Security Report</div>
      <h1>{escape(report.target)}</h1>
      <p class="muted">Generated at {escape(report.generated_at)}</p>
      <div class="cards" aria-label="Executive Summary">
        <div class="card"><span>Risk Score</span><strong>{report.risk_score}/100</strong></div>
        <div class="card"><span>Grade</span><strong>Grade {escape(report.grade)}</strong></div>
        <div class="card"><span>Total Findings</span><strong>{len(report.findings)}</strong></div>
        <div class="card"><span>Medium</span><strong>{counts['medium']}</strong></div>
        <div class="card"><span>Low</span><strong>{counts['low']}</strong></div>
      </div>
    </section>

    <section>
      <h2>Executive Summary</h2>
      <p class="muted">SentinelDeck reviewed passive DNS, HTTP, TLS, and email-security posture for this target. Findings below are grouped by severity and include practical remediation steps.</p>
    </section>

    {sections}
    {no_findings}

    <footer>Generated by SentinelDeck — passive attack-surface visibility for small businesses.</footer>
  </main>
</body>
</html>
"""


def write_html_report(report: ScanReport, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(report), encoding="utf-8")
    return path
