from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from sentineldeck.models import Finding, ScanReport
from sentineldeck.reporters.badge import grade_color

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
    no_findings = (
        '<section class="severity-section"><h2>No findings</h2>'
        '<p class="muted">No issues were detected by the enabled checks.</p></section>'
        if not report.findings
        else ""
    )
    grade = grade_color(report.grade)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelDeck Security Report - {escape(report.target)}</title>
  <style>
    :root {{ color-scheme: dark; --bg:#0a0a0f; --panel:#14141c; --line:#26262f; --text:#f5f5f7; --muted:#9b9ba8; --accent:#ef4444; --accent-2:#f87171; --low:#facc15; --medium:#fb923c; --high:#f43f5e; --critical:#dc2626; --info:#a78bfa; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color:var(--text); background:radial-gradient(1200px 600px at 100% -10%, rgba(220,38,38,.18), transparent 60%), radial-gradient(900px 500px at -10% 0%, rgba(127,29,29,.22), transparent 55%), var(--bg); }}
    main {{ max-width:1120px; margin:0 auto; padding:48px 22px 64px; }}
    a {{ color:var(--accent-2); }}
    .eyebrow {{ color:var(--accent-2); text-transform:uppercase; letter-spacing:.22em; font-size:12px; font-weight:800; }}
    h1 {{ font-size:46px; line-height:1.05; margin:12px 0 6px; letter-spacing:-.5px; }}
    h2 {{ margin-top:40px; font-size:24px; border-left:3px solid var(--accent); padding-left:12px; }}
    h3 {{ margin:14px 0 6px; font-size:18px; }}
    h4 {{ margin:14px 0 4px; font-size:12px; text-transform:uppercase; letter-spacing:.12em; color:var(--accent-2); }}
    .muted {{ color:var(--muted); }}
    .hero {{ position:relative; overflow:hidden; border:1px solid var(--line); background:linear-gradient(135deg, rgba(220,38,38,.12), rgba(20,20,28,.96)); border-radius:24px; padding:36px; box-shadow:0 30px 80px rgba(0,0,0,.55); }}
    .hero-top {{ display:flex; justify-content:space-between; gap:24px; align-items:flex-start; flex-wrap:wrap; }}
    .grade-disc {{ width:128px; height:128px; border-radius:50%; display:grid; place-items:center; flex:0 0 auto; background:#0d0d13; border:6px solid {grade}; box-shadow:0 0 40px {grade}55; }}
    .grade-disc b {{ font-size:60px; line-height:1; color:{grade}; }}
    .grade-disc span {{ display:block; text-align:center; color:var(--muted); font-size:13px; margin-top:2px; }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:14px; margin-top:28px; }}
    .card {{ background:#0e0e15; border:1px solid var(--line); border-radius:16px; padding:16px 18px; }}
    .card span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
    .card strong {{ display:block; font-size:30px; margin-top:6px; font-variant-numeric:tabular-nums; }}
    .card.accent strong {{ color:var(--accent-2); }}
    .finding {{ background:var(--panel); border:1px solid var(--line); border-left:4px solid var(--line); border-radius:16px; margin:14px 0; padding:22px 24px; }}
    .finding-critical {{ border-left-color:var(--critical); }}
    .finding-high {{ border-left-color:var(--high); }}
    .finding-medium {{ border-left-color:var(--medium); }}
    .finding-low {{ border-left-color:var(--low); }}
    .finding-info {{ border-left-color:var(--info); }}
    .finding-meta {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
    .finding p {{ color:#d4d4dd; line-height:1.55; }}
    code, pre {{ background:#08080c; color:#fca5a5; border:1px solid var(--line); border-radius:8px; }}
    code {{ padding:3px 7px; font-size:13px; }}
    pre {{ overflow:auto; padding:14px; color:#cbd5e1; }}
    details summary {{ cursor:pointer; color:var(--muted); margin-top:10px; }}
    .badge {{ border-radius:999px; padding:4px 11px; font-size:11px; font-weight:800; letter-spacing:.04em; }}
    .badge-low {{ background:rgba(250,204,21,.16); color:#fde047; }}
    .badge-medium {{ background:rgba(251,146,60,.16); color:#fdba74; }}
    .badge-high {{ background:rgba(244,63,94,.18); color:#fda4af; }}
    .badge-critical {{ background:rgba(220,38,38,.22); color:#fecaca; }}
    .badge-info {{ background:rgba(167,139,250,.18); color:#ddd6fe; }}
    footer {{ color:var(--muted); margin-top:44px; padding-top:18px; border-top:1px solid var(--line); font-size:13px; }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="hero-top">
        <div>
          <div class="eyebrow">SentinelDeck Security Report</div>
          <h1>{escape(report.target)}</h1>
          <p class="muted">Generated at {escape(report.generated_at)}</p>
        </div>
        <div class="grade-disc"><div><b>{escape(report.grade)}</b><span>Grade {escape(report.grade)}</span></div></div>
      </div>
      <div class="cards" aria-label="Executive Summary">
        <div class="card accent"><span>Risk Score</span><strong>{report.risk_score}/100</strong></div>
        <div class="card"><span>Findings</span><strong>{len(report.findings)}</strong></div>
        <div class="card"><span>High / Critical</span><strong>{counts['critical'] + counts['high']}</strong></div>
        <div class="card"><span>Medium</span><strong>{counts['medium']}</strong></div>
        <div class="card"><span>Low</span><strong>{counts['low']}</strong></div>
      </div>
    </section>

    <section>
      <h2>Executive Summary</h2>
      <p class="muted">SentinelDeck reviewed the passive DNS, HTTP, TLS, and email-security posture for this target. Findings below are grouped by severity, each with the evidence observed and a practical remediation step. Items marked <span class="badge badge-info">UNVERIFIED</span> could not be conclusively determined and do not affect the score.</p>
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
