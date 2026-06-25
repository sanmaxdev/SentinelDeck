"""Render a scan-to-scan delta as a client-ready HTML report.

Matches the dark/red theme of the single-scan report so a consultant can hand a
client "here is what changed since last month" with the same polish.
"""
from __future__ import annotations

from html import escape
from pathlib import Path

from sentineldeck.diff import ReportDelta
from sentineldeck.models import Finding
from sentineldeck.reporters.badge import grade_color

DIRECTION_COPY = {
    "regressed": ("Posture regressed", "#f43f5e"),
    "improved": ("Posture improved", "#22c55e"),
    "changed": ("Findings changed", "#f59e0b"),
    "unchanged": ("No change", "#9b9ba8"),
}


def _finding_row(finding: Finding, kind: str, marker: str) -> str:
    severity = escape(finding.severity.lower())
    unverified = (
        ' <span class="badge badge-info">UNVERIFIED</span>'
        if finding.confidence == "indeterminate"
        else ""
    )
    return f"""
      <li class="row row-{escape(kind)}">
        <span class="marker">{escape(marker)}</span>
        <span class="badge badge-{severity}">{escape(finding.severity.upper())}</span>{unverified}
        <code>{escape(finding.id)}</code>
        <span class="row-title">{escape(finding.title)}</span>
      </li>"""


def _finding_section(title: str, css: str, marker: str, findings: list[Finding]) -> str:
    if not findings:
        return ""
    rows = "".join(_finding_row(f, css, marker) for f in findings)
    return f"""
    <section class="delta-section {css}">
      <h2>{escape(title)} <span class="count">{len(findings)}</span></h2>
      <ul class="rows">{rows}</ul>
    </section>"""


def _severity_section(delta: ReportDelta) -> str:
    if not delta.severity_changes:
        return ""
    rows = "".join(
        f"""
      <li class="row row-changed">
        <span class="marker">~</span>
        <code>{escape(c.id)}</code>
        <span class="row-title">{escape(c.title)}</span>
        <span class="sev-move">{escape(c.previous_severity.upper())} &rarr; {escape(c.current_severity.upper())}{' (escalated)' if c.escalated else ''}</span>
      </li>"""
        for c in delta.severity_changes
    )
    return f"""
    <section class="delta-section changed">
      <h2>Severity changed <span class="count">{len(delta.severity_changes)}</span></h2>
      <ul class="rows">{rows}</ul>
    </section>"""


def render_diff_report(delta: ReportDelta) -> str:
    headline, accent = DIRECTION_COPY.get(delta.direction, DIRECTION_COPY["unchanged"])
    delta_sign = "+" if delta.score_delta > 0 else ""
    prev_color = grade_color(delta.previous_grade)
    curr_color = grade_color(delta.current_grade)
    target_note = (
        f'<p class="muted warn">Comparing different targets: {escape(delta.previous_target)} &rarr; {escape(delta.target)}</p>'
        if delta.previous_target != delta.target
        else ""
    )
    alert_note = (
        f'<p class="muted warn">{len(delta.alerting_findings)} new high/critical finding(s) — review immediately.</p>'
        if delta.alerting_findings
        else ""
    )

    sections = (
        _finding_section("New findings", "new", "+", delta.new_findings)
        + _severity_section(delta)
        + _finding_section("Resolved", "resolved", "-", delta.resolved_findings)
        + _finding_section("Still present", "persisting", "·", delta.persisting_findings)
    )
    if not sections.strip():
        sections = '<section class="delta-section"><h2>No finding changes</h2><p class="muted">Both scans produced the same findings.</p></section>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelDeck Change Report - {escape(delta.target)}</title>
  <style>
    :root {{ color-scheme: dark; --bg:#0a0a0f; --panel:#14141c; --line:#26262f; --text:#f5f5f7; --muted:#9b9ba8; --accent:#ef4444; --accent-2:#f87171; --low:#facc15; --medium:#fb923c; --high:#f43f5e; --critical:#dc2626; --info:#a78bfa; --good:#22c55e; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; color:var(--text); background:radial-gradient(1200px 600px at 100% -10%, rgba(220,38,38,.18), transparent 60%), radial-gradient(900px 500px at -10% 0%, rgba(127,29,29,.22), transparent 55%), var(--bg); }}
    main {{ max-width:1120px; margin:0 auto; padding:48px 22px 64px; }}
    .eyebrow {{ color:var(--accent-2); text-transform:uppercase; letter-spacing:.22em; font-size:12px; font-weight:800; }}
    h1 {{ font-size:42px; line-height:1.05; margin:12px 0 6px; letter-spacing:-.5px; }}
    h2 {{ margin-top:34px; font-size:22px; border-left:3px solid var(--accent); padding-left:12px; display:flex; align-items:center; gap:10px; }}
    .count {{ font-size:13px; color:var(--muted); border:1px solid var(--line); border-radius:999px; padding:1px 9px; font-weight:700; }}
    .muted {{ color:var(--muted); }}
    .warn {{ color:var(--accent-2); font-weight:600; }}
    .hero {{ position:relative; overflow:hidden; border:1px solid var(--line); background:linear-gradient(135deg, rgba(220,38,38,.12), rgba(20,20,28,.96)); border-radius:24px; padding:36px; box-shadow:0 30px 80px rgba(0,0,0,.55); }}
    .direction {{ display:inline-block; margin-top:8px; padding:6px 14px; border-radius:999px; font-weight:800; letter-spacing:.04em; color:{accent}; background:{accent}22; border:1px solid {accent}55; }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-top:28px; }}
    .card {{ background:#0e0e15; border:1px solid var(--line); border-radius:16px; padding:16px 18px; }}
    .card span {{ display:block; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.08em; }}
    .card strong {{ display:block; font-size:30px; margin-top:6px; font-variant-numeric:tabular-nums; }}
    .grades b {{ font-size:30px; }}
    .grades .arrow {{ color:var(--muted); margin:0 8px; }}
    .delta-section {{ margin-top:18px; }}
    .rows {{ list-style:none; margin:8px 0 0; padding:0; }}
    .row {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; background:var(--panel); border:1px solid var(--line); border-left:4px solid var(--line); border-radius:12px; padding:12px 16px; margin:8px 0; }}
    .row-new {{ border-left-color:var(--high); }}
    .row-resolved {{ border-left-color:var(--good); }}
    .row-persisting {{ border-left-color:var(--line); }}
    .row-changed {{ border-left-color:var(--medium); }}
    .marker {{ font-weight:800; width:14px; text-align:center; color:var(--muted); }}
    .row-title {{ color:#d4d4dd; }}
    .sev-move {{ color:var(--accent-2); font-size:13px; font-weight:600; margin-left:auto; }}
    code {{ background:#08080c; color:#fca5a5; border:1px solid var(--line); border-radius:8px; padding:3px 7px; font-size:13px; }}
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
      <div class="eyebrow">SentinelDeck Change Report</div>
      <h1>{escape(delta.target)}</h1>
      <p class="muted">{escape(delta.previous_generated_at)} &rarr; {escape(delta.current_generated_at)}</p>
      <div class="direction">{escape(headline)}</div>
      {target_note}
      {alert_note}
      <div class="cards">
        <div class="card"><span>Risk score</span><strong>{delta.previous_score} &rarr; {delta.current_score}</strong></div>
        <div class="card"><span>Score change</span><strong>{delta_sign}{delta.score_delta}</strong></div>
        <div class="card grades"><span>Grade</span><strong><b style="color:{prev_color}">{escape(delta.previous_grade)}</b><span class="arrow">&rarr;</span><b style="color:{curr_color}">{escape(delta.current_grade)}</b></strong></div>
        <div class="card"><span>New / Resolved</span><strong>+{len(delta.new_findings)} / -{len(delta.resolved_findings)}</strong></div>
      </div>
    </section>
    {sections}
    <footer>Generated by SentinelDeck — passive attack-surface visibility for small businesses.</footer>
  </main>
</body>
</html>
"""


def write_diff_report(delta: ReportDelta, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_diff_report(delta), encoding="utf-8")
    return path
