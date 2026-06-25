from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from sentineldeck.models import Finding, ScanReport
from sentineldeck.remediation import attach_remediations
from sentineldeck.reporters.badge import GRADE_COLORS, grade_color
from sentineldeck.risk.scoring import SEVERITY_POINTS, path_to_grade

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
            remediation=item.get("remediation"),
            suppressed=item.get("suppressed", False),
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
        if finding.suppressed:
            continue
        severity = finding.severity.lower()
        counts[severity if severity in counts else "info"] += 1
    return counts


def _render_references(references: list[str]) -> str:
    parts = [
        f'<a href="{escape(ref)}">{escape(ref)}</a>' if ref.startswith("http") else escape(ref)
        for ref in references
    ]
    return " · ".join(parts)


def _render_fix(finding: Finding) -> str:
    fix = finding.remediation
    if not fix:
        return ""
    refs = _render_references(fix.get("references", []))
    refs_html = f'<div class="fix-refs">{refs}</div>' if refs else ""
    return f"""
      <div class="fix" data-kind="{escape(fix.get('kind', 'text'))}">
        <div class="fix-head">FIX &middot; {escape(fix.get('title', ''))}</div>
        <pre class="fix-snippet">{escape(fix.get('snippet', ''))}</pre>
        {refs_html}
      </div>"""


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
      {_render_fix(finding)}
      <details>
        <summary>Evidence</summary>
        <pre>{evidence}</pre>
      </details>
    </article>
    """


def _render_severity_section(report: ScanReport, severity: str) -> str:
    findings = [
        finding
        for finding in report.findings
        if finding.severity.lower() == severity and not finding.suppressed
    ]
    if not findings:
        return ""
    rendered = "\n".join(_render_finding(finding) for finding in findings)
    return f"""
    <section class="severity-section" id="{severity}">
      <h2>{SEVERITY_LABELS[severity]}</h2>
      {rendered}
    </section>
    """


def _render_accepted(report: ScanReport) -> str:
    accepted = [f for f in report.findings if f.suppressed]
    if not accepted:
        return ""
    chips = "".join(
        f'<span class="host">[{escape(f.severity.upper())}] {escape(f.id)}</span>' for f in accepted
    )
    return f"""
    <section class="severity-section" id="accepted">
      <h2>Accepted <span class="count">{len(accepted)}</span></h2>
      <p class="muted">These findings were accepted via a suppressions file and are excluded from the score.</p>
      <div class="hosts">{chips}</div>
    </section>"""


def _render_attack_surface(report: ScanReport) -> str:
    subs = (report.checks or {}).get("subdomains") or {}
    names = subs.get("subdomains") or []
    if subs.get("status") != "ok" or not names:
        return ""
    sensitive = set(subs.get("sensitive") or [])
    cap = 80
    chips = "".join(
        f'<span class="host{" host-sensitive" if host in sensitive else ""}">{escape(host)}</span>'
        for host in names[:cap]
    )
    more = f'<p class="muted">and {len(names) - cap} more.</p>' if len(names) > cap else ""
    sens_note = (
        f'<p class="muted">{len(sensitive)} look potentially sensitive (highlighted in red).</p>'
        if sensitive
        else ""
    )
    return f"""
    <section class="severity-section" id="attack-surface">
      <h2>Attack Surface <span class="count">{subs.get('count', len(names))}</span></h2>
      <p class="muted">Hostnames discovered in public certificate transparency logs ({escape(str(subs.get('source', 'crt.sh')))}). This is the surface exposed beyond the scanned host.</p>
      {sens_note}
      <div class="hosts">{chips}</div>
      {more}
    </section>"""


def _render_simulator(report: ScanReport) -> str:
    scored = [
        f for f in report.findings
        if f.confidence != "indeterminate" and not f.suppressed
        and SEVERITY_POINTS.get(f.severity.lower(), 0) > 0
    ]
    if not scored:
        return (
            '<section class="severity-section" id="simulator"><h2>Remediation Simulator</h2>'
            '<p class="muted">No scored findings to simulate. This domain is already at grade A.</p></section>'
        )
    plan_ids = {f.id for f in path_to_grade(report.findings, "A")}
    items = "".join(
        f'<li class="sim-item"><label>'
        f'<input type="checkbox" data-points="{SEVERITY_POINTS.get(f.severity.lower(), 0)}" '
        f'data-qw="{1 if f.id in plan_ids else 0}">'
        f'<span class="badge badge-{f.severity.lower()}">{escape(f.severity.upper())}</span>'
        f'<span class="sim-pts">&minus;{SEVERITY_POINTS.get(f.severity.lower(), 0)}</span>'
        f'<span class="sim-title">{escape(f.title)}</span></label></li>'
        for f in sorted(scored, key=lambda f: -SEVERITY_POINTS.get(f.severity.lower(), 0))
    )
    colors = json.dumps(GRADE_COLORS)
    return f"""
    <section class="severity-section" id="simulator">
      <h2>Remediation Simulator</h2>
      <p class="muted">Tick the fixes you plan to make and watch the projected score and grade update live. Each item shows the points it removes; "Apply quick wins" selects the fewest fixes that reach grade A.</p>
      <div class="sim-panel">
        <div class="sim-grade-wrap">
          <div class="sim-grade" id="sim-grade">{escape(report.grade)}</div>
          <div class="sim-readout">
            <div><b id="sim-score">{report.risk_score}</b><span class="muted">/100 projected risk</span></div>
            <div class="muted" id="sim-hint">&nbsp;</div>
          </div>
        </div>
        <div class="sim-bar"><div id="sim-fill"></div></div>
        <div class="sim-actions">
          <button type="button" id="sim-quickwins">Apply quick wins (reach A)</button>
          <button type="button" id="sim-reset" class="ghost">Reset</button>
        </div>
        <ul class="sim-list" id="sim-list">{items}</ul>
      </div>
    </section>
    <script>
    (function() {{
      var COLORS = {colors};
      function gradeFor(s) {{ return s>=80?'F':s>=60?'D':s>=40?'C':s>=20?'B':'A'; }}
      var boxes = [].slice.call(document.querySelectorAll('#sim-list input'));
      var sEl=document.getElementById('sim-score'), gEl=document.getElementById('sim-grade'),
          hEl=document.getElementById('sim-hint'), fEl=document.getElementById('sim-fill');
      function calc() {{
        var s=0, rem=[];
        boxes.forEach(function(b) {{
          if(!b.checked) {{ s += +b.dataset.points; rem.push(+b.dataset.points); }}
          b.closest('.sim-item').classList.toggle('fixed', b.checked);
        }});
        if(s>100) s=100;
        var g=gradeFor(s);
        sEl.textContent=s; gEl.textContent=g;
        gEl.style.color=COLORS[g]; gEl.style.borderColor=COLORS[g]; gEl.style.boxShadow='0 0 26px '+COLORS[g]+'55';
        fEl.style.width=(100-s)+'%'; fEl.style.background=COLORS[g];
        rem.sort(function(a,b) {{ return b-a; }});
        var cur=s, n=0;
        for(var i=0;i<rem.length && cur>19;i++) {{ cur-=rem[i]; n++; }}
        hEl.textContent = s<20 ? 'Grade A reached.' : ('Fix ' + n + ' more to reach grade A');
      }}
      boxes.forEach(function(b) {{ b.addEventListener('change', calc); }});
      document.getElementById('sim-quickwins').addEventListener('click', function() {{
        boxes.forEach(function(b) {{ if(b.dataset.qw==='1') b.checked=true; }}); calc();
      }});
      document.getElementById('sim-reset').addEventListener('click', function() {{
        boxes.forEach(function(b) {{ b.checked=false; }}); calc();
      }});
      calc();
    }})();
    </script>"""


def render_html_report(report: ScanReport) -> str:
    # Ensure fixes are present even for reports saved before remediation existed.
    attach_remediations(report.findings, report.target)
    counts = _severity_counts(report)
    sections = "\n".join(_render_severity_section(report, severity) for severity in SEVERITY_ORDER)
    no_findings = (
        '<section class="severity-section"><h2>No findings</h2>'
        '<p class="muted">No issues were detected by the enabled checks.</p></section>'
        if not report.findings
        else ""
    )
    grade = grade_color(report.grade)
    active_count = sum(counts.values())
    attack_surface = _render_attack_surface(report)
    accepted = _render_accepted(report)
    simulator = _render_simulator(report)

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
    .fix {{ margin-top:14px; border:1px solid #2a1520; background:#0f0a0c; border-radius:12px; overflow:hidden; }}
    .fix-head {{ background:rgba(220,38,38,.14); color:#fca5a5; font-size:11px; font-weight:800; letter-spacing:.08em; padding:8px 14px; }}
    .fix-snippet {{ margin:0; border:0; border-radius:0; background:#08080c; color:#e2e8f0; padding:14px; white-space:pre-wrap; word-break:break-word; }}
    .fix-refs {{ padding:8px 14px; font-size:12px; color:var(--muted); border-top:1px solid var(--line); }}
    .fix-refs a {{ color:var(--accent-2); }}
    .sim-panel {{ background:var(--panel); border:1px solid var(--line); border-radius:18px; padding:22px; }}
    .sim-grade-wrap {{ display:flex; align-items:center; gap:18px; }}
    .sim-grade {{ width:74px; height:74px; flex:0 0 auto; border-radius:50%; display:grid; place-items:center; background:#0d0d13; border:5px solid var(--accent); font-size:34px; font-weight:800; transition:color .25s, border-color .25s, box-shadow .25s; }}
    .sim-readout b {{ font-size:30px; font-variant-numeric:tabular-nums; }}
    .sim-bar {{ height:10px; background:#0e0e15; border:1px solid var(--line); border-radius:999px; overflow:hidden; margin:16px 0; }}
    .sim-bar #sim-fill {{ height:100%; width:0; background:var(--accent); transition:width .25s, background .25s; }}
    .sim-actions {{ display:flex; gap:10px; margin-bottom:8px; flex-wrap:wrap; }}
    .sim-actions button {{ cursor:pointer; border-radius:10px; border:1px solid var(--accent); background:rgba(220,38,38,.16); color:#fecaca; font-weight:700; padding:9px 14px; font-size:13px; }}
    .sim-actions button.ghost {{ border-color:var(--line); background:transparent; color:var(--muted); }}
    .sim-list {{ list-style:none; margin:14px 0 0; padding:0; display:grid; gap:8px; }}
    .sim-item label {{ display:flex; align-items:center; gap:10px; cursor:pointer; background:#0e0e15; border:1px solid var(--line); border-radius:10px; padding:10px 14px; }}
    .sim-item.fixed label {{ opacity:.5; text-decoration:line-through; }}
    .sim-item input {{ width:16px; height:16px; accent-color:var(--accent); flex:0 0 auto; }}
    .sim-pts {{ color:#fda4af; font-variant-numeric:tabular-nums; font-weight:700; font-size:12px; }}
    .sim-title {{ color:#d4d4dd; }}
    .count {{ font-size:13px; color:var(--muted); border:1px solid var(--line); border-radius:999px; padding:1px 10px; font-weight:700; vertical-align:middle; }}
    .hosts {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:10px; }}
    .host {{ background:#0e0e15; border:1px solid var(--line); border-radius:8px; padding:5px 10px; font-size:12.5px; color:#cbd5e1; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
    .host-sensitive {{ border-color:var(--accent); color:#fda4af; background:rgba(220,38,38,.10); }}
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
        <div class="card"><span>Findings</span><strong>{active_count}</strong></div>
        <div class="card"><span>High / Critical</span><strong>{counts['critical'] + counts['high']}</strong></div>
        <div class="card"><span>Medium</span><strong>{counts['medium']}</strong></div>
        <div class="card"><span>Low</span><strong>{counts['low']}</strong></div>
      </div>
    </section>

    <section>
      <h2>Executive Summary</h2>
      <p class="muted">SentinelDeck reviewed the passive DNS, HTTP, TLS, and email-security posture for this target. Findings below are grouped by severity, each with the evidence observed and a copy-paste fix. Items marked <span class="badge badge-info">UNVERIFIED</span> could not be conclusively determined and do not affect the score.</p>
    </section>

    {attack_surface}

    {simulator}

    {sections}
    {no_findings}
    {accepted}

    <footer>Generated by SentinelDeck &middot; passive attack-surface visibility for small businesses.</footer>
  </main>
</body>
</html>
"""


def write_html_report(report: ScanReport, output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(report), encoding="utf-8")
    return path
