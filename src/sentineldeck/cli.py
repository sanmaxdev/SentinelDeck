from __future__ import annotations

import argparse
import json
import os
import sys

from sentineldeck import __version__, tui
from sentineldeck.alerts import send_alert, should_alert
from sentineldeck.diff import ReportDelta, diff_reports
from sentineldeck.models import Finding
from sentineldeck.monitor import DEFAULT_STATE_DIR, monitor_domain
from sentineldeck.remediation import remediation_for
from sentineldeck.reporters.badge import write_badge_svg, write_card_svg
from sentineldeck.reporters.diff_report import write_diff_report
from sentineldeck.reporters.html_report import read_json_report, write_html_report
from sentineldeck.reporters.json_report import write_json_delta, write_json_report
from sentineldeck.scanner import scan_domain
from sentineldeck.suppressions import load_suppressions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentineldeck",
        description="Passive attack-surface radar for small businesses.",
    )
    parser.add_argument("--version", action="version", version=f"SentinelDeck {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=False, metavar="command")

    scan = subparsers.add_parser("scan", help="Run a safe passive scan against a domain.")
    scan.add_argument("target", help="Domain to scan, e.g. example.com")
    scan.add_argument("-o", "--output", help="Write JSON report to this path.")
    scan.add_argument("--html", help="Render a client-ready HTML report to this path.")
    scan.add_argument("--svg", help="Write a shareable SVG score card to this path.")
    scan.add_argument("--badge", help="Write an embeddable SVG grade badge to this path.")
    scan.add_argument("--pretty", action="store_true", help="Print the full JSON report to stdout.")
    scan.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Network timeout in seconds for HTTP and TLS checks (default: 10).",
    )
    scan.add_argument(
        "--suppress",
        metavar="FILE",
        help="Accept listed finding ids (one per line, globs allowed); they are kept out of the score.",
    )

    report = subparsers.add_parser("report", help="Render a saved JSON scan report.")
    report.add_argument("source", help="Path to a SentinelDeck JSON report.")
    report.add_argument("--html", help="Write a client-ready HTML report to this path.")
    report.add_argument("--svg", help="Write a shareable SVG score card to this path.")
    report.add_argument("--badge", help="Write an embeddable SVG grade badge to this path.")

    diff = subparsers.add_parser(
        "diff", help="Compare two saved scan reports and show what changed."
    )
    diff.add_argument("previous", help="Path to the earlier SentinelDeck JSON report.")
    diff.add_argument("current", help="Path to the later SentinelDeck JSON report.")
    diff.add_argument("-o", "--output", help="Write the JSON delta to this path.")
    diff.add_argument(
        "--json", action="store_true", dest="as_json", help="Print the full JSON delta to stdout."
    )
    diff.add_argument("--html", help="Write an HTML change report to this path.")
    diff.add_argument(
        "--exit-code",
        action="store_true",
        help="Return exit code 1 if the posture regressed (for scheduled monitoring).",
    )

    monitor = subparsers.add_parser(
        "monitor", help="Scan a domain, compare to the last run, and alert on regressions."
    )
    monitor.add_argument("target", help="Domain to monitor, e.g. example.com")
    monitor.add_argument(
        "--state-dir",
        default=DEFAULT_STATE_DIR,
        help=f"Directory holding the latest report per domain (default: {DEFAULT_STATE_DIR}).",
    )
    monitor.add_argument(
        "--timeout", type=int, default=10, help="Network timeout in seconds (default: 10)."
    )
    monitor.add_argument(
        "--webhook", help="POST an alert to this URL (Slack, Discord, or any custom endpoint)."
    )
    monitor.add_argument(
        "--alert-on",
        choices=["regression", "change", "always"],
        default="regression",
        help="When to send the webhook alert (default: regression).",
    )
    monitor.add_argument("--html", help="Write an HTML change report to this path.")
    monitor.add_argument(
        "--exit-code", action="store_true", help="Return exit code 1 if the posture regressed."
    )

    subparsers.add_parser("checks", help="List every check SentinelDeck performs.")

    explain = subparsers.add_parser(
        "explain", help="Show the description and copy-paste fix for a finding id."
    )
    explain.add_argument("finding_id", help="A finding id, e.g. dmarc-missing")
    explain.add_argument(
        "--domain", default="example.com", help="Tailor the fix to this domain (default: example.com)."
    )

    subparsers.add_parser("version", help="Print the installed SentinelDeck version.")
    return parser


def _format_diff_summary(delta: ReportDelta) -> str:
    sign = "+" if delta.score_delta > 0 else ""
    lines = [
        f"SentinelDeck change report - {delta.target}",
        f"  {delta.previous_generated_at}  ->  {delta.current_generated_at}",
        f"  Risk score: {delta.previous_score} -> {delta.current_score} ({sign}{delta.score_delta})"
        f"   Grade: {delta.previous_grade} -> {delta.current_grade}"
        f"   [{delta.direction.upper()}]",
    ]
    if delta.previous_target != delta.target:
        lines.append(f"  ! comparing different targets: {delta.previous_target} -> {delta.target}")
    if delta.alerting_findings:
        lines.append(f"  ! {len(delta.alerting_findings)} new high/critical finding(s)")

    def block(title: str, items: list, marker: str) -> None:
        if not items:
            return
        lines.append("")
        lines.append(f"  {title} ({len(items)}):")
        for finding in items:
            lines.append(
                f"    {marker} [{finding.severity.upper():<8}] {finding.id:<26} {finding.title}"
            )

    block("New findings", delta.new_findings, "+")
    block("Resolved", delta.resolved_findings, "-")
    if delta.severity_changes:
        lines.append("")
        lines.append(f"  Severity changed ({len(delta.severity_changes)}):")
        for change in delta.severity_changes:
            escalated = " (escalated)" if change.escalated else ""
            lines.append(
                f"    ~ {change.id:<26} {change.previous_severity.upper()} -> "
                f"{change.current_severity.upper()}{escalated}"
            )
    lines.append("")
    lines.append(f"  Still present: {len(delta.persisting_findings)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    tui.init_stream()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        print(tui.home_screen())
        return 0

    if args.command == "scan":
        suppressions = None
        if args.suppress:
            try:
                suppressions = load_suppressions(args.suppress)
            except OSError as exc:
                print(f"error: cannot read suppressions file: {exc}", file=sys.stderr)
                return 2
        tracker = tui.ScanProgress(args.target) if sys.stderr.isatty() else None
        try:
            report = scan_domain(
                args.target,
                timeout=args.timeout,
                suppressions=suppressions,
                progress=tracker.step if tracker else None,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if tracker:
            tracker.finish()

        saved: list[tuple[str, str]] = []
        if args.output:
            saved.append(("Report", write_json_report(report, args.output)))
        if args.html:
            saved.append(("HTML report", write_html_report(report, args.html)))
        if args.svg:
            saved.append(("Share card", write_card_svg(report, args.svg)))
        if args.badge:
            saved.append(("Badge", write_badge_svg(report, args.badge)))
        for label, path in saved:
            print(f"{label} written: {os.path.abspath(path)}")

        if args.pretty:
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        elif sys.stdout.isatty():
            print(tui.render_scan_summary(report))
        elif not saved:
            # Piped or redirected with no file target: emit JSON so pipelines work.
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        print(f"SentinelDeck score: {report.risk_score}/100 grade={report.grade} findings={len(report.findings)}")
        return 0

    if args.command == "report":
        if not (args.html or args.svg or args.badge):
            print("error: choose at least one of --html, --svg, or --badge", file=sys.stderr)
            return 2
        report = read_json_report(args.source)
        if args.html:
            print(f"HTML report written: {write_html_report(report, args.html)}")
        if args.svg:
            print(f"Share card written: {write_card_svg(report, args.svg)}")
        if args.badge:
            print(f"Badge written: {write_badge_svg(report, args.badge)}")
        return 0

    if args.command == "diff":
        previous = read_json_report(args.previous)
        current = read_json_report(args.current)
        delta = diff_reports(previous, current)

        if args.output:
            print(f"Delta written: {write_json_delta(delta, args.output)}")
        if args.html:
            print(f"HTML change report written: {write_diff_report(delta, args.html)}")
        if args.as_json:
            print(json.dumps(delta.to_dict(), indent=2, sort_keys=True))

        print(_format_diff_summary(delta))
        return 1 if (args.exit_code and delta.regressed) else 0

    if args.command == "monitor":
        try:
            result = monitor_domain(args.target, args.state_dir, timeout=args.timeout)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        current = result["current"]
        if result["baseline"]:
            print(
                f"Baseline saved for {current.target}: "
                f"score {current.risk_score}/100 grade={current.grade}. "
                "Run again later to detect changes."
            )
            return 0

        delta = result["delta"]
        print(_format_diff_summary(delta))
        if args.html:
            print(f"HTML change report written: {write_diff_report(delta, args.html)}")
        if args.webhook and should_alert(delta, args.alert_on):
            sent = send_alert(args.webhook, delta)
            print(f"Webhook alert: {'sent' if sent else 'failed to send'}")
        return 1 if (args.exit_code and delta.regressed) else 0

    if args.command == "checks":
        print(tui.checks_screen())
        return 0

    if args.command == "explain":
        finding = Finding(
            id=args.finding_id, title=args.finding_id, severity="info",
            description="", recommendation="",
        )
        fix = remediation_for(finding, args.domain)
        if fix is None:
            print(
                f"error: no copy-paste fix is registered for '{args.finding_id}'.",
                file=sys.stderr,
            )
            print("Run 'sentineldeck checks' to see what SentinelDeck detects.", file=sys.stderr)
            return 1
        print(tui.render_fix(args.finding_id, fix))
        return 0

    if args.command == "version":
        print(f"SentinelDeck {__version__}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
