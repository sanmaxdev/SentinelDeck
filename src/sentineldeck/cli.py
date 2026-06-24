from __future__ import annotations

import argparse
import json
import sys

from sentineldeck import __version__
from sentineldeck.reporters.html_report import read_json_report, write_html_report
from sentineldeck.reporters.json_report import write_json_report
from sentineldeck.scanner import scan_domain


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentineldeck", description="Passive attack-surface radar for small businesses.")
    parser.add_argument("--version", action="version", version=f"SentinelDeck {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a safe passive scan against a domain.")
    scan.add_argument("target", help="Domain to scan, e.g. example.com")
    scan.add_argument("-o", "--output", help="Write JSON report to this path.")
    scan.add_argument("--pretty", action="store_true", help="Print the full JSON report to stdout.")

    report = subparsers.add_parser("report", help="Render a saved JSON scan report.")
    report.add_argument("source", help="Path to a SentinelDeck JSON report.")
    report.add_argument("--html", required=True, help="Write an HTML report to this path.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            report = scan_domain(args.target)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if args.output:
            path = write_json_report(report, args.output)
            print(f"Report written: {path}")
        if args.pretty or not args.output:
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        print(f"SentinelDeck score: {report.risk_score}/100 grade={report.grade} findings={len(report.findings)}")
        return 0

    if args.command == "report":
        report = read_json_report(args.source)
        path = write_html_report(report, args.html)
        print(f"HTML report written: {path}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
