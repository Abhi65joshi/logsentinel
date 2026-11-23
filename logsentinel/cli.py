"""Command line interface.

Examples::

    python -m logsentinel samples/
    python -m logsentinel /var/log/auth.log --html report.html --json alerts.json
    python -m logsentinel samples/ --min-severity high --fail-on critical
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import Engine
from .models import SEVERITY_ORDER
from .parsers import parse_file
from .report import console_report, html_report, json_report
from .rules import RuleError, default_rules_path, load_rules

LOG_SUFFIXES = {".log", ".json", ".jsonl", ".ndjson", ".txt", ""}


def _collect(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            files.extend(sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in LOG_SUFFIXES))
        elif p.is_file():
            files.append(p)
        else:
            print(f"warning: {p} not found, skipping", file=sys.stderr)
    return files


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="logsentinel",
                                 description="Rule-based threat detection for Linux, Windows and web logs.")
    ap.add_argument("paths", nargs="*", help="log files or directories")
    ap.add_argument("-r", "--rules", action="append",
                    help="rule file or directory (repeatable). Default: bundled rules")
    ap.add_argument("-f", "--format", default="auto",
                    choices=["auto", "linux_auth", "windows", "web"], help="force log format")
    ap.add_argument("--year", type=int, help="year for syslog timestamps without one")
    ap.add_argument("--min-severity", default="low", choices=list(SEVERITY_ORDER),
                    help="hide alerts below this severity")
    ap.add_argument("--json", metavar="FILE", help="write alerts as JSON")
    ap.add_argument("--html", metavar="FILE", help="write an HTML report")
    ap.add_argument("--fail-on", choices=list(SEVERITY_ORDER),
                    help="exit with code 2 if any alert at/above this severity (for CI/automation)")
    ap.add_argument("--no-color", action="store_true", help="disable coloured output")
    ap.add_argument("--list-rules", action="store_true", help="print loaded rules and exit")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.paths and not args.list_rules:
        parser.error("at least one log file or directory is required")

    try:
        rules = load_rules(*(args.rules or [default_rules_path()]))
    except RuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.list_rules:
        for r in rules:
            print(f"{r.id:<8} {r.severity:<9} {r.type:<10} {','.join(r.mitre):<20} {r.title}")
        return 0

    events = []
    for f in _collect(args.paths):
        try:
            events.extend(parse_file(f, fmt=args.format, year=args.year))
        except (ValueError, OSError) as exc:
            print(f"warning: could not parse {f}: {exc}", file=sys.stderr)

    alerts = Engine(rules).run(events)
    floor = SEVERITY_ORDER[args.min_severity]
    alerts = [a for a in alerts if SEVERITY_ORDER[a.severity] >= floor]

    print(console_report(alerts, events, color=not args.no_color and sys.stdout.isatty()))
    if args.json:
        Path(args.json).write_text(json_report(alerts, events), encoding="utf-8")
        print(f"\nJSON written to {args.json}")
    if args.html:
        Path(args.html).write_text(html_report(alerts, events), encoding="utf-8")
        print(f"HTML report written to {args.html}")

    if args.fail_on and any(SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[args.fail_on] for a in alerts):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
