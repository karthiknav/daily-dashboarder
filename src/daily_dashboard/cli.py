from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .jobs.daily_scan import run_daily_scan, write_report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="daily-dashboard")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan configured pipelines and remediate findings")
    scan.add_argument("--config", type=Path, default=Path("pipelines.yml"), help="Path to targets config YAML")
    scan.add_argument("--dry-run", action="store_true", help="Report findings without creating branches/PRs")
    scan.add_argument("--output", type=Path, default=None, help="Write the dashboard JSON report to this path")

    args = parser.parse_args(argv)

    if args.command == "scan":
        report = run_daily_scan(args.config, dry_run=args.dry_run)
        if args.output:
            write_report(report, args.output)
            print(f"Wrote report to {args.output} ({json.dumps(report['summary'])})")
        else:
            print(json.dumps(report, indent=2, default=str))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
