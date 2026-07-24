"""Summary reporting — generate JSON report and console output."""

import json
import os
from datetime import datetime, timezone


def print_progress_table(progress: dict) -> None:
    """Print a compact progress table to stdout."""
    total = sum(progress.values())
    if total == 0:
        print("No targets in state database.")
        return

    print()
    print(f"  {'Status':<12} {'Count':>6}")
    print(f"  {'-'*12} {'-'*6}")
    for status in ("completed", "running", "pending", "failed"):
        count = progress.get(status, 0)
        if count > 0:
            marker = {  # noqa: RUF001
                "completed": " ✓",
                "running": " ▶",
                "pending": " ○",
                "failed": " ✗",
            }.get(status, "")
            print(f"  {status + marker:<12} {count:>6}")
    print(f"  {'─'*12} {'─'*6}")
    print(f"  {'total':<12} {total:>6}")
    print()


def print_summary(summary: dict) -> None:
    """Print final batch summary to stdout."""
    print()
    print("=" * 50)
    print("  CredFlow — Batch Summary")
    print("=" * 50)
    print(f"  Total targets:    {summary['total']}")
    print(f"  Completed:        {summary['completed']} ✓")
    print(f"  Failed:           {summary['failed']} ✗")
    print(f"  Pending:          {summary['pending']}")
    print()

    failures = summary.get("failures", [])
    if failures:
        print("  Failures:")
        for f in failures:
            print(f"    {f['ip']}: {f.get('error', 'unknown')}")
        print()

    reports = summary.get("reports", [])
    if reports:
        print("  Reports:")
        for r in reports:
            print(f"    {r['ip']}:")
            if r.get("report_nessus"):
                print(f"      nessus: {r['report_nessus']}")
            if r.get("report_db"):
                print(f"      db:     {r['report_db']}")
        print()


def generate_summary_json(summary: dict, reports_dir: str) -> str:
    """Write summary JSON to reports directory. Returns file path."""
    os.makedirs(reports_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(reports_dir, f"summary_{ts}.json")
    with open(path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"  Summary written to: {path}")
    return path
