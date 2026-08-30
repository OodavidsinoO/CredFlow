"""Summary reporting — generate JSON report and console output."""

import json
import os
from datetime import UTC, datetime


class _SummaryEncoder(json.JSONEncoder):
    """Custom encoder that serializes datetime objects to ISO-8601 strings.

    Unlike ``default=str``, this allows us to catch unexpected types
    early and surface serialization errors instead of silently masking them.
    """

    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


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

    _print_vuln_summaries(summary)


def _print_vuln_summaries(summary: dict) -> None:
    """Print per-host vulnerability summaries from parsed .nessus reports."""
    reports = summary.get("reports", [])
    if not reports:
        return

    has_summaries = any(r.get("summary") for r in reports)
    if not has_summaries:
        return

    print("  Vulnerability Summary")
    print("  " + "-" * 46)
    for r in reports:
        s = r.get("summary")
        if not s:
            if r.get("summary_error"):
                print(f"    {r['ip']}: summary unavailable ({r['summary_error']})")
            continue

        counts = s.get("severity_counts", {})
        host = s.get("hostname") or s.get("ip") or r["ip"]
        print(f"    {host}:")
        print(
            f"      critical: {counts.get('critical', 0)}  "
            f"high: {counts.get('high', 0)}  "
            f"medium: {counts.get('medium', 0)}  "
            f"low: {counts.get('low', 0)}  "
            f"info: {counts.get('info', 0)}"
        )
        ports = s.get("open_ports", [])
        if ports:
            port_str = ", ".join(
                f"{p['port']}/{p['protocol']}" if p.get("protocol") else str(p["port"])
                for p in ports[:10]
            )
            if len(ports) > 10:
                port_str += f" (+{len(ports) - 10} more)"
            print(f"      open ports: {port_str}")
        top = s.get("top_findings", [])
        if top:
            print("      top findings:")
            for f in top[:5]:
                print(
                    f"        [{f['severity']}] {f['name']}"
                    + (f" (port {f['port']})" if f.get("port") else "")
                )
    print()


def generate_summary_json(summary: dict, reports_dir: str) -> str:
    """Write summary JSON to reports directory. Returns file path."""
    os.makedirs(reports_dir, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(reports_dir, f"summary_{ts}.json")
    with open(path, "w") as f:
        json.dump(summary, f, indent=2, cls=_SummaryEncoder)
    print(f"  Summary written to: {path}")
    return path
