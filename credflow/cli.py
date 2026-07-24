"""CLI entry point — argparse-based command-line interface."""

import argparse
import csv
import logging
import os
import sys

from credflow.config import Config
from credflow.models import Target
from credflow.reporter import generate_summary_json, print_progress_table, print_summary
from credflow.scanner import NessusClient
from credflow.state import StateManager
from credflow.worker import run_batch


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for stdout."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def parse_targets_csv(path: str) -> list[Target]:
    """Parse a targets CSV file. Expected columns: ip,username,password,os_type."""
    import re
    targets = []
    if not os.path.isfile(path):
        print(f"Error: targets file not found: {path}", file=sys.stderr)
        sys.exit(1)

    # utf-8-sig handles BOM characters from Windows-saved CSVs
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        # Normalize header names (strip whitespace, lowercase)
        raw_headers = reader.fieldnames or []
        reader.fieldnames = [h.strip().lower() for h in raw_headers]

        required = {"ip", "username", "password"}
        actual = set(reader.fieldnames)
        missing = required - actual
        if missing:
            print(f"Error: CSV missing required columns: {', '.join(missing)}", file=sys.stderr)
            print(f"  Found: {', '.join(actual)}", file=sys.stderr)
            sys.exit(1)

        # Simple IP/hostname validation pattern
        ip_pattern = re.compile(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*$")

        for i, row in enumerate(reader, start=2):  # header is line 1
            ip = row.get("ip", "").strip()
            username = row.get("username", "").strip()
            password = row.get("password", "").strip()
            os_type = row.get("os_type", "").strip().lower()

            if not ip:
                print(f"Warning: skipping row {i} — missing ip", file=sys.stderr)
                continue
            if not ip_pattern.match(ip):
                print(f"Warning: {ip} may not be a valid hostname/IP — proceeding anyway", file=sys.stderr)
            if not username:
                print(f"Warning: skipping {ip} — missing username", file=sys.stderr)
                continue
            if os_type not in ("linux", "windows"):
                print(
                    f"Warning: {ip} — os_type '{os_type}' not recognized, defaulting to 'linux'",
                    file=sys.stderr,
                )
                os_type = "linux"

            targets.append(Target(ip=ip, username=username, password=password, os_type=os_type))

    if not targets:
        print("Error: no valid targets found in CSV", file=sys.stderr)
        sys.exit(1)

    return targets


def cmd_check(config: Config) -> None:
    """Test connectivity to the Nessus scanner."""
    print(f"Connecting to {config.nessus_url} ...")
    try:
        client = NessusClient(config)
        info = client.check_connection()
        print(f"  Server version: {info['version']}")
        print(f"  Scanner UUID:   {info['scanner_uuid']}")
        print(f"  Status:         {info['status']}")
        print("  ✓ Connection OK")
    except Exception as e:
        print(f"  ✗ Connection failed: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_run(config: Config) -> None:
    """Execute the main scan workflow."""
    logger = logging.getLogger(__name__)

    # Validate config
    errors = config.validate()
    if errors:
        for e in errors:
            print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Parse targets
    logger.info("Loading targets from %s", config.targets_csv)
    targets = parse_targets_csv(config.targets_csv)
    logger.info("Loaded %d target(s)", len(targets))

    # Initialize state
    state = StateManager(config.state_db, max_retries=config.max_retries)

    if not config.resume and os.path.isfile(config.state_db):
        logger.info("--no-resume: dropping existing state database")
        state.reset_all()

    if config.resume and not state.is_empty():
        progress = state.get_progress()
        completed = progress.get("completed", 0)
        if completed > 0:
            logger.info("Resuming — %d target(s) already completed", completed)

    # Run batch
    summary = run_batch(targets, config, state)

    # Print results
    print_summary(summary)
    generate_summary_json(summary, config.reports_dir)

    if summary["failed"] > 0:
        sys.exit(1)


def cmd_status(config: Config) -> None:
    """Display current progress from state database."""
    if not os.path.isfile(config.state_db):
        print("No state database found. Run 'credflow run' first.")
        return

    state = StateManager(config.state_db, max_retries=config.max_retries)
    progress = state.get_progress()
    if state.is_empty():
        print("State database is empty. Run 'credflow run --targets <file>' first.")
        return

    print_progress_table(progress)

    failures = state.get_failures()
    if failures:
        print("  Failures:")
        for f in failures:
            print(f"    {f['ip']}: {f.get('error', 'unknown')} (retries: {f.get('retries', 0)})")
        print()


def cmd_retry(config: Config) -> None:
    """Reset failed targets to pending."""
    if not os.path.isfile(config.state_db):
        print("No state database found.")
        return

    state = StateManager(config.state_db, max_retries=config.max_retries)
    count = state.reset_failed()
    print(f"Reset {count} failed target(s) to pending.")
    print("Run 'credflow run --targets <file>' to retry.")


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="credflow",
        description="Automated Nessus credentialed scanning with 1-to-1 credential isolation.",
    )
    parser.add_argument("--version", action="version", version="credflow 1.0.0")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ---- check ----
    check_parser = subparsers.add_parser("check", help="Test Nessus connectivity")
    _add_nessus_args(check_parser)

    # ---- run ----
    run_parser = subparsers.add_parser("run", help="Execute scan batch")
    run_parser.add_argument(
        "--targets", required=True, help="Path to targets CSV file"
    )
    run_parser.add_argument(
        "--workers", type=int, default=1, help="Number of parallel workers (default: 1, max: 5)"
    )
    run_parser.add_argument(
        "--retries", type=int, default=1, help="Max retries per failed target (default: 1)"
    )
    run_parser.add_argument(
        "--reports-dir", default="./reports", help="Output directory for reports (default: ./reports)"
    )
    run_parser.add_argument(
        "--db-password", default=None, help="Password for .db export (auto-generated if empty)"
    )
    run_parser.add_argument(
        "--template-name", default=None, help="Scan template name to search for"
    )
    run_parser.add_argument(
        "--template-uuid", default=None, help="Scan template UUID (overrides name search)"
    )
    run_parser.add_argument(
        "--timeout", type=int, default=3600, help="Max seconds per scan (default: 3600)"
    )
    run_parser.add_argument(
        "--poll-interval", type=int, default=30, help="Seconds between status checks (default: 30)"
    )
    run_parser.add_argument(
        "--no-resume", action="store_true", help="Start fresh — discard existing state"
    )
    run_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose/debug logging"
    )
    _add_nessus_args(run_parser)

    # ---- status ----
    status_parser = subparsers.add_parser("status", help="Show scan progress")
    status_parser.add_argument(
        "--state-db", default="credflow_state.db", help="Path to state database"
    )

    # ---- retry ----
    retry_parser = subparsers.add_parser("retry", help="Reset failed targets to pending")
    retry_parser.add_argument(
        "--state-db", default="credflow_state.db", help="Path to state database"
    )

    return parser


def _add_nessus_args(parser: argparse.ArgumentParser) -> None:
    """Add Nessus connection override arguments to a subparser."""
    parser.add_argument("--url", default=None, help="Nessus URL (overrides NESSUS_URL)")
    parser.add_argument("--username", default=None, help="Nessus username (overrides NESSUS_USERNAME)")
    parser.add_argument("--password", default=None, help="Nessus password (overrides NESSUS_PASSWORD)")
    parser.add_argument("--api-token", default=None, help="X-API-Token (overrides NESSUS_API_TOKEN, auto-discovered if empty)")
    parser.add_argument("--access-key", default=None, help="API access key (overrides NESSUS_ACCESS_KEY)")
    parser.add_argument("--secret-key", default=None, help="API secret key (overrides NESSUS_SECRET_KEY)")
    parser.add_argument("--no-ssl-verify", action="store_true", default=None, help="Disable SSL verification")


def _build_config(args: argparse.Namespace) -> Config:
    """Build Config from env + CLI args."""
    overrides = {}

    # Map CLI args to config keys — single pass for all str/int/bool overrides
    mapping = {
        # (arg_attr, config_key, is_nessus_prefix)
        ("targets", "targets_csv", False),
        ("workers", "max_workers", False),
        ("retries", "max_retries", False),
        ("timeout", "poll_timeout", False),
        ("poll_interval", "poll_interval", False),
        ("reports_dir", "reports_dir", False),
        ("db_password", "db_password", False),
        ("template_name", "template_name", False),
        ("template_uuid", "template_uuid", False),
        ("state_db", "state_db", False),
        ("url", "nessus_url", True),
        ("username", "nessus_username", True),
        ("password", "nessus_password", True),
        ("api_token", "nessus_api_token", True),
        ("access_key", "nessus_access_key", True),
        ("secret_key", "nessus_secret_key", True),
    }
    for arg_attr, config_key, _is_nessus in mapping:
        val = getattr(args, arg_attr, None)
        if val is not None:
            overrides[config_key] = val

    # Cap max_workers
    if "max_workers" in overrides:
        overrides["max_workers"] = min(int(overrides["max_workers"]), 5)

    # Boolean flags
    if hasattr(args, "no_ssl_verify") and args.no_ssl_verify is True:
        overrides["nessus_ssl_verify"] = False
    if hasattr(args, "no_resume") and args.no_resume:
        overrides["resume"] = False

    return Config.from_env(overrides)


def main() -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if hasattr(args, "verbose") and args.verbose:
        setup_logging(verbose=True)
    else:
        setup_logging(verbose=False)

    config = _build_config(args)

    if args.command == "check":
        cmd_check(config)
    elif args.command == "run":
        cmd_run(config)
    elif args.command == "status":
        cmd_status(config)
    elif args.command == "retry":
        cmd_retry(config)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
