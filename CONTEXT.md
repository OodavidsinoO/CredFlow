# CredFlow

Automated Nessus credentialed scanning with strict 1-to-1 host-to-credential isolation to prevent account lockouts.

Uses session-based authentication (username/password) with X-API-Token extracted
from the Nessus Web UI's JavaScript to unlock the full REST API on
Nessus Professional.

## Language

**Target**:
A host to be scanned, defined by its IP address, a single credential pair, its OS type, and optionally SSH privilege escalation settings (`escalation_method`, `escalation_user`, `escalation_password`).
_Avoid_: Host, endpoint, node, asset

**Credential**:
A username/password pair that authenticates to exactly one Target. Each Target has exactly one Credential.
_Avoid_: Login, account, auth

**Escalation**:
Optional SSH privilege escalation settings attached to a Target's Credential. Defined by three optional CSV columns: `escalation_method` (one of `sudo`, `su`, `su+sudo`, `dzdo`, `pbrun`, `cisco_enable`, `k5login`, `checkpoint_gaia`), `escalation_user` (account to escalate to, defaults to `root`), and `escalation_password` (the escalation password). When set, `_build_credentials()` injects the corresponding Nessus API fields (`elevate_privileges_with`, `escalation_account`, `escalation_password`, `su_user`) into the SSH credential block. Windows hosts ignore escalation settings.
_Avoid_: sudo config, privilege elevation, PE

**Scan Job**:
The full lifecycle of scanning one Target: create a temporary Nessus scan, attach the Target's Credential, launch, poll for completion, export reports, then move the scan to Trash (or permanently delete if `--permanent-delete` is set). A Scan Job is atomic — it either completes fully or fails (with optional retry).
_Avoid_: Task, run, iteration

**Template**:
A Nessus scan policy template (e.g., "Advanced Scan") identified by UUID. Used as the base configuration when creating each temporary scan.
_Avoid_: Policy, profile, preset

**Source Scan**:
A pre-configured scan in Nessus (e.g. `Ubuntu-AdvancedScan`) that CredFlow clones for every target. The source scan's template UUID, plugin family settings, scalar settings (e.g. `max_checks_per_host`), and name are inherited by all created scans. Sensitive settings (SMTP credentials, notification recipients, custom HTTP headers) are excluded from inheritance. This is the primary workflow — template-only scan creation does not inherit plugin family settings.
_Avoid_: Reference scan, base scan

**Plugin Family**:
A group of Nessus plugins (e.g. "Denial of Service", family ID 44). Families can be `enabled` or `disabled`. CredFlow can disable specific families via `--disabled-families` or inherit settings from a source scan. Plugins are passed in the flat `POST /scans` body (`plugins: {Family Name: {id, status}}`), not wrapped in a `families` key.
_Avoid_: Plugin group, plugin category

**Batch**:
A collection of Targets loaded from a single CSV file. All Targets in a Batch share the same Nessus scanner and configuration.
_Avoid_: Set, group, collection

**State**:
The persisted progress of each Target in a Batch, stored in SQLite. States are: `pending` → `running` → `completed` | `failed` (→ `pending` on retry). A `reset_running()` method recovers Targets stuck in `running` after a process crash.
_Avoid_: Status, progress-tracking

**Worker**:
A concurrent execution unit that claims one Target at a time from the State and runs its Scan Job. Multiple Workers can run in parallel within a single Batch, each claiming distinct Targets.
_Avoid_: Thread, process, runner

**Report**:
The output of a completed Scan Job: a `.nessus` file (XML vulnerability data) and a `.db` file (encrypted Nessus database). Both are saved to `./reports/` with the Target's IP and timestamp in the filename. Each `.nessus` report is parsed into a **Vulnerability Summary** (severity counts, open ports, top findings) shown in the batch summary and embedded in `summary_*.json`.
_Avoid_: Export, output, result

**Vulnerability Summary**:
The parsed per-host digest of a `.nessus` report, produced by `report_parser.py`: `severity_counts` (critical/high/medium/low/info), `open_ports` (deduplicated port/protocol/service triples), `top_findings` (severity > 0, capped at 20, sorted by severity then CVSS), and host info (`ip`, `hostname`, `os`, `scan_date` from `HOST_END`). Unparseable reports degrade to a `summary_error` note rather than failing the batch.
_Avoid_: Findings digest, report stats, scan results

**Clean**:
Removes local state database (`credflow_state.db*`) and all report files from `./reports/`. Requires double confirmation (`yes`) unless `--yes` is passed. Does not touch the Nessus server.
_Avoid_: Purge, wipe, reset

**Test Suite**:
202 pytest tests across 11 test files (`test_models.py`, `test_config.py`, `test_colored_formatter.py`, `test_reporter.py`, `test_scanner_helpers.py`, `test_scanner.py`, `test_scanner_advanced.py`, `test_report_parser.py`, `test_cli.py`, `test_state.py`, `test_worker.py`) covering all production modules. Run with `uv run pytest tests/`.
_Avoid_: Test harness, spec, QA script

**Coverage**:
Measured by `pytest-cov` via `uv run pytest tests/ --cov=credflow --cov-report=term`. Overall ~77% across all production modules. Highest: `models.py` (100%), `report_parser.py` (99%), `colored_formatter.py` (97%). Lowest: `cli.py` (~35%) — CLI paths exercised only via unit-level argument parsing, not full subprocess integration.
_Avoid_: Code coverage metric, line hit rate

**Lint**:
Zero-dependency `ruff` with zero violations across all source and test files. Run with `uv run ruff check credflow/ tests/`. Configured in `pyproject.toml` (`[tool.ruff]`).
_Avoid_: Style check, code formatter, linter config
