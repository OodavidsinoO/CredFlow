# Repository Guidelines

## Project Overview

CredFlow is a production-grade automated Nessus vulnerability scanning tool that enforces strict **1-to-1 credential isolation** — each host gets its own temporary scan with its unique credential, preventing account lockouts. Uses session-based auth (username/password) with X-API-Token auto-discovered from Nessus's JavaScript to unlock the full REST API on Nessus Professional (which normally blocks scan creation via API).

## Architecture & Data Flow

```
.env + CLI args → Config.from_env(overrides) → unified Config dataclass
                       │
                       ▼
            parse_targets_csv() → list[Target]  (BOM-safe, validated)
                       │
                       ▼
            StateManager.load_targets() → SQLite (WAL mode)
                       │
                       ▼
         ┌── run_batch() ──────────────────┐
         │  NessusClient(config)            │
         │  get_template_uuid()             │
         │  ThreadPoolExecutor(1–5)         │
         │  ┌── worker_loop() ──────────┐   │
         │  │  claim_next()  (atomic)   │   │
         │  │  run_scan_job()           │   │
         │  │   ├─ create_scan()        │   │
         │  │   ├─ launch_scan()        │   │
         │  │   ├─ poll_until_done()    │   │
         │  │   ├─ export_scan() ×2     │   │
         │  │   ├─ delete_scan(permanent=config.permanent_delete) / trash_scan()        │   │
         │  │   └─ mark_completed()     │   │
         │  └───────────────────────────┘   │
         │  progress_reporter (10s ticker)   │
         └──────────────────────────────────┘
                       │
                       ▼
            _build_summary() → reporter.py
                       │
                       ▼
            print_summary() + generate_summary_json()
```

### Auth Flow
1. `POST /session` with `{username, password}` → extract `token`
2. Set `X-Cookie: token=<token>`
3. If `NESSUS_API_TOKEN` empty: `GET /nessus6.js` → regex `value:function(){return"UUID"}` → extract static X-API-Token
4. Set `X-API-Token: <UUID>`
5. Both headers required for write operations (create/launch/delete scans)

### Concurrency Model
- **ThreadPoolExecutor**: 1–50 workers (hard cap `MAX_WORKERS_HARD_CAP = 50`)
- Each worker gets its **own `NessusClient`** (own `requests.Session` + auth)
- **StateManager** wraps all writes in `threading.Lock` — serialized SQLite access
- `claim_next()` uses `BEGIN EXCLUSIVE` → SELECT pending → UPDATE running → COMMIT (atomic claim)
- `progress_reporter` runs as daemon thread with `threading.Event` stop signal

### Error Handling
- **Custom exceptions**: `CredFlowError` (base), `TemplateNotFoundError`, `ScanTimeoutError` — all in `scanner.py`
- `run_scan_job()`: try/except/finally — `finally` guarantees `delete_scan(permanent=config.permanent_delete)` call
- `mark_failed()`: increments retries; if `retries <= max_retries`, resets to 'pending'
- Worker catches `Exception` from `run_scan_job`, logs via `exc_info=True`, continues
- CLI exits code 1 on any error (validation, scan failure); code 0 on success

## Key Directories

| Directory | Purpose |
|-----------|---------|
| `credflow/` | Python package — all source modules |
| `reports/` | Scan output (.nessus, .db, summary_*.json) — gitignored |
| `.` | Root config files (.env, pyproject.toml, targets.csv) |

## Development Commands

```bash
# ── uv (recommended, 10-100x faster than pip) ──
# Primary workflow: clone source scan
uv run credflow.py check
uv run credflow.py run --targets targets.csv --source-scan "Ubuntu-AdvancedScan"

# With extra disabled families and custom name
uv run credflow.py run --targets targets.csv --source-scan "Ubuntu-AdvancedScan" \
    --disabled-families "Web Crawler" --scan-name-prefix "ProdScan"

# Parallel mode (2 workers)
uv run credflow.py run --targets targets.csv --source-scan "Ubuntu-AdvancedScan" --workers 2

# Permanently delete scans (bypass Trash folder)
uv run credflow.py run --targets targets.csv --source-scan "Ubuntu-AdvancedScan" --permanent-delete

# Project mode — full venv with dev deps
uv sync
uv run python -m credflow check
uv run credflow --version              # console_script entry

# Lock dependencies for reproducible builds
uv lock

# ── pip (fallback) ─────────────────────────
pip install requests urllib3 python-dotenv

# Test Nessus connectivity
python -m credflow check

# Run scans (main workflow)
python -m credflow run --targets targets.csv --source-scan "Ubuntu-AdvancedScan"

# View progress
python -m credflow status

# Retry failed targets
python -m credflow retry

# Clean local state and reports
python -m credflow clean
python -m credflow clean --yes   # skip confirmation

# Verbose/debug mode
python -m credflow run --targets targets.csv --source-scan "Ubuntu-AdvancedScan" -v

# Fresh start (discard state)
python -m credflow run --targets targets.csv --source-scan "Ubuntu-AdvancedScan" --no-resume

# Fallback: manual template + disabled families
python -m credflow run --targets targets.csv --template-name advanced --disabled-families "Denial of Service"

# Hard-coded template UUID
python -m credflow run --targets targets.csv --template-uuid <UUID>
```

## Code Conventions & Common Patterns

### Naming
- **Logger**: `logger = logging.getLogger(__name__)` in every module — never `print()` for runtime output
- **Timestamps**: `datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')` — ISO-like, sortable, filename-safe
- **Report files**: `{target.ip}_{timestamp}.nessus` / `{target.ip}_{timestamp}.db`
- **Summary files**: `summary_{timestamp}.json`
- **State DB**: `credflow_state.db` with `*.db-journal` and `*.db-wal` sidecars (WAL mode)
- **Private helpers**: prefix with `_` (e.g., `_generate_password`, `_build_config`, `_timestamp`)

### State Machine
```
pending → running → completed
                  → failed → pending (if retries ≤ max_retries)
                           → failed (terminal)
```

### Credential Safety (CRITICAL — do not regress)
- **Target repr masks password**: `Target(ip='1.2.3.4', username='admin', password='***', os_type='linux')` — escalation_user and escalation_password also masked
- **No credential logging**: passwords/tokens never appear in log messages
- **DB password logged as length only**: `logger.info("DB password for %s (length=%d)", ip, len(pw))`
- **X-API-Token**: never logged (removed debug line from `_authenticate`)
- **`.env` is gitignored**: never commit real credentials
- **`credflow_state.db` is gitignored**: contains plaintext credentials (known tradeoff for resume)

### Thread Safety
- All StateManager write methods acquire `self._lock` (non-reentrant `threading.Lock`)
- `_get_conn()` creates a **new connection per call** (thread-safe by spec)
- Read methods (`get_progress`, `get_failures`, `is_empty`) do NOT acquire lock — acceptable for WAL readers
- Each worker thread creates its own `NessusClient` — no shared state
- `claim_next()` wraps SELECT+UPDATE in `BEGIN EXCLUSIVE` inside the lock — double-bolted

### REST API Pattern
- `NessusClient._get(path)` — raises on HTTP error via `resp.raise_for_status()`
- `NessusClient._post(path, json=...)` — raises `CredFlowError` on 4xx/5xx with response body
- `NessusClient._put(path, json=...)` — raises `CredFlowError` on 4xx/5xx with response body
- `NessusClient._delete(path)` — best-effort, logs warning on failure
- Export download: POST to request → poll GET status until "ready" → GET download stream

### CSV Parsing
- **Encoding**: `utf-8-sig` (handles Windows BOM)
- **Headers**: case-insensitive, whitespace-stripped
- **Required columns**: `ip`, `username` — missing = row skipped with warning
- **Optional escalation columns**: `escalation_method`, `escalation_user`, `escalation_password` — if absent, no privilege escalation. Valid `escalation_method` values: `sudo`, `su`, `su+sudo`, `dzdo`, `pbrun`, `cisco_enable`, `k5login`, `checkpoint_gaia`. Invalid values raise `CredFlowError` at scan creation.
- **`os_type`**: must be `"linux"` or `"windows"`; defaults to `"linux"` with warning
- **IP validation**: lenient regex `^[a-zA-Z0-9][-a-zA-Z0-9.]*$` — warns but proceeds on mismatch

### Logging
- **Format**: `HH:MM:SS [LEVEL] message`
- **Colors**: ERROR=red, WARNING=yellow, INFO=default, DEBUG=grey; ✓ in messages = green, ✗ = red
- **TTY-safe**: ANSI codes automatically disabled when stdout is piped or `NO_COLOR` is set
- **Default level**: INFO
- **Verbose (`-v`)**: DEBUG (shows HTTP request details from urllib3)
- **Progress**: 10-second ticker in background thread during batch runs
- **Scan completion**: `✓ {ip} completed` / `✗ {ip} failed: {error}`

## Important Files

| File | Role | Key Symbols |
|------|------|------------|
| `credflow/scanner.py` | Core engine | `NessusClient` — `get_template_uuid()`, `get_scan_config()`, `extract_plugins_from_config()`, `resolve_disabled_families()`, `delete_scan()`, `trash_scan()`, `_put()`, `_get_trash_folder_id()`, `_build_credentials()`, `_apply_escalation()`, `_ESCALATION_MAP`, `_ESCALATION_PASSWORD_ONLY`; `run_scan_job()`; `CredFlowError`, `TemplateNotFoundError`, `ScanTimeoutError` |
| `credflow/state.py` | Persistence | `StateManager` — `claim_next()`, `mark_failed()`, `mark_completed()` |
| `credflow/worker.py` | Concurrency | `run_batch()`, `worker_loop()`, `progress_reporter()`, `MAX_WORKERS_HARD_CAP` |
| `credflow/cli.py` | CLI | `main()`, `parse_targets_csv()`, `_build_config()`, `cmd_run()` |
| `credflow/config.py` | Configuration | `Config.from_env()`, `Config.validate()` |
| `credflow/models.py` | Domain | `Target` (masked repr, escalation fields), `ScanJob` |
| `credflow/colored_formatter.py` | Logging colors | `ColoredFormatter` — ANSI color by level + ✓/✗ patterns, zero deps, TTY-safe |
| `credflow/reporter.py` | Output | `print_summary()`, `generate_summary_json()` |
| `pyproject.toml` | Build & deps | PEP 621 metadata, hatchling build, `[project.scripts]` console_scripts |
| `credflow.py` | Standalone entry | PEP 723 inline dep metadata for `uv run credflow.py` |
| `uv.lock` | Lockfile | Pinned dependency graph for reproducible builds |
| `requirements.txt` | Pip fallback | Legacy pip-compatible dependency list |
| `.env.example` | Config template | All env vars + CREDFLOW_PERMANENT_DELETE |
| `targets.csv.example` | Input template | 7-column CSV (ip,username,password,os_type + optional escalation) |
| `CONTEXT.md` | Domain glossary | Target, Credential, Scan Job, Template, Batch, State, Worker, Report |

## Runtime/Tooling Preferences

- **Runtime**: Python 3.12+ (uses `str | None` syntax; f-strings throughout)
- **Package manager**: `uv` (recommended, 10-100x faster); `pip` as fallback
- **Entry points** (three ways):
  1. `uv run credflow.py <cmd>` — PEP 723 standalone script, auto-installs deps in ephemeral venv (~6ms)
  2. `uv run python -m credflow <cmd>` — project mode, after `uv sync`
  3. `uv run credflow <cmd>` — `[project.scripts]` console_script entry point
- **Build system**: `hatchling` (declared in `pyproject.toml`)
- **Dependencies**: `requests>=2.31.0`, `urllib3>=2.0.0`, `python-dotenv>=1.0.0`; dev deps: `pytest`, `ruff`
- **No pyTenable SDK**: uses raw `requests.Session` for direct REST API calls
- **SSL**: verify disabled by default (self-signed Nessus certs); `urllib3.disable_warnings()` per-session
- **SQLite**: WAL journal mode, 5s busy timeout, `check_same_thread=False` not needed (per-connection pattern)

## Testing & QA

- **Test suite**: 168 pytest tests (75% coverage) covering all modules
- **Run tests**: `uv run pytest tests/ -v`
- **Run with coverage**: `uv run pytest tests/ --cov=credflow --cov-report=term`
- **Lint**: `uv run ruff check credflow/ tests/` — 0 violations

### Coverage by Module

| Module | Stmts | Coverage |
|--------|-------|----------|
| `models.py` | 9 | **100%** |
| `reporter.py` | 58 | **98%** |
| `colored_formatter.py` | 32 | **97%** |
| `config.py` | 96 | **96%** |
| `state.py` | 111 | **95%** |
| `scanner.py` | 283 | **93%** |
| `worker.py` | 125 | **79%** |
| `cli.py` | 286 | **35%** |

### Test Structure

  - `tests/test_models.py` — Target dataclass, repr masking
  - `tests/test_config.py` — Config.from_env(), validate(), override merging
  - `tests/test_colored_formatter.py` — ANSI coloring, TTY detection, pipe safety
  - `tests/test_reporter.py` — Summary/progress output, JSON generation
  - `tests/test_scanner_helpers.py` — Password generation, credentials builder, timestamp
  - `tests/test_scanner.py` — Auth, CRUD, polling, export, run_scan_job lifecycle
  - `tests/test_scanner_advanced.py` — Source scan cloning, plugin extraction
  - `tests/test_cli.py` — CSV parsing (BOM, whitespace, validation), argparse
  - `tests/test_state.py` — SQLite CRUD, atomic claims, retry logic, thread safety
  - `tests/test_worker.py` — Batch execution, worker loop, progress reporter
- **Primary workflow**: `--source-scan` clones an existing Nessus scan's template + plugin settings + naming via `/editor/scan/{id}`. Always prefer this over manual `--template-name`.
- **Smoke test**: `uv run credflow.py check` (connectivity)
- **Full E2E**: `uv run credflow.py run --targets targets.csv --source-scan "Ubuntu-AdvancedScan"`
