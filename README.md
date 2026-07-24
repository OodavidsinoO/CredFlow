# CredFlow

> Automated Nessus credentialed scanning with strict 1-to-1 host-to-credential isolation.

[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![uv](https://img.shields.io/badge/uv-package%20manager-de7f21.svg)](https://docs.astral.sh/uv/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Why CredFlow?

Running credentialed vulnerability scans on hundreds of servers with **unique per-host credentials** is a nightmare with Nessus Professional. Placing all credentials in one scan policy causes Nessus to try every credential against every host — triggering **account lockout policies** across your entire fleet.

CredFlow solves this by enforcing a strict **1-to-1 dynamic isolation lifecycle**:

1. Pick ONE host and its specific credential from CSV input
2. Dynamically create a **temporary Nessus scan** dedicated ONLY to that IP with ONLY its credential
3. Launch → wait for completion → export reports (`.nessus` + `.db`)
4. **Move the scan to Trash** (or permanently delete with `--permanent-delete`)
5. Move to the next host (progress saving & resume support)

---

## Quick Start

### Prerequisites

- Python 3.12+
- Nessus Professional (with web UI access)
- Nessus username/password (not just API keys)
- **A pre-configured scan in Nessus** (e.g. `Ubuntu-AdvancedScan`) with your desired template, plugin settings, and credentials structure

### Installation

```bash
git clone <repo-url> CredFlow
cd CredFlow

# Recommended: uv (10-100x faster, auto-manages venv)
uv sync
```

### Dependencies

- **Runtime**: `requests>=2.31.0`, `urllib3>=2.0.0`, `python-dotenv>=1.0.0`
- **Dev**: `pytest`, `pytest-cov`, `responses`, `ruff`

### Configuration

```bash
cp .env.example .env
```

Edit `.env` — the three required fields plus your source scan name:

```bash
# Minimum required
NESSUS_URL=https://your-nessus:8834
NESSUS_USERNAME=your_nessus_username
NESSUS_PASSWORD=your_nessus_password

# Primary workflow: clone an existing scan's settings
SOURCE_SCAN_NAME=Ubuntu-AdvancedScan
```

### Create Targets CSV

```csv
ip,username,password,os_type
192.168.1.134,root,password1,linux
192.168.1.131,Administrator,Pass123!,windows
```

### Run

```bash
# Test connectivity
uv run credflow.py check

# Primary workflow: clone source scan for every target
uv run credflow.py run --targets targets.csv --source-scan "Ubuntu-AdvancedScan"

# Parallel mode (2 workers)
uv run credflow.py run --targets targets.csv --source-scan "Ubuntu-AdvancedScan" --workers 2

# Permanently delete scans instead of moving to Trash
uv run credflow.py run --targets targets.csv --source-scan "Ubuntu-AdvancedScan" --permanent-delete

# View progress
uv run credflow.py status

# Retry failed hosts
uv run credflow.py retry

# Clean local state and reports (double confirm)
uv run credflow.py clean
uv run credflow.py clean --yes   # skip confirmation
```

---

## Primary Workflow: Source Scan

The recommended workflow: create **one** scan in the Nessus UI with your desired
template, plugin families, and credential structure — then point CredFlow at it.

```bash
uv run credflow.py run --targets targets.csv --source-scan "Ubuntu-AdvancedScan"
```

CredFlow will:
1. Fetch that scan's full configuration via the API (`/editor/scan/{id}`)
2. Use its **template** (e.g. Advanced Scan)
3. Copy its **plugin family settings** (e.g. Denial of Service → disabled)
4. Default the scan name to `Ubuntu-AdvancedScan-{IP}`
5. Add per-host credentials from your CSV on top

Store the source scan name in `.env` to skip the repetitive CLI flag:

```bash
# .env
SOURCE_SCAN_NAME=Ubuntu-AdvancedScan
```

Then just:

```bash
uv run credflow.py run --targets targets.csv
```

### Override specific plugin families

Add `--disabled-families` to disable extra families on top of what the source
scan already disables:

```bash
uv run credflow.py run --targets targets.csv --source-scan "Ubuntu-AdvancedScan" \
    --disabled-families "Web Crawler"
```

---

## Entry Methods

```bash
# 1. Standalone script — zero-install, PEP 723 auto-deps (~6ms)
uv run credflow.py check

# 2. Project mode — after uv sync
uv run python -m credflow check

# 3. Console script — after uv sync
uv run credflow --version

# 4. pip fallback
python -m credflow check
```

---

## Commands

| Command | Description |
|---------|-------------|
| `credflow check` | Test Nessus connectivity |
| `credflow run --targets <csv>` | Execute scan batch |
| `credflow status` | Show scan progress |
| `credflow retry` | Reset failed → pending |
| `credflow clean` | Remove state DB + all reports |

### `run` Options

| Flag | Default | Description |
|------|---------|-------------|
| `--targets` | *(required)* | Path to targets CSV file |
| `--source-scan` | — | **Primary**: clone template + plugins + naming from existing scan |
| `--disabled-families` | — | Extra plugin families to disable (comma-separated) |
| `--scan-name-prefix` | source scan / `CredFlow` | Prefix for created scan names |
| `--workers` | `1` | Parallel workers (max 5) |
| `--retries` | `1` | Max retries per failed target |
| `--reports-dir` | `./reports` | Report output directory |
| `--db-password` | auto-generated | Password for .db export |
| `--template-name` | `advanced` | Fallback: scan template to use |
| `--template-uuid` | auto-discovered | Fallback: hard-coded template UUID |
| `--timeout` | `3600` | Max seconds per scan |
| `--poll-interval` | `30` | Seconds between status checks |
| `--no-resume` | `false` | Start fresh (discard state) |
| `--permanent-delete` | `false` | Permanently delete scans instead of moving to Trash |
| `-v` / `--verbose` | `false` | Debug logging |

### Fallback: Manual Template Selection

When you don't have a source scan, use `--template-name` + `--disabled-families`:

```bash
uv run credflow.py run --targets targets.csv \
    --template-name advanced \
    --disabled-families "Denial of Service" \
    --scan-name-prefix "ProdScan"
```

Or hard-code the template UUID:

```bash
uv run credflow.py run --targets targets.csv --template-uuid ad629e16-... \
    --disabled-families "Denial of Service"
```

**Priority**: `--source-scan` > `--template-name` > `--template-uuid`.

---

## Architecture

```
.env + CLI args → Config → CSV Parser → SQLite State DB
                                            │
                               ThreadPoolExecutor (1–5 workers)
                                            │
                               ┌── worker_loop() ──────────┐
                               │  claim_next()  (atomic)   │
                               │  run_scan_job()           │
                               │   ├─ create_scan()        │
                               │   ├─ launch_scan()        │
                               │   ├─ poll_until_done()    │
                               │   ├─ export_scan() ×2     │
                               │   ├─ trash_scan()         │
                               │   └─ mark_completed()     │
                               └───────────────────────────┘
                                            │
                               Summary → Console + JSON
```

### Key Design Decisions

- **Source scan cloning**: Fetches an existing scan's full policy via `/editor/scan/{id}` — inherits template, plugin families, and naming. The primary workflow.
- **Trash by default**: Completed scans are moved to the Nessus Trash folder (not permanently deleted). Use `--permanent-delete` or `CREDFLOW_PERMANENT_DELETE=true` to override. Trash folder ID is auto-discovered via `GET /folders`.
- **uv package manager**: 10-100x faster than pip; three entry methods (standalone script / project / console_script)
- **PEP 723 inline deps**: `credflow.py` declares its own dependencies — `uv run credflow.py` auto-installs in an ephemeral venv
- **Raw REST API**: Uses `requests.Session` directly (not pyTenable SDK) to support dual auth headers required by Nessus Professional
- **X-API-Token Discovery**: Auto-extracts the internal API token from Nessus's `nessus6.js` at startup — no browser/Selenium needed
- **SQLite WAL**: Write-Ahead Logging mode for concurrent read safety
- **Atomic Claims**: `BEGIN EXCLUSIVE` transaction prevents two workers grabbing the same target
- **Per-worker Sessions**: Each worker thread gets its own `NessusClient` with independent authentication

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NESSUS_URL` | **Yes** | — | Nessus server URL |
| `NESSUS_USERNAME` | **Yes** | — | Nessus UI username |
| `NESSUS_PASSWORD` | **Yes** | — | Nessus UI password |
| `SOURCE_SCAN_NAME` | *(recommended)* | — | **Primary**: clone template + plugins from this existing scan |
| `SCAN_TEMPLATE_NAME` | No | `advanced` | Fallback: template name to search |
| `SCAN_TEMPLATE_UUID` | No | auto | Fallback: override template UUID |
| `DISABLED_PLUGIN_FAMILIES` | No | — | Extra plugin families to disable (comma-separated) |
| `SCAN_NAME_PREFIX` | No | source scan / `CredFlow` | Prefix for created scan names |
| `NESSUS_API_TOKEN` | No | auto | X-API-Token (auto-discovered if empty) |
| `NESSUS_SSL_VERIFY` | No | `false` | Enable SSL verification |
| `DB_PASSWORD` | No | random | Password for .db export |
| `CREDFLOW_MAX_WORKERS` | No | `1` | Parallel workers |
| `CREDFLOW_MAX_RETRIES` | No | `1` | Retry attempts |
| `CREDFLOW_POLL_INTERVAL` | No | `30` | Status poll seconds |
| `CREDFLOW_POLL_TIMEOUT` | No | `3600` | Max scan wait seconds |
| `CREDFLOW_BATCH_TIMEOUT` | No | `0` | Max wall-clock seconds for entire batch (0 = no limit) |
| `CREDFLOW_PERMANENT_DELETE` | No | `false` | Permanently delete scans instead of moving to Trash |
| `CREDFLOW_REPORTS_DIR` | No | `./reports` | Output directory |

---

## Output

```
reports/
├── 192.168.1.131_20260724T075006Z.nessus    # XML vulnerability data
├── 192.168.1.131_20260724T075006Z.db        # Encrypted Nessus DB
├── 192.168.1.134_20260724T075042Z.nessus
├── 192.168.1.134_20260724T075042Z.db
└── summary_20260724T075047Z.json            # Batch summary
```

---

## Security

- `.env` and `credflow_state.db` are **gitignored** — never commit credentials
- **Password masking**: `Target.__repr__` shows `password='***'`
- **No credential logging**: passwords/tokens never appear in log output
- **SSL**: verification disabled by default (Nessus uses self-signed certs); enable via `NESSUS_SSL_VERIFY=true`
- **Trash recovery**: Scans are moved to the Nessus Trash folder by default, providing a safety net against accidental deletion. Use `--permanent-delete` or `CREDFLOW_PERMANENT_DELETE=true` to bypass.
- **State DB** contains plaintext credentials — protect accordingly (restrictive file permissions recommended)

---

## Testing

```bash
# Run full test suite (171 tests, 75% coverage)
uv run pytest tests/ -v

# With coverage report
uv run pytest tests/ --cov=credflow --cov-report=term

# Run specific test file
uv run pytest tests/test_scanner.py -v

# Lint check
uv run ruff check credflow/ tests/
```

---

## License

MIT License — see [LICENSE](LICENSE) file.
