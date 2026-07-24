"""Shared test fixtures for CredFlow."""

import os
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from credflow.config import Config
from credflow.models import Target

# ── Temp dirs & files ───────────────────────────────────────────

@pytest.fixture
def tmp_dir():
    """Temporary directory that auto-cleans up."""
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def state_db_path(tmp_dir):
    """Path to a non-existent SQLite DB in a temp dir."""
    return str(tmp_dir / "test_state.db")


# ── Config fixtures ─────────────────────────────────────────────

@pytest.fixture
def minimal_config():
    """Config with minimum required fields filled."""
    return Config(
        nessus_url="https://nessus.example.com:8834",
        nessus_username="admin",
        nessus_password="secret",
    )


@pytest.fixture
def full_config():
    """Config with all common fields set."""
    return Config(
        nessus_url="https://nessus.example.com:8834",
        nessus_username="admin",
        nessus_password="secret",
        nessus_api_token="test-token-123",
        template_name="advanced",
        source_scan_name="Ubuntu-AdvancedScan",
        disabled_plugin_families="Denial of Service",
        scan_name_prefix="ProdScan",
        max_workers=2,
        max_retries=2,
        poll_interval=15,
        poll_timeout=600,
        reports_dir="./test-reports",
        db_password="test-db-pw",
        resume=True,
    )


@pytest.fixture
def clean_env(monkeypatch):
    """Remove all CredFlow-related env vars for a clean test."""
    for key in list(os.environ):
        if any(
            prefix in key.upper()
            for prefix in ("NESSUS_", "CREDFLOW_", "SCAN_", "DB_", "DISABLED_", "SOURCE_")
        ):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)


# ── Target fixtures ──────────────────────────────────────────────

@pytest.fixture
def linux_target():
    """A typical Linux target."""
    return Target(ip="10.0.0.1", username="root", password="hunter2", os_type="linux")


@pytest.fixture
def windows_target():
    """A typical Windows target."""
    return Target(
        ip="10.0.0.2", username="Administrator", password="Pass123!", os_type="windows"
    )


@pytest.fixture
def sample_targets():
    """A list of diverse targets."""
    return [
        Target(ip="10.0.0.1", username="root", password="pw1", os_type="linux"),
        Target(ip="10.0.0.2", username="admin", password="pw2", os_type="windows"),
        Target(ip="10.0.0.3", username="ubuntu", password="pw3", os_type="linux"),
    ]


# ── SQLite fixtures ──────────────────────────────────────────────

@pytest.fixture
def fresh_db(state_db_path):
    """In-memory SQLite database with the targets schema."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS targets (
            ip TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            os_type TEXT NOT NULL DEFAULT 'linux',
            status TEXT NOT NULL DEFAULT 'pending',
            error TEXT,
            retries INTEGER NOT NULL DEFAULT 0,
            report_nessus TEXT,
            report_db TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"""
    )
    conn.commit()
    yield conn
    conn.close()


# ── Mock HTTP fixtures ───────────────────────────────────────────

@pytest.fixture
def mock_session():
    """A mock requests.Session with configurable responses."""
    session = MagicMock()
    session.verify = False
    return session


# ── CSV fixtures ─────────────────────────────────────────────────

@pytest.fixture
def valid_csv(tmp_dir):
    """A valid targets CSV file."""
    path = tmp_dir / "targets.csv"
    path.write_text(
        "ip,username,password,os_type\n"
        "10.0.0.1,root,secret1,linux\n"
        "10.0.0.2,Administrator,secret2,windows\n"
        "10.0.0.3,ubuntu,secret3,linux\n"
    )
    return str(path)


@pytest.fixture
def csv_with_bom(tmp_dir):
    """A CSV file with UTF-8 BOM (Windows-created)."""
    path = tmp_dir / "bom.csv"
    path.write_bytes(
        b"\xef\xbb\xbfip,username,password,os_type\n"
        b"10.0.0.1,root,secret1,linux\n"
    )
    return str(path)


@pytest.fixture
def csv_with_blanks(tmp_dir):
    """A CSV file with empty rows and whitespace headers."""
    path = tmp_dir / "blanks.csv"
    path.write_text(
        "  ip  ,  username  ,  password  ,  os_type  \n"
        "10.0.0.1,root,secret1,linux\n"
        "\n"
        "10.0.0.2,,,windows\n"  # missing username
        "10.0.0.3,ubuntu,secret3,\n"  # missing os_type → defaults to linux
    )
    return str(path)
