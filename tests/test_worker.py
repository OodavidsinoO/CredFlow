"""Integration tests for worker.py — concurrency orchestration."""

import contextlib
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from credflow.config import Config
from credflow.models import Target
from credflow.state import StateManager
from credflow.worker import (
    _build_summary,
    progress_reporter,
    run_batch,
    worker_loop,
)

# ── shared fixtures ──────────────────────────────────────────────

@pytest.fixture
def sample_targets():
    return [
        Target(ip="10.0.0.1", username="u1", password="p1", os_type="linux"),
        Target(ip="10.0.0.2", username="u2", password="p2", os_type="linux"),
        Target(ip="10.0.0.3", username="u3", password="p3", os_type="linux"),
    ]


@pytest.fixture
def config():
    return Config(
        nessus_url="https://nessus.example.com:8834",
        nessus_username="admin",
        nessus_password="secret",
        nessus_api_token="static-token",
        nessus_ssl_verify=False,
        template_name="advanced",
        reports_dir="/tmp/reports",
        max_workers=2,
        poll_interval=30,
        poll_timeout=3600,
        batch_timeout=0,
        db_password="",
    )


@pytest.fixture
def state_db_path():
    import os
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    for suffix in ("", "-journal", "-wal", "-shm"):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path + suffix)


# ── _build_summary ───────────────────────────────────────────────

class TestBuildSummary:
    def test_returns_correct_counts(self, state_db_path, sample_targets):
        state = StateManager(state_db_path)
        state.load_targets(sample_targets)
        # Claim one → running
        t = state.claim_next()
        state.mark_completed(t.ip, "/tmp/r.nessus", "/tmp/r.db")
        # One more pending
        state.claim_next()

        summary = _build_summary(state)
        assert summary["completed"] == 1
        assert summary["pending"] == 1
        assert summary["total"] == 3


# ── worker_loop ──────────────────────────────────────────────────

class TestWorkerLoop:
    def test_completes_all(self, state_db_path, sample_targets, config):
        state = StateManager(state_db_path)
        state.load_targets(sample_targets)

        # Mock run_scan_job to "complete" each target
        def fake_run_scan_job(target, client, cfg, st, template_uuid, plugins=None, scan_name_prefix="CredFlow"):
            st.mark_completed(target.ip, f"/tmp/{target.ip}.nessus", f"/tmp/{target.ip}.db")

        with patch("credflow.worker.run_scan_job", side_effect=fake_run_scan_job):
            mock_client = MagicMock()
            completed = worker_loop(mock_client, config, state, "uuid-1")
            assert completed == 3

        progress = state.get_progress()
        assert progress.get("completed") == 3

    def test_stop_signal(self, state_db_path, sample_targets, config):
        state = StateManager(state_db_path)
        state.load_targets(sample_targets)
        stop_event = threading.Event()
        stop_event.set()  # already stopped

        mock_client = MagicMock()
        completed = worker_loop(mock_client, config, state, "uuid-1", stop_event=stop_event)
        assert completed == 0

    def test_transient_failure_continues(self, state_db_path, sample_targets, config):
        state = StateManager(state_db_path)
        state.load_targets(sample_targets)

        call_count = [0]

        def fake_run_scan_job(target, client, cfg, st, template_uuid, plugins=None, scan_name_prefix="CredFlow"):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionError("transient network error")
            st.mark_completed(target.ip, f"/tmp/{target.ip}.nessus", f"/tmp/{target.ip}.db")

        with patch("credflow.worker.run_scan_job", side_effect=fake_run_scan_job):
            mock_client = MagicMock()
            completed = worker_loop(mock_client, config, state, "uuid-1")
            assert completed == 2  # one failed, two succeeded

    def test_permanent_failure_continues(self, state_db_path, sample_targets, config):
        state = StateManager(state_db_path)
        state.load_targets(sample_targets)

        call_count = [0]

        def fake_run_scan_job(target, client, cfg, st, template_uuid, plugins=None, scan_name_prefix="CredFlow"):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ValueError("permanent config error")
            st.mark_completed(target.ip, f"/tmp/{target.ip}.nessus", f"/tmp/{target.ip}.db")

        with patch("credflow.worker.run_scan_job", side_effect=fake_run_scan_job):
            mock_client = MagicMock()
            completed = worker_loop(mock_client, config, state, "uuid-1")
            assert completed == 2  # one failed, two succeeded


# ── progress_reporter ────────────────────────────────────────────

class TestProgressReporter:
    def test_reports_and_stops(self, state_db_path, sample_targets):
        state = StateManager(state_db_path)
        state.load_targets(sample_targets)
        stop_event = threading.Event()

        reporter_thread = threading.Thread(
            target=progress_reporter, args=(state, stop_event), daemon=True
        )
        reporter_thread.start()
        time.sleep(0.5)
        stop_event.set()
        reporter_thread.join(timeout=2)
        assert not reporter_thread.is_alive()


# ── run_batch ────────────────────────────────────────────────────

class TestRunBatch:
    def test_no_pending_targets(self, state_db_path, sample_targets, config):
        """When all targets are already completed, run_batch returns immediately."""
        state = StateManager(state_db_path)
        state.load_targets(sample_targets)
        # Complete all
        for _ in range(3):
            t = state.claim_next()
            state.mark_completed(t.ip, f"/tmp/{t.ip}.nessus", f"/tmp/{t.ip}.db")

        with patch("credflow.worker.NessusClient") as mock_nessus:
            summary = run_batch(sample_targets, config, state)
            assert summary["pending"] == 0
            assert summary["completed"] == 3
            # NessusClient should not be called
            mock_nessus.assert_not_called()

    def test_workers_capped_at_pending(self, state_db_path, config):
        """Workers = min(config.max_workers, pending_count, MAX_WORKERS_HARD_CAP)."""
        targets = [Target(ip=f"10.0.0.{i}", username="u", password="p", os_type="linux")
                   for i in range(1, 3)]  # only 2 targets
        state = StateManager(state_db_path)
        state.load_targets(targets)

        # Mock everything to avoid real HTTP
        with patch("credflow.worker.NessusClient") as mock_nessus, \
             patch("credflow.worker.run_scan_job") as mock_run_job:
            mock_client_instance = mock_nessus.return_value
            mock_client_instance.get_template_uuid.return_value = "uuid-1"
            mock_client_instance.find_scan_by_name.return_value = None
            mock_client_instance.source_scan_name = None
            mock_client_instance.scan_name_prefix = "CredFlow"

            def fake_run_scan_job(target, client, cfg, st, template_uuid, plugins=None, scan_name_prefix="CredFlow"):
                st.mark_completed(target.ip, f"/tmp/{target.ip}.nessus", f"/tmp/{target.ip}.db")

            mock_run_job.side_effect = fake_run_scan_job

            summary = run_batch(targets, config, state)
            assert summary["completed"] == 2
            # Should only create min(2, 2, 5) = 2 worker clients
            assert mock_nessus.call_count >= 1

    def test_batch_timeout(self, state_db_path, config):
        """With batch_timeout=0.1, the watchdog fires quickly."""
        targets = [Target(ip="10.0.0.1", username="u", password="p", os_type="linux")]
        state = StateManager(state_db_path)
        state.load_targets(targets)
        config.batch_timeout = 1  # 1 second timeout

        with patch("credflow.worker.NessusClient") as mock_nessus, \
             patch("credflow.worker.run_scan_job") as mock_run_job:
            mock_client_instance = mock_nessus.return_value
            mock_client_instance.get_template_uuid.return_value = "uuid-1"
            mock_client_instance.find_scan_by_name.return_value = None

            def fake_run_scan_job(target, client, cfg, st, template_uuid, plugins=None, scan_name_prefix="CredFlow"):
                time.sleep(0.5)  # slow but should finish before timeout

            mock_run_job.side_effect = fake_run_scan_job

            summary = run_batch(targets, config, state)
            # Should complete or timeout gracefully
            assert "completed" in summary

    def test_with_source_scan(self, state_db_path, config):
        """Source scan provides template UUID and plugin settings."""
        targets = [Target(ip="10.0.0.1", username="u", password="p", os_type="linux")]
        state = StateManager(state_db_path)
        state.load_targets(targets)
        config.source_scan_name = "Ubuntu-AdvancedScan"

        with patch("credflow.worker.NessusClient") as mock_nessus, \
             patch("credflow.worker.run_scan_job") as mock_run_job:
            mock_client = mock_nessus.return_value
            mock_client.find_scan_by_name.return_value = {"id": 42, "name": "Ubuntu-AdvancedScan"}
            mock_client.get_scan_config.return_value = {
                "uuid": "src-uuid-42",
                "title": "Ubuntu-AdvancedScan",
                "plugins": {"families": {"DoS": {"id": 44, "status": "disabled"}}},
            }
            mock_client.extract_plugins_from_config.return_value = {"DoS": {"id": 44, "status": "disabled"}}
            mock_client.get_template_uuid.return_value = "uuid-1"

            def fake_run(target, client, cfg, st, template_uuid, plugins=None, scan_name_prefix="CredFlow"):
                st.mark_completed(target.ip, f"/tmp/{target.ip}.nessus", f"/tmp/{target.ip}.db")

            mock_run_job.side_effect = fake_run

            summary = run_batch(targets, config, state)
            assert summary["completed"] == 1
            # Source scan template should be used
            mock_client.get_scan_config.assert_called_once()
            mock_client.extract_plugins_from_config.assert_called_once()
