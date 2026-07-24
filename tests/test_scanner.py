"""Integration tests for NessusClient — mocked HTTP via `responses` library."""

import contextlib
import json
import os
import tempfile

import pytest
import responses

from credflow.config import Config
from credflow.models import Target
from credflow.scanner import (
    CredFlowError,
    NessusClient,
    ScanTimeoutError,
    TemplateNotFoundError,
    run_scan_job,
)
from credflow.state import StateManager

# ── shared fixtures ──────────────────────────────────────────────

@pytest.fixture
def base_url():
    return "https://nessus.example.com:8834"


@pytest.fixture
def config_dict(base_url):
    return {
        "nessus_url": base_url,
        "nessus_username": "admin",
        "nessus_password": "secret",
        "nessus_api_token": "",
        "nessus_ssl_verify": False,
        "template_name": "advanced",
        "reports_dir": "/tmp/reports",
        "max_workers": 1,
        "poll_interval": 30,
        "poll_timeout": 3600,
        "db_password": "",
    }


@pytest.fixture
def config(config_dict):
    return Config(**config_dict)


@pytest.fixture
def target():
    return Target(ip="10.0.0.1", username="root", password="pass", os_type="linux")


@pytest.fixture
def state_db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    for suffix in ("-journal", "-wal", "-shm"):
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path + suffix)


# ── helper ───────────────────────────────────────────────────────

def _mock_login(responses_mock: responses.RequestsMock, base_url: str, token: str = "session-token-123"):
    responses_mock.add(
        responses.POST,
        f"{base_url}/session",
        json={"token": token},
        status=200,
    )


def _mock_api_token_discovery(responses_mock: responses.RequestsMock, base_url: str, token: str = "57879e5a-9092-46a9-b397-c810823e725b"):
    responses_mock.add(
        responses.GET,
        f"{base_url}/nessus6.js",
        body=f'value:function(){{return"{token}"}}',
        status=200,
        content_type="application/javascript",
    )


def _full_auth(responses_mock: responses.RequestsMock, base_url: str):
    _mock_login(responses_mock, base_url)
    _mock_api_token_discovery(responses_mock, base_url)


# ── authentication ───────────────────────────────────────────────

class TestAuthenticate:
    def test_login_success(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            assert "X-Cookie" in client._session.headers
            assert "X-API-Token" in client._session.headers

    def test_login_failure(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, f"{base_url}/session", status=401, body="Unauthorized")
            with pytest.raises(CredFlowError, match="Login failed"):
                NessusClient(Config(**config_dict))

    def test_login_missing_token(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            rsps.add(responses.POST, f"{base_url}/session", json={}, status=200)
            with pytest.raises(CredFlowError, match="missing token"):
                NessusClient(Config(**config_dict))

    def test_api_token_from_config(self, config_dict, base_url):
        config_dict["nessus_api_token"] = "static-token-999"
        with responses.RequestsMock() as rsps:
            _mock_login(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            assert client._session.headers["X-API-Token"] == "static-token-999"

    def test_api_token_discovery_fallback(self, config_dict, base_url):
        """When nessus6.js has no UUID token → discovery fails."""
        with responses.RequestsMock() as rsps:
            _mock_login(rsps, base_url)
            rsps.add(
                responses.GET,
                f"{base_url}/nessus6.js",
                body="var x = 1; function foo() { return 'bar'; }",
                status=200,
            )
            with pytest.raises(CredFlowError, match="Could not discover"):
                NessusClient(Config(**config_dict))


# ── check_connection ─────────────────────────────────────────────

class TestCheckConnection:
    def test_healthy(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.GET, f"{base_url}/server/status", json={"status": "ready"})
            rsps.add(responses.GET, f"{base_url}/server/properties",
                     json={"server_version": "10.7.0", "uuid": "scanner-uuid"})
            client = NessusClient(Config(**config_dict))
            info = client.check_connection()
            assert info["status"] == "ready"
            assert info["version"] == "10.7.0"


# ── template resolution ──────────────────────────────────────────

class TestGetTemplateUuid:
    def test_exact_match(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(
                responses.GET,
                f"{base_url}/editor/scan/templates",
                json={"templates": [
                    {"name": "Advanced Scan", "uuid": "uuid-advanced"},
                    {"name": "Basic Network Scan", "uuid": "uuid-basic"},
                ]},
            )
            client = NessusClient(Config(**config_dict))
            uuid = client.get_template_uuid("Advanced Scan")
            assert uuid == "uuid-advanced"

    def test_substring_match(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(
                responses.GET,
                f"{base_url}/editor/scan/templates",
                json={"templates": [
                    {"name": "Custom Advanced Scan", "uuid": "uuid-custom-advanced"},
                ]},
            )
            client = NessusClient(Config(**config_dict))
            uuid = client.get_template_uuid("advanced")
            assert uuid == "uuid-custom-advanced"

    def test_not_found(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(
                responses.GET,
                f"{base_url}/editor/scan/templates",
                json={"templates": [{"name": "Basic", "uuid": "uuid-basic"}]},
            )
            client = NessusClient(Config(**config_dict))
            with pytest.raises(TemplateNotFoundError):
                client.get_template_uuid("nonexistent")

    def test_config_override(self, config_dict, base_url):
        config_dict["template_uuid"] = "forced-uuid"
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            uuid = client.get_template_uuid("anything")
            assert uuid == "forced-uuid"


class TestGetTemplateDetail:
    def test_returns_detail(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            detail = {"uuid": "uuid-1", "plugins": {"families": {"DoS": {"id": 44, "status": "disabled"}}}}
            rsps.add(responses.GET, f"{base_url}/editor/scan/templates/uuid-1", json=detail)
            client = NessusClient(Config(**config_dict))
            assert client.get_template_detail("uuid-1") == detail


# ── plugin family resolution ─────────────────────────────────────

class TestResolveDisabledFamilies:
    def test_exact_match(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(
                responses.GET,
                f"{base_url}/editor/scan/templates/uuid-1",
                json={"plugins": {"families": {
                    "Denial of Service": {"id": 44, "status": "enabled"},
                    "Web Crawler": {"id": 100, "status": "enabled"},
                }}},
            )
            client = NessusClient(Config(**config_dict))
            plugins = client.resolve_disabled_families(["Denial of Service"], "uuid-1")
            assert plugins == {"Denial of Service": {"id": 44, "status": "disabled"}}

    def test_substring_match(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(
                responses.GET,
                f"{base_url}/editor/scan/templates/uuid-1",
                json={"plugins": {"families": {
                    "Denial of Service": {"id": 44, "status": "enabled"},
                }}},
            )
            client = NessusClient(Config(**config_dict))
            # "Denial" is a real substring of "Denial of Service"
            plugins = client.resolve_disabled_families(["Denial"], "uuid-1")
            assert plugins["Denial of Service"]["status"] == "disabled"

    def test_empty_input(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            assert client.resolve_disabled_families([], "uuid-1") == {}


# ── scan lifecycle ───────────────────────────────────────────────

class TestCreateScan:
    def test_creates_linux_scan(self, config_dict, base_url, target):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(
                responses.POST,
                f"{base_url}/scans",
                json={"scan": {"id": 42}},
                status=200,
            )
            client = NessusClient(Config(**config_dict))
            scan_id = client.create_scan(target, "uuid-1")
            assert scan_id == 42
            req_body = json.loads(rsps.calls[-1].request.body)
            assert req_body["uuid"] == "uuid-1"
            assert "SSH" in json.dumps(req_body["credentials"])

    def test_creates_with_plugins(self, config_dict, base_url, target):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.POST, f"{base_url}/scans", json={"scan": {"id": 43}}, status=200)
            client = NessusClient(Config(**config_dict))
            plugins = {"DoS": {"id": 44, "status": "disabled"}}
            scan_id = client.create_scan(target, "uuid-1", plugins=plugins)
            assert scan_id == 43
            req_body = json.loads(rsps.calls[-1].request.body)
            assert req_body["plugins"] == plugins

    def test_error_no_id(self, config_dict, base_url, target):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.POST, f"{base_url}/scans", json={"error": "bad"}, status=200)
            client = NessusClient(Config(**config_dict))
            with pytest.raises(CredFlowError, match="no id"):
                client.create_scan(target, "uuid-1")


class TestLaunchScan:
    def test_launches(self, config_dict, base_url, target):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.POST, f"{base_url}/scans", json={"scan": {"id": 44}}, status=200)
            rsps.add(responses.POST, f"{base_url}/scans/44/launch", json={}, status=200)
            client = NessusClient(Config(**config_dict))
            scan_id = client.create_scan(target, "uuid-1")
            client.launch_scan(scan_id)  # should not raise


class TestPollUntilDone:
    def test_completed(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.GET, f"{base_url}/scans/1",
                     json={"info": {"status": "completed"}})
            client = NessusClient(Config(**config_dict))
            status = client.poll_until_done(1, poll_interval=1, timeout=10)
            assert status == "completed"

    def test_paused_then_completed(self, config_dict, base_url):
        """Paused is a terminal state per our implementation."""
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.GET, f"{base_url}/scans/1",
                     json={"info": {"status": "paused"}})
            client = NessusClient(Config(**config_dict))
            status = client.poll_until_done(1, poll_interval=1, timeout=10)
            assert status == "paused"

    def test_polling_then_completed(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            # First poll: running, second: completed
            rsps.add(responses.GET, f"{base_url}/scans/1",
                     json={"info": {"status": "running"}})
            rsps.add(responses.GET, f"{base_url}/scans/1",
                     json={"info": {"status": "completed"}})
            client = NessusClient(Config(**config_dict))
            status = client.poll_until_done(1, poll_interval=1, timeout=10)
            assert status == "completed"

    def test_timeout(self, config_dict, base_url):
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            _full_auth(rsps, base_url)
            # poll_interval floored at 5 → 2 calls before timeout=6
            for _ in range(3):
                rsps.add(responses.GET, f"{base_url}/scans/1",
                         json={"info": {"status": "running"}})
            client = NessusClient(Config(**config_dict))
            with pytest.raises(ScanTimeoutError):
                client.poll_until_done(1, poll_interval=5, timeout=6)


class TestExportScan:
    def test_export_nessus(self, config_dict, base_url, tmp_path):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.POST, f"{base_url}/scans/1/export",
                     json={"file": 100}, status=200)
            rsps.add(responses.GET, f"{base_url}/scans/1/export/100/status",
                     json={"status": "ready"})
            output_path = str(tmp_path / "report.nessus")
            rsps.add(
                responses.GET,
                f"{base_url}/scans/1/export/100/download",
                body=b"<NessusClientData>...</NessusClientData>",
                status=200,
            )
            client = NessusClient(Config(**config_dict))
            result = client.export_scan(1, "nessus", output_path)
            assert result == output_path
            assert os.path.exists(output_path)

    def test_export_db_with_password(self, config_dict, base_url, tmp_path):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.POST, f"{base_url}/scans/1/export",
                     json={"file": 101}, status=200)
            rsps.add(responses.GET, f"{base_url}/scans/1/export/101/status",
                     json={"status": "ready"})
            output_path = str(tmp_path / "report.db")
            rsps.add(
                responses.GET,
                f"{base_url}/scans/1/export/101/download",
                body=b"\x00\x01\x02\x03",
                status=200,
            )
            client = NessusClient(Config(**config_dict))
            result = client.export_scan(1, "db", output_path, db_password="dbpass")
            assert result == output_path

    def test_export_not_ready(self, config_dict, base_url, tmp_path, monkeypatch):
        """Export polling times out after 300s of 'loading' status."""
        monkeypatch.setattr("time.sleep", lambda s: None)  # speed through polling
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.POST, f"{base_url}/scans/1/export",
                     json={"file": 102}, status=200)
            for _ in range(155):  # 300s / 2s per poll, plus margin
                rsps.add(responses.GET, f"{base_url}/scans/1/export/102/status",
                         json={"status": "loading"})
            output_path = str(tmp_path / "report.nessus")
            client = NessusClient(Config(**config_dict))
            with pytest.raises(CredFlowError, match="not ready"):
                client.export_scan(1, "nessus", output_path)


class TestDeleteScan:
    def test_trash_scan(self, config_dict, base_url):
        """Default: move to Trash folder."""
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            # Need folders endpoint for trash ID discovery
            rsps.add(responses.GET, f"{base_url}/folders",
                     json={"folders": [{"type": "trash", "id": 2}]})
            rsps.add(responses.PUT, f"{base_url}/scans/1/folder",
                     json={}, status=200)
            client = NessusClient(Config(**config_dict))
            client.delete_scan(1)  # default: trash

    def test_trash_scan_fallback(self, config_dict, base_url):
        """Trash fails → fallback to permanent delete."""
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.GET, f"{base_url}/folders",
                     json={"folders": [{"type": "trash", "id": 2}]})
            rsps.add(responses.PUT, f"{base_url}/scans/1/folder",
                     status=500)
            rsps.add(responses.DELETE, f"{base_url}/scans/1", status=200)
            client = NessusClient(Config(**config_dict))
            client.delete_scan(1)  # should not raise

    def test_trash_folder_not_found(self, config_dict, base_url):
        """No trash folder in response → fallback to ID 2."""
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.GET, f"{base_url}/folders",
                     json={"folders": []})
            rsps.add(responses.PUT, f"{base_url}/scans/1/folder",
                     json={}, status=200)
            client = NessusClient(Config(**config_dict))
            client.delete_scan(1)  # uses fallback ID 2

    def test_permanent_delete(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.DELETE, f"{base_url}/scans/1", status=200)
            client = NessusClient(Config(**config_dict))
            client.delete_scan(1, permanent=True)

    def test_permanent_delete_failure(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.DELETE, f"{base_url}/scans/1", status=500)
            client = NessusClient(Config(**config_dict))
            client.delete_scan(1, permanent=True)  # should not raise, just log warning


# ── credentials builder ──────────────────────────────────────────

class TestBuildCredentials:
    def test_linux(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            creds = client._build_credentials(
                Target(ip="1.2.3.4", username="root", password="pw", os_type="linux")
            )
            assert "SSH" in creds["add"]["Host"]
            assert creds["add"]["Host"]["SSH"][0]["username"] == "root"

    def test_windows(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            creds = client._build_credentials(
                Target(ip="1.2.3.4", username="admin", password="pw", os_type="windows")
            )
            assert "Windows" in creds["add"]["Host"]
            assert creds["add"]["Host"]["Windows"][0]["auth_method"] == "Password"

    def test_unsupported_os(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            with pytest.raises(CredFlowError, match="Unsupported os_type"):
                client._build_credentials(
                    Target(ip="1.2.3.4", username="u", password="pw", os_type="mac")
                )


# ── close ────────────────────────────────────────────────────────

class TestClose:
    def test_closes_session(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            client.close()
            # after close, the session should be closed


# ── run_scan_job (orchestration) ─────────────────────────────────

class TestRunScanJob:
    def test_full_lifecycle(self, config_dict, base_url, target, state_db_path):
        config = Config(**config_dict)
        state = StateManager(state_db_path)
        state.load_targets([target])

        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(config)

            # create_scan
            rsps.add(responses.POST, f"{base_url}/scans",
                     json={"scan": {"id": 99}}, status=200)
            # launch
            rsps.add(responses.POST, f"{base_url}/scans/99/launch",
                     json={}, status=200)
            # poll — completed
            rsps.add(responses.GET, f"{base_url}/scans/99",
                     json={"info": {"status": "completed"}})
            # export nessus
            rsps.add(responses.POST, f"{base_url}/scans/99/export",
                     json={"file": 200}, status=200)
            rsps.add(responses.GET, f"{base_url}/scans/99/export/200/status",
                     json={"status": "ready"})
            rsps.add(responses.GET, f"{base_url}/scans/99/export/200/download",
                     body=b"<xml>data</xml>", status=200)
            # export db
            rsps.add(responses.POST, f"{base_url}/scans/99/export",
                     json={"file": 201}, status=200)
            rsps.add(responses.GET, f"{base_url}/scans/99/export/201/status",
                     json={"status": "ready"})
            rsps.add(responses.GET, f"{base_url}/scans/99/export/201/download",
                     body=b"\x00\x01", status=200)
            # trash (default)
            rsps.add(responses.GET, f"{base_url}/folders",
                     json={"folders": [{"type": "trash", "id": 2}]})
            rsps.add(responses.PUT, f"{base_url}/scans/99/folder",
                     json={}, status=200)

            run_scan_job(target, client, config, state, "uuid-1")

            progress = state.get_progress()
            assert progress.get("completed") == 1

    def test_non_completed_terminal_status(self, config_dict, base_url, target, state_db_path):
        config = Config(**config_dict)
        state = StateManager(state_db_path, max_retries=0)  # no retry → terminal failed
        state.load_targets([target])

        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(config)

            rsps.add(responses.POST, f"{base_url}/scans",
                     json={"scan": {"id": 99}}, status=200)
            rsps.add(responses.POST, f"{base_url}/scans/99/launch",
                     json={}, status=200)
            rsps.add(responses.GET, f"{base_url}/scans/99",
                     json={"info": {"status": "aborted"}})
            # trash in finally
            rsps.add(responses.GET, f"{base_url}/folders",
                     json={"folders": [{"type": "trash", "id": 2}]})
            rsps.add(responses.PUT, f"{base_url}/scans/99/folder",
                     json={}, status=200)

            with pytest.raises(CredFlowError, match="aborted"):
                run_scan_job(target, client, config, state, "uuid-1")

            progress = state.get_progress()
            assert progress.get("failed") == 1

    def test_cleanup_on_exception(self, config_dict, base_url, target, state_db_path):
        """Ensure delete_scan is called even when export fails."""
        config = Config(**config_dict)
        state = StateManager(state_db_path)
        state.load_targets([target])

        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(config)

            rsps.add(responses.POST, f"{base_url}/scans",
                     json={"scan": {"id": 99}}, status=200)
            rsps.add(responses.POST, f"{base_url}/scans/99/launch",
                     json={}, status=200)
            rsps.add(responses.GET, f"{base_url}/scans/99",
                     json={"info": {"status": "completed"}})
            # export fails
            rsps.add(responses.POST, f"{base_url}/scans/99/export",
                     json={}, status=500)
            # trash in finally
            rsps.add(responses.GET, f"{base_url}/folders",
                     json={"folders": [{"type": "trash", "id": 2}]})
            rsps.add(responses.PUT, f"{base_url}/scans/99/folder",
                     json={}, status=200)

            with pytest.raises(CredFlowError):
                run_scan_job(target, client, config, state, "uuid-1")

            # verify trash was called
            assert any("PUT" in str(c.request.method) for c in rsps.calls if c.request)
