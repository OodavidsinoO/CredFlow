"""Additional scanner integration tests — source scan flow, find_scan_by_name, plugin extraction."""

import pytest
import responses

from credflow.config import Config
from credflow.scanner import NessusClient


@pytest.fixture
def base_url():
    return "https://nessus.example.com:8834"


@pytest.fixture
def config_dict(base_url):
    return {
        "nessus_url": base_url,
        "nessus_username": "admin",
        "nessus_password": "secret",
        "nessus_api_token": "static-token-123",
        "nessus_ssl_verify": False,
        "template_name": "advanced",
        "reports_dir": "/tmp/reports",
        "max_workers": 1,
        "poll_interval": 30,
        "poll_timeout": 3600,
        "db_password": "",
    }


def _full_auth(rsps, base_url):
    rsps.add(responses.POST, f"{base_url}/session", json={"token": "t"}, status=200)


class TestFindScanByName:
    def test_exact_match(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.GET, f"{base_url}/scans",
                     json={"scans": [
                         {"id": 1, "name": "Other Scan"},
                         {"id": 2, "name": "Ubuntu-AdvancedScan"},
                     ]})
            client = NessusClient(Config(**config_dict))
            result = client.find_scan_by_name("Ubuntu-AdvancedScan")
            assert result is not None
            assert result["id"] == 2

    def test_substring_fallback(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.GET, f"{base_url}/scans",
                     json={"scans": [
                         {"name": "My-Ubuntu-AdvancedScan-v2"},
                     ]})
            client = NessusClient(Config(**config_dict))
            result = client.find_scan_by_name("Ubuntu-Advanced")
            assert result is not None
            assert "Ubuntu" in result["name"]

    def test_not_found(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.GET, f"{base_url}/scans",
                     json={"scans": [{"id": 1, "name": "Other"}]})
            client = NessusClient(Config(**config_dict))
            assert client.find_scan_by_name("nonexistent") is None

    def test_empty_scans(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            rsps.add(responses.GET, f"{base_url}/scans", json={})
            client = NessusClient(Config(**config_dict))
            assert client.find_scan_by_name("anything") is None


class TestGetScanConfig:
    def test_returns_config(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            config = {
                "uuid": "template-uuid-1",
                "title": "Ubuntu-AdvancedScan",
                "plugins": {"families": {"DoS": {"id": 44, "status": "disabled"}}},
                "settings": {"name": "MyScan"},
            }
            rsps.add(responses.GET, f"{base_url}/editor/scan/42", json=config)
            client = NessusClient(Config(**config_dict))
            result = client.get_scan_config(42)
            assert result["uuid"] == "template-uuid-1"
            assert result["title"] == "Ubuntu-AdvancedScan"


class TestExtractPluginsFromConfig:
    def test_extracts_disabled_families(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            scan_config = {
                "plugins": {"families": {
                    "DoS": {"id": 44, "status": "disabled"},
                    "Web Crawler": {"id": 100, "status": "enabled"},
                    "Port Scanners": {"id": 20, "status": "disabled"},
                }}
            }
            result = client.extract_plugins_from_config(scan_config)
            # Only non-enabled families should be included
            assert "DoS" in result
            assert result["DoS"]["status"] == "disabled"
            assert "Port Scanners" in result
            assert "Web Crawler" not in result  # enabled → not included

    def test_empty_config(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            assert client.extract_plugins_from_config({}) == {}

    def test_no_families(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            assert client.extract_plugins_from_config({"plugins": {"other": "stuff"}}) == {}


class TestExtractSettingsFromConfig:
    def test_flattens_scalar_inputs(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            scan_config = {
                "settings": {
                    "advanced": {
                        "groups": [{
                            "inputs": [
                                {"id": "max_checks_per_host", "type": "small-entry", "default": "25"},
                                {"id": "safe_checks", "type": "dropdown", "default": "yes"},
                                {"id": "name", "type": "entry", "default": "MyScan"},
                                {"id": "text_targets", "type": "entry", "default": "1.2.3.4"},
                                {"id": "enabled", "type": "checkbox", "default": "yes"},
                            ]
                        }]
                    }
                }
            }
            result = client.extract_settings_from_config(scan_config)
            assert result["max_checks_per_host"] == "25"
            assert result["safe_checks"] == "yes"
            # Per-scan fields excluded
            assert "name" not in result
            assert "text_targets" not in result
            assert "enabled" not in result

    def test_skips_null_defaults(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            scan_config = {
                "settings": {
                    "basic": {
                        "inputs": [
                            {"id": "description", "type": "entry", "default": None},
                            {"id": "max_hosts_per_scan", "type": "small-entry", "default": "100"},
                        ]
                    }
                }
            }
            result = client.extract_settings_from_config(scan_config)
            assert "description" not in result
            assert result["max_hosts_per_scan"] == "100"

    def test_excludes_sensitive_settings(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            client = NessusClient(Config(**config_dict))
            scan_config = {
                "settings": {
                    "report": {
                        "groups": [{
                            "inputs": [
                                {"id": "smtp_from", "type": "entry", "default": "admin@corp.com"},
                                {"id": "smtp_password", "type": "password", "default": "hunter2"},
                                {"id": "smtp_to", "type": "entry", "default": "sec@corp.com"},
                                {"id": "custom_http_header_value", "type": "entry", "default": "Bearer abc123"},
                                {"id": "max_checks_per_host", "type": "small-entry", "default": "25"},
                            ]
                        }]
                    }
                }
            }
            result = client.extract_settings_from_config(scan_config)
            assert "smtp_from" not in result
            assert "smtp_password" not in result
            assert "smtp_to" not in result
            assert "custom_http_header_value" not in result
            assert result["max_checks_per_host"] == "25"


class TestFindScanByNameSourceScan:
    """Test the full source scan discovery flow used in run_batch."""

    def test_source_scan_discovery(self, config_dict, base_url):
        with responses.RequestsMock() as rsps:
            _full_auth(rsps, base_url)
            # First call: /scans → find source scan
            rsps.add(responses.GET, f"{base_url}/scans",
                     json={"scans": [{"id": 42, "name": "Ubuntu-AdvancedScan"}]})
            # Second call: /editor/scan/42 → get full config
            rsps.add(responses.GET, f"{base_url}/editor/scan/42",
                     json={
                         "uuid": "template-uuid-99",
                         "title": "Ubuntu-AdvancedScan",
                         "plugins": {"families": {"DoS": {"id": 44, "status": "disabled"}}},
                     })
            client = NessusClient(Config(**config_dict))
            source_scan = client.find_scan_by_name("Ubuntu-AdvancedScan")
            assert source_scan is not None
            scan_config = client.get_scan_config(source_scan["id"])
            template_uuid = scan_config.get("uuid")
            assert template_uuid == "template-uuid-99"
            plugins = client.extract_plugins_from_config(scan_config)
            assert "DoS" in plugins
