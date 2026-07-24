"""Unit tests for credflow.scanner helpers — not requiring live Nessus."""

import re
import string
from unittest.mock import patch

import pytest

from credflow.scanner import (
    CredFlowError,
    _generate_password,
    _timestamp,
)


class TestGeneratePassword:
    def test_default_length(self):
        pw = _generate_password()
        assert len(pw) == 16

    def test_custom_length(self):
        pw = _generate_password(32)
        assert len(pw) == 32

    def test_only_alphanumeric(self):
        for _ in range(100):
            pw = _generate_password()
            assert all(c in string.ascii_letters + string.digits for c in pw)

    def test_randomness(self):
        passwords = {_generate_password() for _ in range(20)}
        assert len(passwords) > 1


class TestTimestamp:
    def test_format(self):
        ts = _timestamp()
        assert re.match(r"^\d{8}T\d{6}Z$", ts)

    def test_unique(self):
        import time
        ts1 = _timestamp()
        time.sleep(0.1)
        # Even at second granularity, both should be valid format.
        ts2 = _timestamp()
        assert re.match(r"^\d{8}T\d{6}Z$", ts1)
        assert re.match(r"^\d{8}T\d{6}Z$", ts2)


class TestBuildCredentials:
    """Test _build_credentials via NessusClient (mocked auth)."""

    @staticmethod
    def _client():
        """Create a NessusClient with _authenticate mocked out."""
        from credflow.config import Config
        from credflow.scanner import NessusClient

        with patch.object(NessusClient, "_authenticate", return_value=None):
            return NessusClient(Config(
                nessus_url="https://test:8834",
                nessus_username="u",
                nessus_password="p",
            ))

    def test_linux_ssh(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="root", password="secret", os_type="linux")
        creds = client._build_credentials(t)
        assert "SSH" in creds["add"]["Host"]
        ssh = creds["add"]["Host"]["SSH"][0]
        assert ssh["auth_method"] == "password"
        assert ssh["username"] == "root"
        assert ssh["password"] == "secret"

    def test_windows(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.2", username="Administrator", password="Pass!", os_type="windows")
        creds = client._build_credentials(t)
        win = creds["add"]["Host"]["Windows"][0]
        assert win["auth_method"] == "Password"
        assert win["username"] == "Administrator"
        assert win["password"] == "Pass!"

    def test_unknown_os_type_raises(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.3", username="u", password="p", os_type="macos")
        with pytest.raises(CredFlowError, match="Unsupported os_type"):
            client._build_credentials(t)

    def test_linux_case_insensitive(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="root", password="s", os_type="LINUX")
        creds = client._build_credentials(t)
        assert "SSH" in creds["add"]["Host"]

    def test_windows_case_insensitive(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.2", username="Admin", password="p", os_type="WINDOWS")
        creds = client._build_credentials(t)
        assert "Windows" in creds["add"]["Host"]

    def test_empty_password_warning(self, caplog):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="root", password="", os_type="linux")
        client._build_credentials(t)
        assert "Empty password" in caplog.text

    # ── escalation ──────────────────────────────────────────

    def test_escalation_sudo(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="deploy", password="pw", os_type="linux",
                   escalation_method="sudo", escalation_user="root", escalation_password="sudopw")
        creds = client._build_credentials(t)
        ssh = creds["add"]["Host"]["SSH"][0]
        assert ssh["elevate_privileges_with"] == "sudo"
        assert ssh["escalation_account"] == "root"
        assert ssh["escalation_password"] == "sudopw"
        # base creds still present
        assert ssh["username"] == "deploy"
        assert ssh["password"] == "pw"

    def test_escalation_no_method_means_no_escalation(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="u", password="p", os_type="linux")
        creds = client._build_credentials(t)
        ssh = creds["add"]["Host"]["SSH"][0]
        assert "elevate_privileges_with" not in ssh

    def test_escalation_default_user_root(self):
        """escalation_user defaults to root when not specified."""
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="u", password="p", os_type="linux",
                   escalation_method="su", escalation_password="supw")
        creds = client._build_credentials(t)
        ssh = creds["add"]["Host"]["SSH"][0]
        assert ssh["escalation_account"] == "root"

    def test_escalation_cisco_enable(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="u", password="p", os_type="linux",
                   escalation_method="cisco_enable", escalation_password="enablepw")
        creds = client._build_credentials(t)
        ssh = creds["add"]["Host"]["SSH"][0]
        assert ssh["elevate_privileges_with"] == "Cisco 'enable'"
        assert ssh["escalation_password"] == "enablepw"
        assert "escalation_account" not in ssh  # cisco_enable doesn't need it

    def test_escalation_k5login(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="u", password="p", os_type="linux",
                   escalation_method="k5login", escalation_user="admin")
        creds = client._build_credentials(t)
        ssh = creds["add"]["Host"]["SSH"][0]
        assert ssh["elevate_privileges_with"] == ".k5login"
        assert ssh["escalation_account"] == "admin"
        assert "escalation_password" not in ssh

    def test_escalation_su_sudo(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="u", password="p", os_type="linux",
                   escalation_method="su+sudo", escalation_user="admin", escalation_password="supass")
        creds = client._build_credentials(t)
        ssh = creds["add"]["Host"]["SSH"][0]
        assert ssh["elevate_privileges_with"] == "su+sudo"
        assert ssh["escalation_account"] == "admin"
        assert ssh["su_user"] == "admin"

    def test_escalation_invalid_method_raises(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="u", password="p", os_type="linux",
                   escalation_method="bogus", escalation_password="x")
        with pytest.raises(CredFlowError, match="Invalid escalation_method"):
            client._build_credentials(t)

    def test_escalation_ignored_for_windows(self):
        from credflow.models import Target
        client = self._client()
        t = Target(ip="10.0.0.1", username="Admin", password="p", os_type="windows",
                   escalation_method="sudo", escalation_password="ignored")
        creds = client._build_credentials(t)
        win = creds["add"]["Host"]["Windows"][0]
        assert "elevate_privileges_with" not in win

    def test_escalation_all_methods_valid(self):
        """All 8 valid escalation methods accepted."""
        from credflow.models import Target
        client = self._client()
        for method in ["sudo", "su", "su+sudo", "dzdo", "pbrun",
                        "cisco_enable", "k5login", "checkpoint_gaia"]:
            t = Target(ip="10.0.0.1", username="u", password="p", os_type="linux",
                       escalation_method=method, escalation_user="root",
                       escalation_password="pw")
            creds = client._build_credentials(t)
            ssh = creds["add"]["Host"]["SSH"][0]
            assert "elevate_privileges_with" in ssh, f"Missing for {method}"
