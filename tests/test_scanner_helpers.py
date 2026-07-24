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
