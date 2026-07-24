"""Nessus scanner engine — core scan lifecycle management.

Uses session-based auth (username/password) with X-API-Token extracted
from the Nessus Web UI's JavaScript to unlock full REST API access
on Nessus Professional (which normally blocks scan creation via API).
"""

import json
import logging
import os
import re
import secrets
import string
import time
from datetime import datetime, timezone

import requests

from credflow.config import Config
from credflow.models import Target
from credflow.state import StateManager

logger = logging.getLogger(__name__)


class CredFlowError(Exception):
    """Base exception for CredFlow operational errors."""


class TemplateNotFoundError(CredFlowError):
    """Could not find the requested scan template."""


class ScanTimeoutError(CredFlowError):
    """Scan did not complete within the configured timeout."""


class NessusClient:
    """Wraps Nessus REST API for scan lifecycle operations.

    Uses session-based auth (X-Cookie) + X-API-Token (extracted from
    nessus6.js) to unlock the full REST API on Nessus Professional.
    """

    def __init__(self, config: Config):
        self._config = config
        self._url = config.nessus_url.rstrip("/")
        self._verify = config.nessus_ssl_verify
        self._session = requests.Session()
        self._session.verify = self._verify
        if not self._verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self._authenticate()

    # ── authentication ──────────────────────────────────────────

    def _authenticate(self) -> None:
        """Authenticate using username/password, then discover X-API-Token."""
        logger.info("Authenticating to Nessus at %s", self._url)

        # Step 1: Login with username/password to get session token
        resp = self._session.post(
            f"{self._url}/session",
            json={"username": self._config.nessus_username,
                  "password": self._config.nessus_password},
        )
        if resp.status_code != 200:
            raise CredFlowError(f"Login failed: {resp.status_code} {resp.text}")
        session_token = resp.json().get("token")
        if not session_token:
            raise CredFlowError("Login response missing token")
        self._session.headers["X-Cookie"] = f"token={session_token}"
        logger.info("Session established")

        # Step 2: Get or discover the X-API-Token
        api_token = self._config.nessus_api_token
        if not api_token:
            api_token = self._discover_api_token()
        self._session.headers["X-API-Token"] = api_token

    def _discover_api_token(self) -> str:
        """Extract the X-API-Token from Nessus's nessus6.js file.

        The token is returned by _Utils.getApiToken() and is a static UUID
        embedded in the JavaScript bundle.
        """
        try:
            resp = requests.get(
                f"{self._url}/nessus6.js",
                verify=self._verify,
                timeout=10,
            )
            resp.raise_for_status()
            # Search for: value:function(){return"UUID"}
            match = re.search(
                r'value:function\(\)\{return"([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"',
                resp.text,
            )
            if match:
                token = match.group(1)
                logger.info("Auto-discovered X-API-Token from nessus6.js")
                return token
        except Exception as e:
            logger.warning("Could not auto-discover X-API-Token: %s", e)

        raise CredFlowError(
            "Could not discover X-API-Token. Set NESSUS_API_TOKEN in .env "
            "or ensure /nessus6.js is accessible."
        )

    def check_connection(self) -> dict:
        """Verify connectivity and return server info."""
        status = self._get("/server/status")
        props = self._get("/server/properties")
        status_str = status if isinstance(status, str) else status.get("status", "unknown")
        return {
            "status": status_str,
            "version": props.get("server_version", "unknown"),
            "scanner_uuid": props.get("uuid", "unknown"),
        }

    # ── HTTP helpers ────────────────────────────────────────────

    def _get(self, path: str) -> dict:
        resp = self._session.get(f"{self._url}{path}")
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, **kwargs) -> dict:
        resp = self._session.post(f"{self._url}{path}", **kwargs)
        if resp.status_code >= 400:
            raise CredFlowError(
                f"API error {resp.status_code} on {path}: {resp.text[:300]}"
            )
        return resp.json()

    def _delete(self, path: str) -> None:
        resp = self._session.delete(f"{self._url}{path}")
        if resp.status_code != 200:
            logger.warning("DELETE %s → %s: %s", path, resp.status_code, resp.text[:200])

    # ── template ────────────────────────────────────────────────

    def get_template_uuid(self, name: str) -> str:
        """Discover a scan template UUID by name. Falls back to config override.

        Matching strategy: exact → substring → raise error.
        """
        if self._config.template_uuid:
            logger.info("Using configured template UUID: %s", self._config.template_uuid)
            return self._config.template_uuid

        data = self._get("/editor/scan/templates")
        templates = data.get("templates") or []
        if not templates:
            raise TemplateNotFoundError(
                "No scan templates returned from Nessus. "
                "Set SCAN_TEMPLATE_UUID in .env to override."
            )
        name_lower = name.lower()

        # Pass 1: exact match
        for tmpl in templates:
            tmpl_name = (tmpl.get("name") or tmpl.get("title", "")).lower()
            if tmpl_name == name_lower:
                uuid = tmpl.get("uuid") or tmpl.get("template_uuid", "")
                if uuid:
                    logger.info("Found template '%s' → UUID %s", tmpl.get("name") or tmpl.get("title"), uuid)
                    return uuid

        # Pass 2: substring match
        candidates = []
        for tmpl in templates:
            tmpl_name = (tmpl.get("name") or tmpl.get("title", "")).lower()
            if name_lower in tmpl_name or tmpl_name in name_lower:
                uuid = tmpl.get("uuid") or tmpl.get("template_uuid", "")
                if uuid:
                    candidates.append((tmpl_name, uuid))
        if candidates:
            candidates.sort(key=lambda x: len(x[0]))
            tmpl_name, uuid = candidates[0]
            logger.info("Found template '%s' → UUID %s (substring)", tmpl_name, uuid)
            return uuid

        available = [t.get("name") or t.get("title", "?") for t in templates]
        raise TemplateNotFoundError(
            f"Template '{name}' not found. Available: {', '.join(available[:8])}. "
            f"Set SCAN_TEMPLATE_UUID in .env to override."
        )

    # ── scan lifecycle ──────────────────────────────────────────

    def create_scan(self, target: Target, template_uuid: str) -> int:
        """Create a temporary Nessus scan with single-host credentials."""
        credentials = self._build_credentials(target)
        scan_name = f"CredFlow-{target.ip}"

        logger.info("Creating scan '%s' for %s (%s)", scan_name, target.ip, target.os_type)

        body = {
            "uuid": template_uuid,
            "settings": {
                "name": scan_name,
                "text_targets": target.ip,
                "enabled": False,
            },
            "credentials": credentials,
        }
        result = self._post("/scans", json=body)
        scan = result.get("scan", result)
        scan_id = scan.get("id")
        if not scan_id:
            raise CredFlowError(f"Failed to create scan: no id — {result}")
        logger.info("Scan created — id=%s", scan_id)
        return int(scan_id)

    def launch_scan(self, scan_id: int) -> None:
        """Launch a scan."""
        logger.info("Launching scan %s", scan_id)
        self._post(f"/scans/{scan_id}/launch")
        logger.info("Scan %s launched", scan_id)

    def poll_until_done(
        self, scan_id: int, poll_interval: int = 30, timeout: int = 3600
    ) -> str:
        """Poll scan status until terminal state. Returns final status string."""
        poll_interval = max(poll_interval, 5)  # minimum 5s
        elapsed = 0
        while elapsed < timeout:
            details = self._get(f"/scans/{scan_id}")
            status = details.get("info", {}).get("status", "unknown")
            logger.debug("Scan %s status: %s (elapsed %ss)", scan_id, status, elapsed)
            if status in ("completed", "aborted", "canceled", "imported"):
                return status
            time.sleep(poll_interval)
            elapsed += poll_interval

        raise ScanTimeoutError(f"Scan {scan_id} did not complete within {timeout}s")

    def export_scan(
        self,
        scan_id: int,
        fmt: str,
        output_path: str,
        db_password: str | None = None,
    ) -> str:
        """Export scan report to file. Returns the output path."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        logger.info("Exporting scan %s → %s (format=%s)", scan_id, output_path, fmt)

        # Request export
        export_body = {"format": fmt}
        if fmt == "db" and db_password:
            export_body["password"] = db_password
        export_resp = self._post(f"/scans/{scan_id}/export", json=export_body)
        file_id = export_resp.get("file")
        if not file_id:
            raise CredFlowError(f"Export request failed: {export_resp}")

        # Wait for export to be ready (max 5 minutes)
        export_elapsed = 0
        while export_elapsed < 300:
            status_resp = self._get(f"/scans/{scan_id}/export/{file_id}/status")
            if status_resp.get("status") == "ready":
                break
            time.sleep(2)
            export_elapsed += 2
        else:
            raise CredFlowError(f"Export {file_id} not ready after 300s")

        # Download
        resp = self._session.get(
            f"{self._url}/scans/{scan_id}/export/{file_id}/download",
            stream=True,
        )
        resp.raise_for_status()
        with open(output_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)

        logger.info("Export complete: %s", output_path)
        return output_path

    def delete_scan(self, scan_id: int) -> None:
        """Delete a scan (best-effort — logs but doesn't raise on failure)."""
        try:
            logger.info("Deleting scan %s", scan_id)
            self._delete(f"/scans/{scan_id}")
            logger.info("Scan %s deleted", scan_id)
        except Exception as e:
            logger.warning("Failed to delete scan %s: %s", scan_id, e)

    # ── credentials builder ─────────────────────────────────────

    def _build_credentials(self, target: Target) -> dict:
        """Build the credentials JSON structure based on OS type."""
        if target.os_type.lower() == "linux":
            return {
                "add": {
                    "Host": {
                        "SSH": [
                            {
                                "auth_method": "password",
                                "username": target.username,
                                "password": target.password,
                            }
                        ]
                    }
                }
            }
        elif target.os_type.lower() == "windows":
            return {
                "add": {
                    "Host": {
                        "Windows": [
                            {
                                "domain": "",
                                "username": target.username,
                                "auth_method": "Password",
                                "password": target.password,
                            }
                        ]
                    }
                }
            }
        else:
            raise CredFlowError(
                f"Unsupported os_type '{target.os_type}' for {target.ip}. "
                "Expected 'linux' or 'windows'."
            )


# ── helpers ─────────────────────────────────────────────────────

def _generate_password(length: int = 16) -> str:
    """Generate a random password for DB export."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _timestamp() -> str:
    """Return ISO-like timestamp safe for filenames."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ── orchestration ───────────────────────────────────────────────

def run_scan_job(
    target: Target,
    client: NessusClient,
    config: Config,
    state: StateManager,
    template_uuid: str,
) -> None:
    """Execute the full scan lifecycle for a single target."""
    scan_id = None
    try:
        scan_id = client.create_scan(target, template_uuid)
        client.launch_scan(scan_id)

        final_status = client.poll_until_done(
            scan_id, config.poll_interval, config.poll_timeout
        )
        if final_status != "completed":
            raise CredFlowError(
                f"Scan {scan_id} ended with status '{final_status}' (expected 'completed')"
            )

        ts = _timestamp()
        os.makedirs(config.reports_dir, exist_ok=True)
        report_nessus = os.path.join(config.reports_dir, f"{target.ip}_{ts}.nessus")
        report_db = os.path.join(config.reports_dir, f"{target.ip}_{ts}.db")

        client.export_scan(scan_id, "nessus", report_nessus)

        db_password = config.db_password or _generate_password()
        if not config.db_password:
            logger.info("Auto-generated DB password for %s (length=%d)", target.ip, len(db_password))
        client.export_scan(scan_id, "db", report_db, db_password=db_password)

        client.delete_scan(scan_id)
        scan_id = None

        state.mark_completed(target.ip, report_nessus, report_db)
        logger.info("✓ %s completed — reports saved", target.ip)

    except Exception as e:
        logger.error("✗ %s failed: %s", target.ip, e)
        will_retry = state.mark_failed(target.ip, str(e))
        if will_retry:
            logger.info("  %s will be retried", target.ip)
        raise

    finally:
        if scan_id is not None:
            client.delete_scan(scan_id)
