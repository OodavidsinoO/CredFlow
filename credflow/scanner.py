"""Nessus scanner engine — core scan lifecycle management.

Uses session-based auth (username/password) with X-API-Token extracted
from the Nessus Web UI's JavaScript to unlock full REST API access
on Nessus Professional (which normally blocks scan creation via API).
"""

import logging
import os
import re
import secrets
import string
import time
from datetime import UTC, datetime

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
        self._trash_folder_id: int | None = None
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
        # API v2: required since Nessus 19.x for plugins.families data and
        # for plugins payloads in POST /scans to take effect
        self._session.headers["X-API-Version"] = "2"
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

            # Fallback: broader pattern, then filter for UUID-like strings
            logger.warning("Primary token regex failed; trying fallback pattern")
            candidates = re.findall(
                r'value:function\(\)\{return"([^"]+)"',
                resp.text,
            )
            uuid_re = re.compile(
                r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
            )
            for candidate in candidates:
                if uuid_re.match(candidate):
                    logger.info("Auto-discovered X-API-Token via fallback pattern")
                    return candidate
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

    def _put(self, path: str, **kwargs) -> dict:
        resp = self._session.put(f"{self._url}{path}", **kwargs)
        if resp.status_code >= 400:
            raise CredFlowError(
                f"API error {resp.status_code} on PUT {path}: {resp.text[:300]}"
            )
        # Some PUT endpoints return empty 200 (no JSON body)
        if not resp.text or not resp.text.strip():
            return {}
        return resp.json()

    # ── template ────────────────────────────────────────────────

    def get_template_detail(self, uuid: str) -> dict:
        """Fetch full template/policy detail including plugins.families.

        Returns the complete template configuration, which includes
        ``plugins.families`` — a dict keyed by family name, each containing
        ``id``, ``count``, ``status`` (“enabled” / “disabled”), ``locked``.
        """
        return self._get(f"/editor/scan/templates/{uuid}")

    def resolve_disabled_families(self, disabled_names: list[str], template_uuid: str) -> dict:
        """Build a ``plugins`` payload for scan creation from a list of family names.

        Fetches the template detail to map family names to their IDs, then
        returns a dict suitable for the ``plugins`` key in POST /scans.
        """
        if not disabled_names:
            return {}

        detail = self.get_template_detail(template_uuid)
        families = (detail.get("plugins") or {}).get("families", {})

        name_to_id: dict[str, int] = {}
        for family_name, fam_info in families.items():
            name_to_id[family_name.lower()] = fam_info.get("id")

        plugins: dict[str, dict] = {}
        for name in disabled_names:
            fam_id = name_to_id.get(name.lower())
            if fam_id is not None:
                plugins[name] = {"id": fam_id, "status": "disabled"}
            else:
                # Try substring match
                candidates = [
                    (fn, fi.get("id"))
                    for fn, fi in families.items()
                    if name.lower() in fn.lower()
                ]
                if candidates:
                    fn, fam_id = candidates[0]
                    logger.info(
                        "Resolved '%s' → family '%s' (id=%s)", name, fn, fam_id
                    )
                    plugins[fn] = {"id": fam_id, "status": "disabled"}
                else:
                    logger.warning(
                        "Plugin family '%s' not found in template. Available: %s",
                        name,
                        ", ".join(sorted(families.keys()))[:200],
                    )

        return plugins if plugins else {}

    def find_scan_by_name(self, name: str) -> dict | None:
        """Find an existing scan by name. Returns scan info dict or None."""
        data = self._get("/scans")
        scans = data.get("scans") or []
        name_lower = name.lower()
        for scan in scans:
            if (scan.get("name") or "").lower() == name_lower:
                return scan
        # Substring fallback
        for scan in scans:
            if name_lower in (scan.get("name") or "").lower():
                return scan
        return None

    def get_scan_config(self, scan_id: int) -> dict:
        """Fetch the full scan configuration from the editor endpoint.

        Returns the scan's policy details including ``uuid`` (template UUID),
        ``plugins.families``, ``settings``, and ``credentials``.
        """
        return self._get(f"/editor/scan/{scan_id}")

    def extract_plugins_from_config(self, scan_config: dict) -> dict:
        """Extract the ``plugins`` payload from a scan/policy configuration.

        Returns a dict suitable for the ``plugins`` key in POST /scans,
        or an empty dict if no plugin families are configured.
        """
        plugins = scan_config.get("plugins", {})
        if not isinstance(plugins, dict):
            return {}
        families = plugins.get("families", {})
        if not families:
            return {}
        # Build the payload: only include families that differ from default
        result_families: dict[str, dict] = {}
        for name, fam in families.items():
            if not isinstance(fam, dict):
                continue
            status = fam.get("status", "enabled")
            fam_id = fam.get("id")
            if status != "enabled" and fam_id is not None:
                result_families[name] = {"id": fam_id, "status": status}
        return result_families if result_families else {}

    def extract_settings_from_config(self, scan_config: dict) -> dict:
        """Extract scalar settings from a scan/policy configuration.

        The editor response nests settings as UI form definitions
        (``settings.<section>.groups[].inputs[]``) where the current value
        lives in the ``default`` field. This flattens all scalar inputs into
        a flat dict suitable for the ``settings`` key in POST /scans.

        Per-scan fields (name, text_targets, file_targets, enabled, launch,
        description) and sensitive fields (SMTP credentials, notification
        recipients, custom HTTP headers) are excluded — the caller sets those.
        """
        scalar_types = {
            "entry", "small-entry", "checkbox", "radio",
            "ui_radio", "dropdown", "small-textarea", "textarea", "file",
        }
        excluded = {
            "name", "text_targets", "file_targets", "enabled", "launch", "description",
            # Sensitive / notification settings — never inherit secrets
            "smtp_from", "smtp_to", "smtp_password", "smtp_domain",
            "email_lists", "email_recipients", "email_cc", "email_bcc",
            "custom_http_header", "custom_http_header_name", "custom_http_header_value",
        }

        settings = scan_config.get("settings", {})
        if not isinstance(settings, dict):
            return {}

        flat: dict[str, object] = {}

        def _walk(node) -> None:
            if isinstance(node, dict):
                if (
                    "id" in node
                    and "type" in node
                    and node.get("type") in scalar_types
                    and node["id"] not in excluded
                ):
                    value = node.get("default")
                    if value is not None:
                        flat[node["id"]] = value
                for child in node.values():
                    _walk(child)
            elif isinstance(node, list):
                for child in node:
                    _walk(child)

        _walk(settings)
        return flat

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

    def create_scan(
        self,
        target: Target,
        template_uuid: str,
        plugins: dict | None = None,
        settings: dict | None = None,
        scan_name_prefix: str = "CredFlow",
    ) -> int:
        """Create a temporary Nessus scan with single-host credentials.

        Args:
            target: The scan target.
            template_uuid: Nessus template UUID.
            plugins: Optional ``plugins`` payload (e.g. ``{"Denial of Service": {"id": 44, "status": "disabled"}}``)
                     to control which plugin families are enabled/disabled.
            settings: Optional flat settings dict (e.g. ``{"max_checks_per_host": "25"}``)
                      inherited from a source scan.
            scan_name_prefix: Prefix for the scan name; ``{prefix}-{ip}``.
        """
        credentials = self._build_credentials(target)
        scan_name = f"{scan_name_prefix}-{target.ip}"

        logger.info("Creating scan '%s' for %s (%s)", scan_name, target.ip, target.os_type)

        scan_settings: dict = {
            "name": scan_name,
            "text_targets": target.ip,
            "enabled": False,
        }
        if settings:
            scan_settings.update(settings)
        body: dict = {
            "uuid": template_uuid,
            "settings": scan_settings,
            "credentials": credentials,
        }
        if plugins:
            body["plugins"] = plugins
            family_names = list(plugins.keys())
            logger.info("Plugin families configured: %s", ", ".join(family_names) or "none")

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
            if status in ("completed", "aborted", "canceled", "imported", "paused"):
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

        # Download with retry for transient errors
        max_retries = 2
        last_error = None
        for attempt in range(max_retries + 1):
            try:
                resp = self._session.get(
                    f"{self._url}/scans/{scan_id}/export/{file_id}/download",
                    stream=True,
                )
                resp.raise_for_status()
                with open(output_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        f.write(chunk)
                break
            except (requests.ConnectionError, requests.Timeout) as e:
                last_error = e
                if attempt < max_retries:
                    logger.warning(
                        "Export download attempt %d/%d failed: %s. Retrying in 1s...",
                        attempt + 1, max_retries + 1, e,
                    )
                    time.sleep(1)
                else:
                    raise CredFlowError(
                        f"Export download failed after {max_retries + 1} attempts: {e}"
                    ) from e

        if last_error:
            logger.info("Export download succeeded on retry")

        logger.info("Export complete: %s", output_path)
        return output_path

    def _get_trash_folder_id(self) -> int:
        """Discover the Trash folder ID from the Nessus folders endpoint.

        Cached after first call — the trash folder ID is static per Nessus instance.
        """
        if self._trash_folder_id is not None:
            return self._trash_folder_id

        data = self._get("/folders")
        for folder in data.get("folders", []):
            if folder.get("type") == "trash":
                self._trash_folder_id = folder["id"]
                logger.debug("Trash folder ID: %d", self._trash_folder_id)
                return self._trash_folder_id

        # Fallback: Nessus Pro always uses ID 2 for Trash
        logger.warning("Trash folder not found via API — falling back to ID 2")
        self._trash_folder_id = 2
        return 2

    def trash_scan(self, scan_id: int) -> None:
        """Move a scan to the Trash folder (best-effort, logs but doesn't raise)."""
        try:
            trash_id = self._get_trash_folder_id()
            logger.info("Moving scan %s to Trash (folder %d)", scan_id, trash_id)
            self._put(f"/scans/{scan_id}/folder", json={"folder_id": trash_id})
            logger.info("Scan %s moved to Trash", scan_id)
        except Exception as e:
            logger.warning("Failed to trash scan %s: %s", scan_id, e)
            # Fall back to permanent delete so scans don't accumulate
            try:
                self._delete(f"/scans/{scan_id}")
                logger.info("Scan %s permanently deleted (trash fallback)", scan_id)
            except Exception:
                logger.warning("Failed to delete scan %s after trash failure", scan_id)

    def delete_scan(self, scan_id: int, permanent: bool = False) -> None:
        """Remove a scan. Default: move to Trash. If permanent=True: delete irreversibly."""
        if permanent:
            try:
                logger.info("Permanently deleting scan %s", scan_id)
                self._delete(f"/scans/{scan_id}")
                logger.info("Scan %s permanently deleted", scan_id)
            except Exception as e:
                logger.warning("Failed to permanently delete scan %s: %s", scan_id, e)
        else:
            self.trash_scan(scan_id)

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._session.close()
        logger.debug("NessusClient session closed")

    # ── credentials builder ─────────────────────────────────────

    # Map user-friendly CSV values to Nessus API values
    _ESCALATION_MAP: dict[str, str] = {
        "sudo": "sudo",
        "su": "su",
        "su+sudo": "su+sudo",
        "dzdo": "dzdo",
        "pbrun": "pbrun",
        "cisco_enable": "Cisco 'enable'",
        "k5login": ".k5login",
        "checkpoint_gaia": "Checkpoint Gaia 'expert'",
    }

    # Elevation types that only need password (no escalation_account)
    _ESCALATION_PASSWORD_ONLY: set[str] = {"cisco_enable", "checkpoint_gaia"}

    def _build_credentials(self, target: Target) -> dict:
        """Build the credentials JSON structure based on OS type."""
        if not target.password or not target.password.strip():
            logger.warning("Empty password for target %s", target.ip)

        if target.os_type.lower() == "linux":
            ssh_cred: dict[str, object] = {
                "auth_method": "password",
                "username": target.username,
                "password": target.password,
            }
            self._apply_escalation(ssh_cred, target)
            return {
                "add": {
                    "Host": {
                        "SSH": [ssh_cred]
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

    def _apply_escalation(self, ssh_cred: dict, target: Target) -> None:
        """Mutate ssh_cred dict with privilege escalation fields if configured."""
        if not target.escalation_method:
            return

        method = target.escalation_method.lower()
        api_value = self._ESCALATION_MAP.get(method)
        if api_value is None:
            valid = ", ".join(sorted(self._ESCALATION_MAP.keys()))
            raise CredFlowError(
                f"Invalid escalation_method '{target.escalation_method}' for {target.ip}. "
                f"Valid values: {valid}"
            )

        ssh_cred["elevate_privileges_with"] = api_value

        if method in self._ESCALATION_PASSWORD_ONLY:
            if target.escalation_password:
                ssh_cred["escalation_password"] = target.escalation_password
        else:
            ssh_cred["escalation_account"] = target.escalation_user or "root"
            if target.escalation_password:
                ssh_cred["escalation_password"] = target.escalation_password

        if method == "su+sudo" and target.escalation_user:
            ssh_cred["su_user"] = target.escalation_user


# ── helpers ─────────────────────────────────────────────────────

def _generate_password(length: int = 16) -> str:
    """Generate a random password for DB export."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _timestamp() -> str:
    """Return ISO-like timestamp safe for filenames."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


# ── orchestration ───────────────────────────────────────────────

def run_scan_job(
    target: Target,
    client: NessusClient,
    config: Config,
    state: StateManager,
    template_uuid: str,
    plugins: dict | None = None,
    settings: dict | None = None,
    scan_name_prefix: str = "CredFlow",
) -> None:
    """Execute the full scan lifecycle for a single target."""
    scan_id = None
    try:
        scan_id = client.create_scan(
            target, template_uuid, plugins=plugins, settings=settings,
            scan_name_prefix=scan_name_prefix,
        )
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

        client.delete_scan(scan_id, permanent=config.permanent_delete)
        scan_id = None

        try:
            state.mark_completed(target.ip, report_nessus, report_db)
        except Exception as e:
            logger.warning(
                "Scan succeeded but mark_completed failed for %s: %s. "
                "Reports saved at %s and %s but not recorded in state.",
                target.ip, e, report_nessus, report_db,
            )

        logger.info("✓ %s completed — reports saved", target.ip)

    except Exception as e:
        logger.error("✗ %s failed: %s", target.ip, e)
        will_retry = state.mark_failed(target.ip, str(e))
        if will_retry:
            logger.info("  %s will be retried", target.ip)
        raise

    finally:
        if scan_id is not None:
            client.delete_scan(scan_id, permanent=config.permanent_delete)
