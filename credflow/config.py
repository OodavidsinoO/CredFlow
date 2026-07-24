"""Configuration loader — merges .env, environment variables, and CLI args."""

import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


def _env_int(key: str, default: int) -> int:
    """Read an integer environment variable, logging a warning on parse failure."""
    raw = os.getenv(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning(
            "Invalid value for %s=%r, expected integer; using default %d",
            key, raw, default,
        )
        return default


try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


@dataclass
class Config:
    """Unified configuration for a CredFlow run."""

    # Nessus connection
    nessus_url: str = ""
    nessus_username: str = ""
    nessus_password: str = ""
    nessus_api_token: str = ""    # X-API-Token from nessus6.js (auto-discovered if empty)
    nessus_access_key: str = ""     # fallback API key auth
    nessus_secret_key: str = ""     # fallback API key auth
    nessus_ssl_verify: bool = False

    # Scan template
    template_name: str = "advanced"
    template_uuid: str = ""

    # Plugin family control
    disabled_plugin_families: str = ""   # comma-separated names, e.g. "Denial of Service,Web Crawler"
    source_scan_name: str = ""          # clone plugin settings from this existing scan

    # Scan naming
    scan_name_prefix: str = ""           # prefix for created scans; defaults to source_scan_name or "CredFlow"

    # Input / output
    targets_csv: str = "targets.csv"
    reports_dir: str = "./reports"
    db_password: str = ""

    # Execution
    max_workers: int = 1
    max_retries: int = 1
    poll_interval: int = 30      # seconds between status checks
    poll_timeout: int = 3600     # max seconds to wait for scan completion
    batch_timeout: int = 0       # max wall-clock seconds for entire batch (0 = no timeout)
    permanent_delete: bool = False  # permanently delete scans instead of moving to Trash

    # Resume
    resume: bool = True
    state_db: str = "credflow_state.db"

    # Overrides from CLI
    _cli_overrides: dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_env(cls, cli_overrides: dict | None = None) -> "Config":
        """Build Config from environment variables, then apply CLI overrides."""
        cfg = cls()
        cfg.nessus_url = os.getenv("NESSUS_URL", "")
        cfg.nessus_username = os.getenv("NESSUS_USERNAME", "")
        cfg.nessus_password = os.getenv("NESSUS_PASSWORD", "")
        cfg.nessus_api_token = os.getenv("NESSUS_API_TOKEN", "")
        cfg.nessus_access_key = os.getenv("NESSUS_ACCESS_KEY", "")
        cfg.nessus_secret_key = os.getenv("NESSUS_SECRET_KEY", "")
        cfg.nessus_ssl_verify = os.getenv("NESSUS_SSL_VERIFY", "false").lower() == "true"
        cfg.template_name = os.getenv("SCAN_TEMPLATE_NAME", "advanced")
        cfg.template_uuid = os.getenv("SCAN_TEMPLATE_UUID", "")
        cfg.disabled_plugin_families = os.getenv("DISABLED_PLUGIN_FAMILIES", "")
        cfg.source_scan_name = os.getenv("SOURCE_SCAN_NAME", "")
        cfg.scan_name_prefix = os.getenv("SCAN_NAME_PREFIX", "")
        cfg.db_password = os.getenv("DB_PASSWORD", "")
        cfg.max_workers = _env_int("CREDFLOW_MAX_WORKERS", 1)
        cfg.max_retries = _env_int("CREDFLOW_MAX_RETRIES", 1)
        cfg.poll_interval = _env_int("CREDFLOW_POLL_INTERVAL", 30)
        cfg.poll_timeout = _env_int("CREDFLOW_POLL_TIMEOUT", 3600)
        cfg.batch_timeout = _env_int("CREDFLOW_BATCH_TIMEOUT", 0)
        cfg.permanent_delete = os.getenv("CREDFLOW_PERMANENT_DELETE", "").lower() == "true"
        cfg.resume = os.getenv("CREDFLOW_RESUME", "true").lower() == "true"
        cfg.reports_dir = os.getenv("CREDFLOW_REPORTS_DIR", "./reports")

        if cli_overrides:
            cfg._apply_overrides(cli_overrides)

        return cfg

    def _apply_overrides(self, overrides: dict) -> None:
        """Apply CLI-provided overrides (only if explicitly set)."""
        bool_keys = {"nessus_ssl_verify", "resume", "permanent_delete"}
        int_keys = {"max_workers", "max_retries", "poll_interval", "poll_timeout", "batch_timeout"}
        str_keys = {
            "nessus_url", "nessus_username", "nessus_password",
            "nessus_api_token", "nessus_access_key", "nessus_secret_key",
            "template_name", "template_uuid", "targets_csv",
            "reports_dir", "db_password", "state_db",
            "disabled_plugin_families", "source_scan_name", "scan_name_prefix",
        }

        for key, value in overrides.items():
            if value is None:
                continue
            if key in bool_keys:
                setattr(self, key, bool(value))
            elif key in int_keys:
                setattr(self, key, int(value))
            elif key in str_keys:
                setattr(self, key, str(value))
            else:
                setattr(self, key, value)

    def validate(self) -> list[str]:
        """Return list of missing required config items."""
        errors = []
        if not self.nessus_url:
            errors.append("Missing required: NESSUS_URL")
        if not self.nessus_username:
            errors.append("Missing required: NESSUS_USERNAME")
        if not self.nessus_password:
            errors.append("Missing required: NESSUS_PASSWORD")
        if self.max_workers < 1:
            errors.append("max_workers must be >= 1")
        if self.poll_interval < 5:
            errors.append("poll_interval must be >= 5 seconds")
        return errors
