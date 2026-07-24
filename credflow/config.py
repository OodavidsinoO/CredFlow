"""Configuration loader — merges .env, environment variables, and CLI args."""

import os
from dataclasses import dataclass, field

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
    template_name: str = "basic"
    template_uuid: str = ""

    # Input / output
    targets_csv: str = "targets.csv"
    reports_dir: str = "./reports"
    db_password: str = ""

    # Execution
    max_workers: int = 1
    max_retries: int = 1
    poll_interval: int = 30      # seconds between status checks
    poll_timeout: int = 3600     # max seconds to wait for scan completion

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
        cfg.template_name = os.getenv("SCAN_TEMPLATE_NAME", "basic")
        cfg.template_uuid = os.getenv("SCAN_TEMPLATE_UUID", "")
        cfg.db_password = os.getenv("DB_PASSWORD", "")
        cfg.max_workers = int(os.getenv("CREDFLOW_MAX_WORKERS", "1"))
        cfg.max_retries = int(os.getenv("CREDFLOW_MAX_RETRIES", "1"))
        cfg.poll_interval = int(os.getenv("CREDFLOW_POLL_INTERVAL", "30"))
        cfg.poll_timeout = int(os.getenv("CREDFLOW_POLL_TIMEOUT", "3600"))
        cfg.reports_dir = os.getenv("CREDFLOW_REPORTS_DIR", "./reports")

        if cli_overrides:
            cfg._apply_overrides(cli_overrides)

        return cfg

    def _apply_overrides(self, overrides: dict) -> None:
        """Apply CLI-provided overrides (only if explicitly set)."""
        bool_keys = {"nessus_ssl_verify", "resume"}
        int_keys = {"max_workers", "max_retries", "poll_interval", "poll_timeout"}
        str_keys = {
            "nessus_url", "nessus_username", "nessus_password",
            "nessus_api_token", "nessus_access_key", "nessus_secret_key",
            "template_name", "template_uuid", "targets_csv",
            "reports_dir", "db_password", "state_db",
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
            errors.append("NESSUS_URL is required")
        if not self.nessus_username:
            errors.append("NESSUS_USERNAME is required")
        if not self.nessus_password:
            errors.append("NESSUS_PASSWORD is required")
        if self.max_workers < 1:
            errors.append("max_workers must be >= 1")
        if self.poll_interval < 5:
            errors.append("poll_interval must be >= 5 seconds")
        return errors
