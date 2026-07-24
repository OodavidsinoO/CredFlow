"""Domain model dataclasses for CredFlow."""

from dataclasses import dataclass, field


@dataclass
class Target:
    """A host to scan, defined by IP + credential + OS type."""
    ip: str
    username: str
    password: str  # repr is masked
    os_type: str  # "linux" | "windows"

    def __repr__(self) -> str:
        return f"Target(ip={self.ip!r}, username={self.username!r}, password='***', os_type={self.os_type!r})"


@dataclass
class ScanJob:
    """Full lifecycle state of a single Target scan."""
    target: Target
    scan_id: int | None = None
    status: str = "pending"  # pending|running|completed|failed
    error: str | None = None
    retries: int = 0
    started_at: str | None = None
    completed_at: str | None = None
    report_nessus: str | None = None
    report_db: str | None = None
