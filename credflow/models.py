"""Domain model dataclasses for CredFlow."""

from dataclasses import dataclass


@dataclass
class Target:
    """A host to scan, defined by IP + credential + OS type."""
    ip: str
    username: str
    password: str  # repr is masked
    os_type: str  # "linux" | "windows"

    def __repr__(self) -> str:
        return f"Target(ip={self.ip!r}, username={self.username!r}, password='***', os_type={self.os_type!r})"

