"""Domain model dataclasses for CredFlow."""

from dataclasses import dataclass


@dataclass
class Target:
    """A host to scan, defined by IP + credential + OS type."""
    ip: str
    username: str
    password: str  # repr is masked
    os_type: str  # "linux" | "windows"
    escalation_method: str | None = None  # sudo, su, su+sudo, dzdo, pbrun, cisco_enable, k5login, checkpoint_gaia
    escalation_user: str | None = None     # account to escalate to (defaults to root)
    escalation_password: str | None = None # password for escalation

    def __repr__(self) -> str:
        parts = [
            f"Target(ip={self.ip!r}, username={self.username!r}, password='***', os_type={self.os_type!r}",
        ]
        if self.escalation_method:
            parts.append(f", escalation_method={self.escalation_method!r}")
            parts.append(", escalation_user='***'" if self.escalation_user else "")
            parts.append(", escalation_password='***'" if self.escalation_password else "")
        parts.append(")")
        return "".join(p for p in parts if p)

