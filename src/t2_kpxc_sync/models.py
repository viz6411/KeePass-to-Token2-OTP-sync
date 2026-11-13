"""Domain models for TOTP synchronization."""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class TOTPEntry:
    """Represents a validated TOTP profile extracted from KeePassXC."""
    issuer: str
    account: str
    secret: str
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30

    @property
    def canonical_key(self) -> tuple[str, str]:
        """Canonical identifier: (normalized_issuer, normalized_account)."""
        return (self.issuer.strip().lower(), self.account.strip().lower())

    @property
    def is_token2_compatible(self) -> bool:
        """Token2 PIN+ R3.3 supports SHA1/SHA256, 6/8 digits, 30/60 period."""
        return (
            self.algorithm.upper() in ("SHA1", "SHA256")
            and self.digits in (6, 8)
            and self.period in (30, 60)
        )


@dataclass(frozen=True)
class Token2Profile:
    """Represents a profile read from Token2 hardware token."""
    slot: int
    issuer: str
    account: str
    algorithm: str = "SHA1"
    digits: int = 6
    period: int = 30
    current_otp: Optional[str] = None

    @property
    def canonical_key(self) -> tuple[str, str]:
        return (self.issuer.strip().lower(), self.account.strip().lower())
