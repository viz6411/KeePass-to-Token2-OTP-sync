"""Exception hierarchy for Token2 hardware driver and adapter."""

from __future__ import annotations


class Token2Error(Exception):
    """Base exception for all Token2 operations, transport, and protocol errors."""


class Token2PINError(Token2Error):
    """Raised when PIN authentication fails. Immediate abort without retries."""
