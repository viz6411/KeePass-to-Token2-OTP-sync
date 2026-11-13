"""Diff engine for comparing KeePassXC and Token2 entries."""

import base64
import hashlib
import hmac
import struct
import time
from dataclasses import dataclass, field
from typing import Sequence

from .models import TOTPEntry, Token2Profile

TOKEN2_MAX_CAPACITY = 300


def calculate_totp(
    secret: str,
    timestamp: int,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "SHA1"
) -> str:
    """Calculates standard RFC 6238 TOTP code."""
    # Clean and pad base32 secret
    clean_secret = secret.replace(" ", "").upper()
    missing_padding = len(clean_secret) % 8
    if missing_padding:
        clean_secret += "=" * (8 - missing_padding)

    key = base64.b32decode(clean_secret, casefold=True)
    counter = timestamp // period
    msg = struct.pack(">Q", counter)

    algo = hashlib.sha256 if algorithm.upper() == "SHA256" else hashlib.sha1
    mac = hmac.new(key, msg, algo).digest()

    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    otp = code % (10**digits)
    return str(otp).zfill(digits)


@dataclass
class DiffResult:
    to_add: list[TOTPEntry] = field(default_factory=list)
    to_update: list[tuple[TOTPEntry, Token2Profile]] = field(default_factory=list)
    to_delete: list[Token2Profile] = field(default_factory=list)
    skipped: list[TOTPEntry] = field(default_factory=list)
    duplicates: list[tuple[str, str]] = field(default_factory=list)
    final_slot_count: int = 0
    is_capacity_exceeded: bool = False


def compute_diff(
    kpxc_entries: Sequence[TOTPEntry],
    token_profiles: Sequence[Token2Profile],
    current_time: int | None = None
) -> DiffResult:
    """Compares KeePassXC entries against Token2 profiles."""
    if current_time is None:
        current_time = int(time.time())

    result = DiffResult()

    # Check for duplicates in KeePassXC
    seen_keys: set[tuple[str, str]] = set()
    valid_kpxc: dict[tuple[str, str], TOTPEntry] = {}

    for entry in kpxc_entries:
        key = entry.canonical_key
        if key in seen_keys:
            result.duplicates.append(key)
        else:
            seen_keys.add(key)
            if not entry.is_token2_compatible:
                result.skipped.append(entry)
            else:
                valid_kpxc[key] = entry

    token_map: dict[tuple[str, str], Token2Profile] = {
        p.canonical_key: p for p in token_profiles
    }

    # Evaluate adds and updates
    for key, entry in valid_kpxc.items():
        if key not in token_map:
            result.to_add.append(entry)
        else:
            profile = token_map[key]
            # Check parameter mismatch
            param_mismatch = (
                entry.algorithm.upper() != profile.algorithm.upper()
                or entry.digits != profile.digits
                or entry.period != profile.period
            )
            # Live TOTP code mismatch
            code_mismatch = False
            if profile.current_otp:
                try:
                    expected_code = calculate_totp(
                        entry.secret,
                        current_time,
                        entry.digits,
                        entry.period,
                        entry.algorithm
                    )
                    code_mismatch = (expected_code != profile.current_otp)
                except Exception:
                    code_mismatch = True

            if param_mismatch or code_mismatch:
                result.to_update.append((entry, profile))

    # Evaluate deletes
    for key, profile in token_map.items():
        if key not in valid_kpxc:
            result.to_delete.append(profile)

    # Calculate capacity
    current_count = len(token_profiles)
    result.final_slot_count = current_count - len(result.to_delete) + len(result.to_add)
    result.is_capacity_exceeded = result.final_slot_count > TOKEN2_MAX_CAPACITY

    return result
