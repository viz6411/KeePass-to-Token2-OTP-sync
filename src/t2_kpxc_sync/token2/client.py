"""High-level client for direct USB-HID interaction with Token2 PIN+ hardware keys.

Provides Token2DirectClient for listing, provisioning, reading, and deleting
TOTP profiles without requiring any external CLI binaries.
"""

from __future__ import annotations

import base64
import time
from typing import Self

from ..models import Token2Profile
from ..security import scrub_bytes
from .crypto import encrypt_payload_ecdh
from .exceptions import Token2Error, Token2PINError
from .protocol import (
    SW_AUTH_FAILED,
    SW_BUTTON_TIMEOUT,
    SW_EMPTY_OR_NOT_FOUND,
    SW_ENTRY_NOT_FOUND,
    SW_MEMORY_FULL,
    SW_OK,
    build_enum_codes_apdu,
    build_enum_codes_continue_apdu,
    build_get_ecdh_pubkey_apdu,
    build_get_info_apdu,
    build_read_one_apdu,
    build_write_seed_apdu,
    parse_enum_response,
    parse_status_word,
    serialize_delete_payload,
    serialize_write_seed_payload,
)
from .transport import BaseTransport, HIDTransport


class Token2ClientError(Token2Error):
    """Base exception for Token2 client operations."""


class Token2MemoryFullError(Token2ClientError):
    """Raised when the hardware token storage is full (300 slots limit)."""


class Token2ButtonTimeoutError(Token2ClientError):
    """Raised when user touch confirmation times out."""


class Token2DirectClient:
    """High-level driver client for direct USB-HID communication with Token2 keys."""

    def __init__(self, transport: BaseTransport | None = None) -> None:
        self.transport: BaseTransport = transport if transport is not None else HIDTransport()
        self._is_connected: bool = False

    def open(self) -> None:
        """Opens connection to the Token2 hardware token."""
        if not self._is_connected:
            self.transport.open()
            self._is_connected = True

    def close(self) -> None:
        """Closes connection to the Token2 hardware token."""
        if self._is_connected:
            self.transport.close()
            self._is_connected = False

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if not self._is_connected:
            self.open()

    def get_info(self) -> str:
        """Queries the hardware device info / serial number.

        Returns:
            Serial number string (e.g. 'T2F2-TEST-99887766').
        """
        self._ensure_open()
        apdu = build_get_info_apdu()
        resp = self.transport.send_apdu(apdu)
        data, sw = parse_status_word(resp)

        if sw == SW_AUTH_FAILED:
            raise Token2PINError("Token2 authentication failed (PIN required or incorrect PIN, status word 0x6982)")

        if sw != SW_OK:
            raise Token2ClientError(f"Failed to query device info (status word 0x{sw:04X})")

        # Parse tag 0xD1 if present: [0xD1, length, serial_bytes...]
        if len(data) >= 2 and data[0] == 0xD1:
            length = data[1]
            return data[2 : 2 + length].decode("ascii", errors="replace").strip()

        return data.decode("ascii", errors="replace").strip()

    def get_token_public_key(self) -> bytes:
        """Queries the token's 64-byte uncompressed P-256 ECDH public key."""
        self._ensure_open()
        apdu = build_get_ecdh_pubkey_apdu()
        resp = self.transport.send_apdu(apdu)
        data, sw = parse_status_word(resp)

        if sw == SW_AUTH_FAILED:
            raise Token2PINError("Token2 authentication failed (PIN required or incorrect PIN, status word 0x6982)")

        if sw == SW_BUTTON_TIMEOUT:
            raise Token2ButtonTimeoutError("Token2 button press confirmation timed out (status word 0x6FF9)")

        if sw != SW_OK:
            raise Token2ClientError(f"Failed to fetch Token2 ECDH public key (status word 0x{sw:04X})")

        if len(data) < 64:
            raise Token2ClientError(f"Token2 public key too short ({len(data)} bytes, expected 64)")

        return data[:64]

    def list_entries(self) -> list[Token2Profile]:
        """Lists all TOTP/HOTP entries stored on the hardware token.

        Iterates through paginated ENUM_CODES responses and maps them into
        Token2Profile objects with synthetic 1-based slot numbers.

        Returns:
            List of Token2Profile objects.
        """
        self._ensure_open()
        now_ts = int(time.time())
        apdu = build_enum_codes_apdu(timestamp=now_ts)
        resp = self.transport.send_apdu(apdu)
        data, sw = parse_status_word(resp)

        if sw == SW_AUTH_FAILED:
            raise Token2PINError("Token2 authentication failed (PIN required or incorrect PIN, status word 0x6982)")

        if sw in (SW_EMPTY_OR_NOT_FOUND, SW_ENTRY_NOT_FOUND):
            return []

        if sw == SW_BUTTON_TIMEOUT:
            raise Token2ButtonTimeoutError("Token2 button press confirmation timed out (status word 0x6FF9)")

        if sw != SW_OK:
            raise Token2ClientError(f"Failed to list Token2 entries (status word 0x{sw:04X})")

        entries_raw, has_more = parse_enum_response(data)

        # Pagination loop
        while has_more:
            cont_apdu = build_enum_codes_continue_apdu(timestamp=now_ts)
            cont_resp = self.transport.send_apdu(cont_apdu)
            cont_data, cont_sw = parse_status_word(cont_resp)

            if cont_sw == SW_AUTH_FAILED:
                raise Token2PINError("Token2 authentication failed (PIN required or incorrect PIN, status word 0x6982)")

            if cont_sw in (SW_EMPTY_OR_NOT_FOUND, SW_ENTRY_NOT_FOUND):
                break

            if cont_sw != SW_OK:
                raise Token2ClientError(f"Failed reading next page of entries (status word 0x{cont_sw:04X})")

            page_entries, has_more = parse_enum_response(cont_data)
            entries_raw.extend(page_entries)

        # Convert to Token2Profile domain models with synthetic slot numbers (1..N)
        profiles: list[Token2Profile] = []
        for idx, item in enumerate(entries_raw):
            profiles.append(
                Token2Profile(
                    slot=idx + 1,
                    issuer=item["app_name"],
                    account=item["account_name"],
                    algorithm=item["algorithm"],
                    digits=item["digits"],
                    period=item["timestep"],
                    current_otp=item["otp_code"],
                )
            )

        return profiles

    def write_entry(
        self,
        issuer: str,
        account: str,
        secret: str,
        algorithm: str = "SHA1",
        digits: int = 6,
        period: int = 30,
        btn_flag: int = 0,
    ) -> None:
        """Writes or updates a TOTP entry on the hardware token.

        Args:
            issuer: Service / app name.
            account: User account name.
            secret: Base32-encoded TOTP secret.
            algorithm: Hash algorithm ("SHA1" or "SHA256").
            digits: OTP length (6 or 8).
            period: Timestep in seconds (30 or 60).
            btn_flag: 0 for automatic OTP generation, 1 for touch-required.

        Raises:
            Token2MemoryFullError: If device storage capacity is exceeded (0x6A84).
            Token2ButtonTimeoutError: If user touch interaction timed out (0x6FF9).
            Token2ClientError: On other protocol or cryptographic failures.
        """
        self._ensure_open()

        # Clean and decode base32 secret
        clean_secret = secret.replace(" ", "").upper()
        if not clean_secret:
            raise ValueError(f"Secret cannot be empty for entry {issuer}:{account}")
        missing_padding = len(clean_secret) % 8
        if missing_padding:
            clean_secret += "=" * (8 - missing_padding)

        try:
            raw_seed = base64.b32decode(clean_secret, casefold=True)
        except Exception as err:
            raise ValueError(f"Invalid Base32 secret for entry {issuer}:{account}: {err}") from err

        if not raw_seed:
            raise ValueError(f"Secret seed cannot be empty for entry {issuer}:{account}")

        token_pub_key = self.get_token_public_key()

        raw_seed_buf = bytearray(raw_seed)
        try:
            payload = serialize_write_seed_payload(
                app_name=issuer,
                account_name=account,
                raw_seed=bytes(raw_seed_buf),
                algorithm=algorithm,
                timestep=period,
                code_length=digits,
                btn_flag=btn_flag,
            )
            payload_buf = bytearray(payload)
            try:
                encrypted_block = encrypt_payload_ecdh(token_pub_key, payload_buf)
            finally:
                scrub_bytes(payload_buf)
        finally:
            scrub_bytes(raw_seed_buf)

        apdu = build_write_seed_apdu(encrypted_block)
        resp = self.transport.send_apdu(apdu)
        _, sw = parse_status_word(resp)

        if sw == SW_AUTH_FAILED:
            raise Token2PINError("Token2 authentication failed (PIN required or incorrect PIN, status word 0x6982)")
        if sw == SW_MEMORY_FULL:
            raise Token2MemoryFullError("Token2 device memory is full (status word 0x6A84)")
        if sw == SW_BUTTON_TIMEOUT:
            raise Token2ButtonTimeoutError("Token2 button press confirmation timed out (status word 0x6FF9)")
        if sw != SW_OK:
            raise Token2ClientError(f"Failed to write entry to Token2 (status word 0x{sw:04X})")

    def delete_entry(self, issuer: str, account: str) -> None:
        """Deletes an entry by issuer and account name.

        Args:
            issuer: Service / app name.
            account: User account name.

        Raises:
            Token2ClientError: On communication or protocol failure.
        """
        self._ensure_open()
        token_pub_key = self.get_token_public_key()
        payload = serialize_delete_payload(app_name=issuer, account_name=account)

        encrypted_block = encrypt_payload_ecdh(token_pub_key, payload)
        apdu = build_write_seed_apdu(encrypted_block)
        resp = self.transport.send_apdu(apdu)
        _, sw = parse_status_word(resp)

        if sw == SW_AUTH_FAILED:
            raise Token2PINError("Token2 authentication failed (PIN required or incorrect PIN, status word 0x6982)")
        if sw not in (SW_OK, SW_ENTRY_NOT_FOUND, SW_EMPTY_OR_NOT_FOUND):
            raise Token2ClientError(f"Failed to delete entry from Token2 (status word 0x{sw:04X})")

    def read_otp(self, issuer: str, account: str) -> str | None:
        """Queries a single entry and retrieves its current live OTP code."""
        self._ensure_open()
        now_ts = int(time.time())
        apdu = build_read_one_apdu(app_name=issuer, account_name=account, timestamp=now_ts)
        resp = self.transport.send_apdu(apdu)
        data, sw = parse_status_word(resp)

        if sw == SW_AUTH_FAILED:
            raise Token2PINError("Token2 authentication failed (PIN required or incorrect PIN, status word 0x6982)")

        if sw in (SW_ENTRY_NOT_FOUND, SW_EMPTY_OR_NOT_FOUND):
            return None

        if sw == SW_BUTTON_TIMEOUT:
            raise Token2ButtonTimeoutError("Token2 button press confirmation timed out (status word 0x6FF9)")

        if sw != SW_OK:
            raise Token2ClientError(f"Failed reading entry OTP from Token2 (status word 0x{sw:04X})")

        # Parse single record payload:
        # type(1) algo(1) timestep(2) digits(1) btn_flag(1) len(app)(1) app len(acct)(1) acct [len(otp)(1) otp]
        if len(data) < 7:
            return None

        pos = 5
        btn_flag = data[pos]
        pos += 1

        if pos >= len(data):
            return None
        app_len = data[pos]
        pos += 1
        if pos + app_len > len(data):
            return None
        returned_app = data[pos : pos + app_len].decode("utf-8", errors="replace")
        pos += app_len

        if pos >= len(data):
            return None
        acct_len = data[pos]
        pos += 1
        if pos + acct_len > len(data):
            return None
        returned_acct = data[pos : pos + acct_len].decode("utf-8", errors="replace")
        pos += acct_len

        # Strict profile identity verification
        if returned_app != issuer or returned_acct != account:
            return None

        if btn_flag == 0 and pos < len(data):
            code_len = data[pos]
            pos += 1
            if pos + code_len <= len(data):
                return data[pos : pos + code_len].decode("ascii", errors="replace").strip()

        return None

    def erase_all(self) -> None:
        """Erases all entries stored on the hardware key."""
        self._ensure_open()
        token_pub_key = self.get_token_public_key()
        encrypted_block = encrypt_payload_ecdh(token_pub_key, b"")
        apdu = build_write_seed_apdu(encrypted_block)
        resp = self.transport.send_apdu(apdu)
        _, sw = parse_status_word(resp)

        if sw == SW_AUTH_FAILED:
            raise Token2PINError("Token2 authentication failed (PIN required or incorrect PIN, status word 0x6982)")

        if sw != SW_OK:
            raise Token2ClientError(f"Failed erasing all entries from Token2 (status word 0x{sw:04X})")
