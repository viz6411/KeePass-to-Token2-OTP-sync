"""APDU Command definitions, serialization, and packet framing for Token2 hardware keys.

Defines wire-level ISO 7816-4 APDUs, status codes, payload packers for WRITE_SEED
and DELETE operations, and stream deserializers for ENUM_CODES.
"""

from __future__ import annotations

import time
from typing import Any

from .exceptions import Token2Error

# APDU Command Headers (CLA INS P1 P2)
CMD_GET_ECDH_PUBKEY: bytes = bytes.fromhex("80C50100")
CMD_WRITE_SEED: bytes = bytes.fromhex("80C50502")
CMD_ENUM_CODES: bytes = bytes.fromhex("80C50500")
CMD_ENUM_CODES_CONTINUE: bytes = bytes.fromhex("80C50501")
CMD_READ_ONE: bytes = bytes.fromhex("80C50500")
CMD_GET_INFO: bytes = bytes.fromhex("80330000")

# Bricking Guard: SET_DEVICE_TYPE can disable USB interfaces, permanently bricking device.
# This APDU must NEVER be sent by this driver.
CMD_SET_DEVICE_TYPE: bytes = bytes.fromhex("80C50201")

# Standard Status Words (SW1 SW2)
SW_OK: int = 0x9000
SW_EMPTY_OR_NOT_FOUND: int = 0x6A80
SW_ENTRY_NOT_FOUND: int = 0x6A83
SW_MEMORY_FULL: int = 0x6A84
SW_NOT_SUPPORTED: int = 0x6A86
SW_AUTH_FAILED: int = 0x6982
SW_BUTTON_TIMEOUT: int = 0x6FF9

# Algorithm byte constants
ALGO_SHA1: int = 0xC1
ALGO_SHA256: int = 0xC2
ALGO_SHA512: int = 0xC3

# OTP Type byte constants
OTP_TYPE_HOTP: int = 0x00
OTP_TYPE_TOTP: int = 0x01

# Subcommands for CMD_ENUM_CODES / CMD_READ_ONE
SUBCOMMAND_READ_ONE: int = 0x01
SUBCOMMAND_READ_ALL: int = 0x03


class Token2ProtocolError(Token2Error):
    """Raised when an APDU command or response violates the Token2 protocol specification."""


def validate_apdu_safety(apdu: bytes) -> None:
    """Verifies that an APDU does not execute hazardous commands such as SET_DEVICE_TYPE.

    Raises:
        Token2ProtocolError: If a hazardous command is detected.
    """
    if len(apdu) >= 3 and apdu[:3] == bytes.fromhex("80C502"):
        p2_hex = f"{apdu[3]:02X}" if len(apdu) >= 4 else "??"
        raise Token2ProtocolError(
            f"FATAL: Attempted execution of CMD_SET_DEVICE_TYPE family (80 C5 02 {p2_hex}). "
            "This command is blocked to prevent hardware bricking."
        )


def build_apdu(cla_ins_p1_p2: bytes, payload: bytes = b"") -> bytes:
    """Builds an extended ISO 7816-4 APDU frame [CLA INS P1 P2 (00 Lc_hi Lc_lo Payload)].

    Args:
        cla_ins_p1_p2: 4-byte APDU header.
        payload: Optional payload bytes.

    Returns:
        Encoded APDU bytes.
    """
    validate_apdu_safety(cla_ins_p1_p2)
    if not payload:
        return cla_ins_p1_p2

    # Extended Lc: 0x00 followed by 2 bytes big-endian length
    extended_lc = b"\x00" + len(payload).to_bytes(2, "big")
    return cla_ins_p1_p2 + extended_lc + payload


def parse_status_word(response: bytes) -> tuple[bytes, int]:
    """Extracts the data portion and 2-byte status word from an APDU response.

    Args:
        response: Full APDU response ending with SW1 SW2.

    Returns:
        Tuple of (data_bytes, status_word_int).

    Raises:
        Token2ProtocolError: If response is fewer than 2 bytes.
    """
    if len(response) < 2:
        raise Token2ProtocolError(f"Response too short ({len(response)} bytes), expected >= 2 bytes")
    data = response[:-2]
    sw = int.from_bytes(response[-2:], "big")
    return data, sw


def serialize_write_seed_payload(
    app_name: str,
    account_name: str,
    raw_seed: bytes,
    otp_type: int = OTP_TYPE_TOTP,
    algorithm: str = "SHA1",
    timestep: int = 30,
    code_length: int = 6,
    btn_flag: int = 0,
) -> bytes:
    """Serializes the unencrypted payload for CMD_WRITE_SEED.

    Format:
        type (1B) + algo (1B) + timestep (2B big-endian) + code_length (1B) + btn_flag (1B)
        + len(app) (1B) + app_bytes + len(acct) (1B) + acct_bytes + len(seed) (1B) + raw_seed.

    Args:
        app_name: Issuer / service name (max 64 bytes UTF-8).
        account_name: Account identifier / username (max 64 bytes UTF-8).
        raw_seed: Raw secret key bytes (10 to 64 bytes).
        otp_type: 0x01 for TOTP, 0x00 for HOTP.
        algorithm: "SHA1", "SHA256", or "SHA512".
        timestep: TOTP period in seconds (typically 30 or 60).
        code_length: Number of digits (typically 6 or 8).
        btn_flag: 0x00 (no button press required) or 0x01 (button press required).

    Returns:
        Serialized byte payload ready for ECDH + AES encryption.
    """
    app_bytes = app_name.encode("utf-8")
    acct_bytes = account_name.encode("utf-8")

    if len(app_bytes) > 64:
        raise ValueError(f"Issuer/app name too long ({len(app_bytes)} bytes > 64)")
    if len(acct_bytes) > 64:
        raise ValueError(f"Account name too long ({len(acct_bytes)} bytes > 64)")
    if not raw_seed:
        raise ValueError("Raw seed cannot be empty (zero-length seed represents delete)")
    if len(raw_seed) > 64:
        raise ValueError(f"Raw seed too long ({len(raw_seed)} bytes > 64)")

    algo_norm = algorithm.strip().upper()
    if algo_norm == "SHA256":
        algo_byte = ALGO_SHA256
    elif algo_norm == "SHA512":
        algo_byte = ALGO_SHA512
    else:
        algo_byte = ALGO_SHA1

    return (
        bytes([otp_type, algo_byte])
        + int(timestep).to_bytes(2, "big")
        + bytes([code_length, btn_flag])
        + bytes([len(app_bytes)])
        + app_bytes
        + bytes([len(acct_bytes)])
        + acct_bytes
        + bytes([len(raw_seed)])
        + raw_seed
    )


def serialize_delete_payload(app_name: str, account_name: str) -> bytes:
    """Serializes the unencrypted payload for deleting an entry on Token2.

    Identical to WRITE_SEED payload, with parameters zeroed and len(seed) = 0.
    """
    app_bytes = app_name.encode("utf-8")
    acct_bytes = account_name.encode("utf-8")

    if len(app_bytes) > 64:
        raise ValueError(f"Issuer/app name too long ({len(app_bytes)} bytes > 64)")
    if len(acct_bytes) > 64:
        raise ValueError(f"Account name too long ({len(acct_bytes)} bytes > 64)")

    return (
        b"\x00\x00\x00\x00\x00\x00"
        + bytes([len(app_bytes)])
        + app_bytes
        + bytes([len(acct_bytes)])
        + acct_bytes
        + b"\x00"
    )


def build_enum_codes_apdu(timestamp: int | None = None) -> bytes:
    """Builds CMD_ENUM_CODES APDU with subcommand 0x03 (READ_ALL) and 8-byte timestamp."""
    if timestamp is None:
        timestamp = int(time.time())
    payload = bytes([SUBCOMMAND_READ_ALL]) + int(timestamp).to_bytes(8, "big")
    return build_apdu(CMD_ENUM_CODES, payload)


def build_enum_codes_continue_apdu(timestamp: int | None = None) -> bytes:
    """Builds CMD_ENUM_CODES_CONTINUE APDU with 8-byte timestamp for paginated reading."""
    if timestamp is None:
        timestamp = int(time.time())
    payload = int(timestamp).to_bytes(8, "big")
    return build_apdu(CMD_ENUM_CODES_CONTINUE, payload)


def build_read_one_apdu(app_name: str, account_name: str, timestamp: int | None = None) -> bytes:
    """Builds CMD_READ_ONE APDU to query a single entry and fetch its current OTP code."""
    if timestamp is None:
        timestamp = int(time.time())
    app_bytes = app_name.encode("utf-8")
    acct_bytes = account_name.encode("utf-8")
    payload = (
        bytes([SUBCOMMAND_READ_ONE])
        + int(timestamp).to_bytes(8, "big")
        + bytes([len(app_bytes)])
        + app_bytes
        + bytes([len(acct_bytes)])
        + acct_bytes
    )
    return build_apdu(CMD_READ_ONE, payload)


def build_write_seed_apdu(encrypted_block: bytes) -> bytes:
    """Builds CMD_WRITE_SEED APDU carrying the ECDH+AES-encrypted block."""
    return build_apdu(CMD_WRITE_SEED, encrypted_block)


def build_get_info_apdu() -> bytes:
    """Builds CMD_GET_INFO APDU."""
    return build_apdu(CMD_GET_INFO)


def build_get_ecdh_pubkey_apdu() -> bytes:
    """Builds CMD_GET_ECDH_PUBKEY APDU."""
    return build_apdu(CMD_GET_ECDH_PUBKEY)


def parse_enum_response(data: bytes) -> tuple[list[dict[str, Any]], bool]:
    """Parses raw stream response from CMD_ENUM_CODES or CMD_ENUM_CODES_CONTINUE.

    The first byte indicates continuation in MSB (`byte & 0x80`) and the type of the
    first entry in the lower 7 bits (`byte & 0x7F`).
    Subsequent entries have their type as the first byte of their individual record.

    Returns:
        Tuple of (list_of_entry_dicts, has_more_boolean).
    """
    if not data:
        return [], False

    has_more = bool(data[0] & 0x80)
    first_type = data[0] & 0x7F

    entries: list[dict[str, Any]] = []
    pos = 1
    is_first = True

    while pos < len(data):
        if is_first:
            entry_type = first_type
            is_first = False
        else:
            entry_type = data[pos]
            pos += 1

        if pos >= len(data):
            break

        algo_byte = data[pos]
        pos += 1

        if algo_byte == ALGO_SHA256:
            algo = "SHA256"
        elif algo_byte == ALGO_SHA512:
            algo = "SHA512"
        else:
            algo = "SHA1"

        if pos + 2 > len(data):
            break
        timestep = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2

        if pos >= len(data):
            break
        code_length = data[pos]
        pos += 1

        if pos >= len(data):
            break
        btn_flag = data[pos]
        pos += 1

        if pos >= len(data):
            break
        app_len = data[pos]
        pos += 1

        if pos + app_len > len(data):
            break
        app_name = data[pos:pos + app_len].decode("utf-8", errors="replace")
        pos += app_len

        if pos >= len(data):
            break
        acct_len = data[pos]
        pos += 1

        if pos + acct_len > len(data):
            break
        account_name = data[pos:pos + acct_len].decode("utf-8", errors="replace")
        pos += acct_len

        otp_code: str | None = None
        # In Token2 protocol: otp_code is present only when entry_type == TOTP (1) and btn_flag == 0
        if entry_type == OTP_TYPE_TOTP and btn_flag == 0:
            if pos >= len(data):
                break
            code_len = data[pos]
            pos += 1
            if code_len > 10 or pos + code_len > len(data):
                break
            otp_code = data[pos : pos + code_len].decode("ascii", errors="replace").strip()
            pos += code_len

        entries.append({
            "type": "TOTP" if entry_type == OTP_TYPE_TOTP else "HOTP",
            "algorithm": algo,
            "timestep": timestep,
            "digits": code_length,
            "btn_flag": btn_flag,
            "app_name": app_name,
            "account_name": account_name,
            "otp_code": otp_code,
        })

    return entries, has_more
