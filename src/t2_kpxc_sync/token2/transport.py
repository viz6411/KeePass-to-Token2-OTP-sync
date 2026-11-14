"""USB-HID Transport layer for Token2 PIN+ hardware tokens.

Provides BaseTransport interface, production HIDTransport using hidapi,
and MockHIDTransport for standalone unit and integration testing without hardware.
"""

from __future__ import annotations

import abc
import contextlib
import time
from collections.abc import Callable
from typing import Any, Self

from .crypto import (
    IV_1,
    decrypt_payload_ecdh,
    generate_ecdh_keypair,
)
from .exceptions import Token2Error
from .protocol import (
    ALGO_SHA1,
    ALGO_SHA256,
    CMD_ENUM_CODES,
    CMD_ENUM_CODES_CONTINUE,
    CMD_GET_ECDH_PUBKEY,
    CMD_GET_INFO,
    CMD_READ_ONE,
    CMD_WRITE_SEED,
    OTP_TYPE_HOTP,
    OTP_TYPE_TOTP,
    SW_EMPTY_OR_NOT_FOUND,
    SW_ENTRY_NOT_FOUND,
    SW_MEMORY_FULL,
    SW_OK,
    SW_SHORT_FORM_REJECTED,
    Token2ProtocolError,
    validate_apdu_safety,
)

# Standard Token2 USB Identifiers
TOKEN2_VID: int = 0x349E
TOKEN2_PID: int = 0x0022
TOKEN2_MANUFACTURER_KEYWORD: str = "TOKEN2"
TOKEN2_PRODUCT_KEYWORD: str = "FIDO2 SECURITY KEY"

# Framing constants
FEATURE_REPORT_ID: int = 0x00
FEATURE_REPORT_MAGIC: int = 0x21
FEATURE_REPORT_SIZE: int = 65
CHUNK_DATA_MAX_SIZE: int = 61

FLAG_LAST_FRAME: int = 0x00
FLAG_MORE_FRAMES: int = 0x20
FLAG_POLLING_IN_PROGRESS: int = 0xC0


class Token2TransportError(Token2Error):
    """Base exception for transport communication errors."""


class Token2DeviceNotFoundError(Token2TransportError):
    """Raised when no matching Token2 hardware token is found on the USB bus."""


class Token2TimeoutError(Token2TransportError):
    """Raised when device polling or button-press interaction times out."""


class BaseTransport(abc.ABC):
    """Abstract base transport for Token2 communications."""

    def __init__(self) -> None:
        self._seq: int = 0

    @abc.abstractmethod
    def open(self) -> None:
        """Opens connection to the hardware device."""
        self._seq = 0

    @abc.abstractmethod
    def close(self) -> None:
        """Closes connection to the hardware device."""

    @abc.abstractmethod
    def send_feature_report(self, report: bytes) -> None:
        """Sends a 65-byte Feature Report to the device."""

    @abc.abstractmethod
    def get_feature_report(self, report_id: int, length: int) -> bytes:
        """Retrieves a Feature Report from the device."""

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def send_apdu(
        self,
        apdu: bytes,
        timeout: float = 10.0,
        on_polling_callback: Callable[[int], None] | None = None,
    ) -> bytes:
        """Sends an APDU command across 65-byte Feature Reports and reassembles the response.

        Handles chunk fragmentation (flag 0x20) for payloads > 61 bytes,
        polling (flag 0xC0) for in-progress operations / touch confirmation,
        and response stream reassembly.

        Args:
            apdu: Full APDU command bytes.
            timeout: Maximum seconds to wait for complete response.
            on_polling_callback: Optional callback invoked with poll count when device is busy.

        Returns:
            Complete APDU response bytes ending with 2-byte status word.

        Raises:
            Token2ProtocolError: On safety check failure or framing violations.
            Token2TimeoutError: If operation exceeds timeout limit.
            Token2TransportError: On USB communication failure.
        """
        validate_apdu_safety(apdu)

        # 1. Fragment outgoing APDU into <= 61-byte chunks
        chunks: list[bytes] = []
        if not apdu:
            chunks.append(b"")
        else:
            for i in range(0, len(apdu), CHUNK_DATA_MAX_SIZE):
                chunks.append(apdu[i : i + CHUNK_DATA_MAX_SIZE])

        # Token2 USB-HID wire protocol: sequence counter strictly resets per APDU command
        self._seq = 0
        for idx, chunk in enumerate(chunks):
            is_last = (idx == len(chunks) - 1)
            flag = FLAG_LAST_FRAME if is_last else FLAG_MORE_FRAMES
            seq_val = idx & 0x0F
            flags_seq = (flag & 0xF0) | seq_val

            pad_len = CHUNK_DATA_MAX_SIZE - len(chunk)
            report = (
                bytes([FEATURE_REPORT_ID, FEATURE_REPORT_MAGIC, flags_seq, len(chunk)])
                + chunk
                + bytes(pad_len)
            )
            self.send_feature_report(report)
            self._seq = (idx + 1) & 0x0F

        # 2. Reassemble incoming response frames
        response_bytes = bytearray()
        start_time = time.monotonic()
        poll_count = 0
        poll_delay = 0.05
        expected_rx_seq = 0

        while True:
            if time.monotonic() - start_time > timeout:
                raise Token2TimeoutError(
                    f"Timed out after {timeout:.1f}s waiting for Token2 response (polled {poll_count} times)"
                )

            report = self.get_feature_report(FEATURE_REPORT_ID, FEATURE_REPORT_SIZE)
            raw = bytes(report)

            # Strip leading Report ID 0x00 if present in report return
            if len(raw) == FEATURE_REPORT_SIZE and raw[0] == FEATURE_REPORT_ID:
                raw = raw[1:]

            if len(raw) < 3:
                raise Token2ProtocolError(f"Feature report response too short ({len(raw)} bytes, expected >= 3)")

            magic = raw[0]
            if magic != FEATURE_REPORT_MAGIC:
                raise Token2ProtocolError(f"Invalid feature report magic 0x{magic:02X}, expected 0x21")

            flags_seq = raw[1]
            chunk_len = raw[2]
            flag = flags_seq & 0xF0
            rx_seq = flags_seq & 0x0F

            if flag == FLAG_POLLING_IN_PROGRESS:
                # Device busy / waiting for touch button
                poll_count += 1
                if on_polling_callback is not None:
                    on_polling_callback(poll_count)
                time.sleep(poll_delay)
                # In polling mode, sequence counter is NOT advanced
                continue

            if rx_seq != expected_rx_seq:
                raise Token2ProtocolError(
                    f"Sequence mismatch in response frame: got {rx_seq}, expected {expected_rx_seq}"
                )
            expected_rx_seq = (expected_rx_seq + 1) & 0x0F

            if 3 + chunk_len > len(raw):
                raise Token2ProtocolError(
                    f"Report payload overflow: claimed length {chunk_len}, buffer length {len(raw)}"
                )

            chunk_data = raw[3 : 3 + chunk_len]
            response_bytes.extend(chunk_data)

            if flag == FLAG_MORE_FRAMES:
                # More frames follow
                continue
            elif flag == FLAG_LAST_FRAME:
                # Complete APDU received
                break
            else:
                raise Token2ProtocolError(f"Unexpected frame flag 0x{flag:02X} in response")

        return bytes(response_bytes)


class HIDTransport(BaseTransport):
    """Production USB-HID transport using the hidapi library."""

    def __init__(
        self,
        vendor_id: int = TOKEN2_VID,
        product_id: int = TOKEN2_PID,
        device_path: bytes | None = None,
    ) -> None:
        super().__init__()
        self.vendor_id = vendor_id
        self.product_id = product_id
        self.device_path = device_path
        self._dev = None

    def open(self) -> None:
        """Finds and opens the Token2 USB-HID device."""
        self._seq = 0
        if self._dev is not None:
            return

        try:
            import hid
        except ImportError as err:
            raise Token2TransportError(
                "The 'hidapi' library is not available. Install with 'pip install hidapi'."
            ) from err

        target_path: bytes | None = self.device_path

        if target_path is None:
            # Enumerate USB devices matching VID/PID or manufacturer/product strings
            devices = hid.enumerate()
            for info in devices:
                vid = info.get("vendor_id", 0)
                pid = info.get("product_id", 0)
                mfr = (info.get("manufacturer_string") or "").upper()
                prod = (info.get("product_string") or "").upper()

                matches_vid_pid = (vid == self.vendor_id and pid == self.product_id)
                matches_descriptor = (
                    TOKEN2_MANUFACTURER_KEYWORD in mfr or TOKEN2_PRODUCT_KEYWORD in prod
                )

                if matches_vid_pid or matches_descriptor:
                    target_path = info.get("path")
                    break

        if target_path is None:
            raise Token2DeviceNotFoundError(
                f"No Token2 device found (VID=0x{self.vendor_id:04X}, PID=0x{self.product_id:04X}). "
                "Ensure device is connected and appropriate udev rules (on Linux) are configured."
            )

        try:
            dev = hid.device()
            dev.open_path(target_path)
            self._dev = dev
        except Exception as err:
            raise Token2TransportError(f"Failed to open Token2 USB-HID device: {err}") from err

    def close(self) -> None:
        """Closes the USB-HID device."""
        if self._dev is not None:
            with contextlib.suppress(Exception):
                self._dev.close()
            self._dev = None

    def send_feature_report(self, report: bytes) -> None:
        """Sends a 65-byte Feature Report to the device via hidapi."""
        if self._dev is None:
            raise Token2TransportError("Device is not open")

        if len(report) != FEATURE_REPORT_SIZE:
            raise ValueError(f"Report must be {FEATURE_REPORT_SIZE} bytes, got {len(report)}")

        try:
            # hidapi expects a list of integers or bytes starting with report ID
            res = self._dev.send_feature_report(list(report))
            if res < 0:
                raise Token2TransportError(f"send_feature_report failed (code {res})")
        except Exception as err:
            raise Token2TransportError(f"USB send_feature_report error: {err}") from err

    def get_feature_report(self, report_id: int, length: int) -> bytes:
        """Reads a Feature Report from the device via hidapi."""
        if self._dev is None:
            raise Token2TransportError("Device is not open")

        try:
            data = self._dev.get_feature_report(report_id, length)
            if not data:
                raise Token2TransportError("get_feature_report returned empty response")
            return bytes(data)
        except Exception as err:
            raise Token2TransportError(f"USB get_feature_report error: {err}") from err


class MockHIDTransport(BaseTransport):
    """In-memory mock hardware transport simulating a Token2 PIN+ device.

    Implements P-256 ECDH key exchange, AES-256-CBC decryption of write/delete
    commands, TOTP code calculation, pagination, and configurable chaos hooks.
    """

    def __init__(
        self,
        serial: str = "T2F2-TEST-99887766",
        max_entries: int = 300,
        page_size: int = 5,
    ) -> None:
        super().__init__()
        self.serial = serial
        self.max_entries = max_entries
        self.page_size = page_size
        self.is_open: bool = False

        # Generate simulated device ECDH keypair
        self._priv_key, self.public_key_raw = generate_ecdh_keypair()

        # Storage: (app_name, account_name) -> dict
        self.entries: dict[tuple[str, str], dict[str, Any]] = {}

        # Internal state for framing simulation
        self._incoming_buffer = bytearray()
        self._rx_expected_seq: int = 0
        self._outgoing_chunks: list[tuple[bytes, int, int]] = []

        # Chaos / simulation controls
        self.poll_delay_countdown: int = 0
        self.force_status_word: int | None = None
        self._enum_cursor: int = 0
        self._last_timestamp: int = 0

    def open(self) -> None:
        self._seq = 0
        self._rx_expected_seq = 0
        self.is_open = True

    def close(self) -> None:
        self.is_open = False
        self._rx_expected_seq = 0
        self._incoming_buffer.clear()
        self._outgoing_chunks.clear()

    def send_feature_report(self, report: bytes) -> None:
        """Processes an incoming 65-byte Feature Report from host."""
        if not self.is_open:
            raise Token2TransportError("Mock device is not open")

        if len(report) != FEATURE_REPORT_SIZE:
            raise Token2ProtocolError(f"Mock report size must be 65 bytes, got {len(report)}")

        if report[0] != FEATURE_REPORT_ID:
            raise Token2ProtocolError(f"Invalid report ID {report[0]}")

        magic = report[1]
        if magic != FEATURE_REPORT_MAGIC:
            raise Token2ProtocolError(f"Invalid magic 0x{magic:02X}")

        flags_seq = report[2]
        chunk_len = report[3]
        if chunk_len > CHUNK_DATA_MAX_SIZE:
            raise Token2ProtocolError(
                f"Feature report chunk_len ({chunk_len}) exceeds maximum allowed {CHUNK_DATA_MAX_SIZE}"
            )
        flag = flags_seq & 0xF0
        seq = flags_seq & 0x0F

        if seq != self._rx_expected_seq:
            # Emulate real Token2 firmware: out-of-order or invalid seq counter yields SW_SHORT_FORM_REJECTED (0x6FFB)
            self._incoming_buffer.clear()
            self._rx_expected_seq = 0
            self._prepare_outgoing_chunks(SW_SHORT_FORM_REJECTED.to_bytes(2, "big"))
            return

        chunk = report[4 : 4 + chunk_len]
        self._incoming_buffer.extend(chunk)

        if flag == FLAG_MORE_FRAMES:
            self._rx_expected_seq = (seq + 1) & 0x0F
        elif flag == FLAG_LAST_FRAME:
            self._rx_expected_seq = 0
            # Full APDU received; process and prepare outgoing response
            apdu = bytes(self._incoming_buffer)
            self._incoming_buffer.clear()
            response_apdu = self._process_apdu(apdu)
            self._prepare_outgoing_chunks(response_apdu)
        else:
            raise Token2ProtocolError(f"Unexpected frame flag 0x{flag:02X} in report")

    def get_feature_report(self, report_id: int, length: int) -> bytes:
        """Serves outgoing Feature Reports to the host."""
        if not self.is_open:
            raise Token2TransportError("Mock device is not open")

        # Simulate in-progress / touch polling flag if countdown active
        if self.poll_delay_countdown > 0:
            self.poll_delay_countdown -= 1
            flags_seq = (FLAG_POLLING_IN_PROGRESS & 0xF0) | 0
            return bytes([FEATURE_REPORT_ID, FEATURE_REPORT_MAGIC, flags_seq, 0]) + bytes(61)

        if not self._outgoing_chunks:
            # Empty response or idle
            flags_seq = (FLAG_LAST_FRAME & 0xF0) | 0
            return bytes([FEATURE_REPORT_ID, FEATURE_REPORT_MAGIC, flags_seq, 0]) + bytes(61)

        chunk, flag, seq = self._outgoing_chunks.pop(0)
        flags_seq = (flag & 0xF0) | (seq & 0x0F)
        pad_len = CHUNK_DATA_MAX_SIZE - len(chunk)
        return (
            bytes([FEATURE_REPORT_ID, FEATURE_REPORT_MAGIC, flags_seq, len(chunk)])
            + chunk
            + bytes(pad_len)
        )

    def _prepare_outgoing_chunks(self, apdu_response: bytes) -> None:
        """Splits an APDU response into 61-byte chunks for get_feature_report."""
        self._outgoing_chunks.clear()
        if not apdu_response:
            self._outgoing_chunks.append((b"", FLAG_LAST_FRAME, 0))
            return

        chunks: list[bytes] = []
        for i in range(0, len(apdu_response), CHUNK_DATA_MAX_SIZE):
            chunks.append(apdu_response[i : i + CHUNK_DATA_MAX_SIZE])

        for idx, chunk in enumerate(chunks):
            is_last = (idx == len(chunks) - 1)
            flag = FLAG_LAST_FRAME if is_last else FLAG_MORE_FRAMES
            self._outgoing_chunks.append((chunk, flag, idx & 0x0F))

    def _process_apdu(self, apdu: bytes) -> bytes:
        """Dispatches and executes APDU commands against in-memory state."""
        if self.force_status_word is not None:
            sw = self.force_status_word
            return sw.to_bytes(2, "big")

        if len(apdu) < 4:
            return (0x6700).to_bytes(2, "big")  # Wrong length

        header = apdu[:4]

        # 1. GET ECDH PUBKEY
        if header == CMD_GET_ECDH_PUBKEY:
            return self.public_key_raw + SW_OK.to_bytes(2, "big")

        # 2. GET INFO
        if header == CMD_GET_INFO:
            serial_bytes = self.serial.encode("ascii")
            # Return tag 0xD1 + length + serial_bytes + 90 00
            info_payload = bytes([0xD1, len(serial_bytes)]) + serial_bytes
            return info_payload + SW_OK.to_bytes(2, "big")

        # 3. WRITE SEED (provision or delete)
        if header == CMD_WRITE_SEED:
            return self._handle_write_seed(apdu)

        # 4. ENUM CODES / READ ONE (80 C5 05 00)
        if header == bytes.fromhex("80C50500"):
            if len(apdu) > 7:
                subcmd = apdu[7]
                if subcmd == 0x01:  # SUBCOMMAND_READ_ONE
                    return self._handle_read_one(apdu)
                if subcmd == 0x03:  # SUBCOMMAND_READ_ALL
                    return self._handle_enum_codes(apdu)
            return (0x6A80).to_bytes(2, "big")

        # 5. ENUM CODES CONTINUE (Pagination)
        if header == CMD_ENUM_CODES_CONTINUE:
            return self._handle_enum_codes_continue(apdu)

        # Unsupported command
        return (0x6D00).to_bytes(2, "big")  # Instruction not supported

    def _handle_write_seed(self, apdu: bytes) -> bytes:
        # Strip header (4 bytes) + extended Lc (3 bytes: 00 Lc_hi Lc_lo)
        if len(apdu) < 7:
            return (0x6700).to_bytes(2, "big")
        encrypted_block = apdu[7:]

        try:
            plaintext = decrypt_payload_ecdh(self._priv_key, encrypted_block, IV_1)
        except (ValueError, TypeError, KeyError, IndexError):
            return (0x6982).to_bytes(2, "big")  # Security status not satisfied

        if not plaintext:
            # Erase all
            self.entries.clear()
            return SW_OK.to_bytes(2, "big")

        # Parse plaintext fields:
        # type(1) algo(1) timestep(2) code_length(1) btn_flag(1)
        # len(app)(1) app len(acct)(1) acct len(seed)(1) seed
        if len(plaintext) < 8:
            return (0x6A80).to_bytes(2, "big")

        try:
            otp_type = plaintext[0]
            algo_byte = plaintext[1]
            timestep = int.from_bytes(plaintext[2:4], "big")
            code_length = plaintext[4]
            btn_flag = plaintext[5]

            pos = 6
            if pos >= len(plaintext):
                return (0x6A80).to_bytes(2, "big")
            app_len = plaintext[pos]
            pos += 1
            if pos + app_len > len(plaintext):
                return (0x6A80).to_bytes(2, "big")
            app_name = plaintext[pos : pos + app_len].decode("utf-8", errors="replace")
            pos += app_len

            if pos >= len(plaintext):
                return (0x6A80).to_bytes(2, "big")
            acct_len = plaintext[pos]
            pos += 1
            if pos + acct_len > len(plaintext):
                return (0x6A80).to_bytes(2, "big")
            account_name = plaintext[pos : pos + acct_len].decode("utf-8", errors="replace")
            pos += acct_len

            if pos >= len(plaintext):
                return (0x6A80).to_bytes(2, "big")
            seed_len = plaintext[pos]
            pos += 1
            if pos + seed_len > len(plaintext):
                return (0x6A80).to_bytes(2, "big")
            seed = plaintext[pos : pos + seed_len]
        except (IndexError, ValueError):
            return (0x6A80).to_bytes(2, "big")

        key = (app_name, account_name)

        if seed_len == 0:
            # Delete operation
            self.entries.pop(key, None)
            return SW_OK.to_bytes(2, "big")

        # Provision / update operation
        if key not in self.entries and len(self.entries) >= self.max_entries:
            return SW_MEMORY_FULL.to_bytes(2, "big")

        algo_str = "SHA256" if algo_byte == ALGO_SHA256 else "SHA1"
        self.entries[key] = {
            "type": "TOTP" if otp_type == OTP_TYPE_TOTP else "HOTP",
            "algorithm": algo_str,
            "timestep": timestep,
            "digits": code_length,
            "btn_flag": btn_flag,
            "app_name": app_name,
            "account_name": account_name,
            "seed": seed,
        }
        return SW_OK.to_bytes(2, "big")

    def _handle_enum_codes(self, apdu: bytes) -> bytes:
        if not self.entries:
            return SW_EMPTY_OR_NOT_FOUND.to_bytes(2, "big")

        # Extract timestamp from payload: 4 header + 3 Lc + 1 subcmd + 8 timestamp
        ts = int(time.time())
        if len(apdu) >= 16:
            ts = int.from_bytes(apdu[8:16], "big")
        self._last_timestamp = ts
        self._enum_cursor = 0

        return self._build_enum_page()

    def _handle_enum_codes_continue(self, apdu: bytes) -> bytes:
        # Extract timestamp: 4 header + 3 Lc + 8 timestamp
        ts = self._last_timestamp
        if len(apdu) >= 15:
            ts = int.from_bytes(apdu[7:15], "big")
        self._last_timestamp = ts

        return self._build_enum_page()

    def _build_enum_page(self) -> bytes:
        all_items = list(self.entries.values())
        if self._enum_cursor >= len(all_items):
            return SW_EMPTY_OR_NOT_FOUND.to_bytes(2, "big")

        page_items = all_items[self._enum_cursor : self._enum_cursor + self.page_size]
        self._enum_cursor += len(page_items)
        has_more = self._enum_cursor < len(all_items)

        page_bytes = bytearray()
        first_item = page_items[0]
        first_type_byte = OTP_TYPE_TOTP if first_item["type"] == "TOTP" else OTP_TYPE_HOTP
        if has_more:
            first_type_byte |= 0x80
        page_bytes.append(first_type_byte)

        for idx, item in enumerate(page_items):
            if idx > 0:
                item_type = OTP_TYPE_TOTP if item["type"] == "TOTP" else OTP_TYPE_HOTP
                page_bytes.append(item_type)

            algo_byte = ALGO_SHA256 if item["algorithm"] == "SHA256" else ALGO_SHA1
            page_bytes.append(algo_byte)
            page_bytes.extend(int(item["timestep"]).to_bytes(2, "big"))
            page_bytes.append(item["digits"])
            page_bytes.append(item["btn_flag"])

            app_b = item["app_name"].encode("utf-8")
            page_bytes.append(len(app_b))
            page_bytes.extend(app_b)

            acct_b = item["account_name"].encode("utf-8")
            page_bytes.append(len(acct_b))
            page_bytes.extend(acct_b)

            if item["type"] == "TOTP" and item["btn_flag"] == 0:
                otp_code = self._compute_totp(
                    item["seed"],
                    self._last_timestamp,
                    item["timestep"],
                    item["digits"],
                    item["algorithm"],
                )
                code_b = otp_code.encode("ascii")
                page_bytes.append(len(code_b))
                page_bytes.extend(code_b)

        return bytes(page_bytes) + SW_OK.to_bytes(2, "big")

    def _handle_read_one(self, apdu: bytes) -> bytes:
        # 4 header + 3 Lc + 1 subcmd + 8 timestamp + 1 app_len + app + 1 acct_len + acct
        if len(apdu) < 17:
            return (0x6700).to_bytes(2, "big")

        try:
            ts = int.from_bytes(apdu[8:16], "big")
            pos = 16
            if pos >= len(apdu):
                return (0x6700).to_bytes(2, "big")
            app_len = apdu[pos]
            pos += 1
            if pos + app_len > len(apdu):
                return (0x6700).to_bytes(2, "big")
            app_name = apdu[pos : pos + app_len].decode("utf-8", errors="replace")
            pos += app_len

            if pos >= len(apdu):
                return (0x6700).to_bytes(2, "big")
            acct_len = apdu[pos]
            pos += 1
            if pos + acct_len > len(apdu):
                return (0x6700).to_bytes(2, "big")
            acct_name = apdu[pos : pos + acct_len].decode("utf-8", errors="replace")
        except (IndexError, ValueError):
            return (0x6700).to_bytes(2, "big")

        key = (app_name, acct_name)
        if key not in self.entries:
            return SW_ENTRY_NOT_FOUND.to_bytes(2, "big")

        item = self.entries[key]
        item_bytes = bytearray()
        item_type = OTP_TYPE_TOTP if item["type"] == "TOTP" else OTP_TYPE_HOTP
        item_bytes.append(item_type)
        algo_byte = ALGO_SHA256 if item["algorithm"] == "SHA256" else ALGO_SHA1
        item_bytes.append(algo_byte)
        item_bytes.extend(int(item["timestep"]).to_bytes(2, "big"))
        item_bytes.append(item["digits"])
        item_bytes.append(item["btn_flag"])

        app_b = item["app_name"].encode("utf-8")
        item_bytes.append(len(app_b))
        item_bytes.extend(app_b)

        acct_b = item["account_name"].encode("utf-8")
        item_bytes.append(len(acct_b))
        item_bytes.extend(acct_b)

        if item["type"] == "TOTP" and item["btn_flag"] == 0:
            otp_code = self._compute_totp(
                item["seed"],
                ts,
                item["timestep"],
                item["digits"],
                item["algorithm"],
            )
            code_b = otp_code.encode("ascii")
            item_bytes.append(len(code_b))
            item_bytes.extend(code_b)

        return bytes(item_bytes) + SW_OK.to_bytes(2, "big")

    @staticmethod
    def _compute_totp(
        raw_seed: bytes,
        timestamp: int,
        timestep: int = 30,
        digits: int = 6,
        algorithm: str = "SHA1",
    ) -> str:
        """Calculates RFC 6238 TOTP directly from raw seed bytes."""
        import hashlib
        import hmac
        import struct

        counter = int(timestamp // timestep)
        msg = struct.pack(">Q", counter)
        algo = hashlib.sha256 if algorithm.upper() == "SHA256" else hashlib.sha1
        mac = hmac.new(raw_seed, msg, algo).digest()
        offset = mac[-1] & 0x0F
        code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
        otp = code % (10**digits)
        return str(otp).zfill(digits)
