"""tests/e2e/conftest.py: Shared fixtures and in-process virtual USB-HID hardware device.

Provides:
- SimulatedToken2HIDDevice: Pure Python virtual secure element emulating USB-HID
  framing (65-byte feature reports, magic 0x21), NIST P-256 ECDH, AES-256-CBC IV-1,
  and APDU command processing.
- mock_token2_hid: Fixture patching hidapi boundary to connect production transport
  to SimulatedToken2HIDDevice.
- isolated_config_env: Fixture providing isolated filesystem config paths.
- sample_vault_with_entries: Fixture generating pre-seeded multi-schema KDBX database.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import os
import struct
import sys
import types
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from tests.e2e.fixtures.kdbx_factory import KDBXFactory

# Constant IV-1 for Token2 PIN+ AES-256-CBC encryption
IV_1: bytes = bytes.fromhex("9DD8918E34F3CCAB08CB7518F71938F1")


@dataclass
class VirtualToken2Entry:
    """Internal NVRAM record stored in virtual Token2 device."""

    entry_type: int  # 0x01 = TOTP, 0x00 = HOTP
    algorithm: int  # 0xC1 = SHA1, 0xC2 = SHA256
    timestep: int  # 30 or 60
    digits: int  # 6 or 8
    btn_flag: int  # 0x00 or 0x01
    app_name: str
    account_name: str
    raw_seed: bytes


class SimulatedToken2HIDDevice:
    """In-process virtual Token2 PIN+ R3.3 USB-HID hardware device.

    Implements full protocol stack at the 65-byte USB feature report boundary:
    - 65-byte framing: ID 0x00, Magic 0x21, Flags/Sequence, 61-byte chunks
    - NIST P-256 (secp256r1) keypair generation and ECDH key agreement
    - Session key derivation via SHA-256(Z)
    - AES-256-CBC decryption with constant IV-1 and PKCS#7 unpadding
    - APDU dispatch: GET_INFO, GET_ECDH_PUBKEY, WRITE_SEED, ENUM_CODES, PIN ops
    - In-memory NVRAM storage up to max_capacity (default 300 entries)
    - RFC 6238 TOTP computation on demand
    """

    def __init__(
        self,
        serial_number: str = "T2-E2E-SIM-0022",
        pin: Optional[str] = None,
        max_capacity: int = 300,
        touch_polling_ticks: int = 0,
    ) -> None:
        self.serial_number = serial_number
        self.pin = pin
        self.pin_attempts_remaining = 10
        self.is_pin_verified = pin is None
        self.max_capacity = max_capacity
        self.touch_polling_ticks = touch_polling_ticks
        self._current_polling_tick = 0
        self.is_connected = True

        # Generate virtual hardware NIST P-256 key pair
        self._hw_priv = ec.generate_private_key(ec.SECP256R1())
        raw_pub = self._hw_priv.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        self.hw_pub_bytes = raw_pub[1:]  # 64 bytes uncompressed (X || Y)

        # Virtual NVRAM: (app_name, account_name) -> VirtualToken2Entry
        self.entries: dict[tuple[str, str], VirtualToken2Entry] = {}

        # USB transfer buffers
        self._rx_apdu_buffer = bytearray()
        self._rx_expected_seq = 0
        self._tx_report_queue: list[bytes] = []

    def disconnect(self) -> None:
        """Simulates USB cable unplug / hardware fault."""
        self.is_connected = False

    def reconnect(self) -> None:
        """Simulates USB cable re-insertion."""
        self.is_connected = True
        self._rx_apdu_buffer.clear()
        self._rx_expected_seq = 0
        self._tx_report_queue.clear()

    def send_feature_report(self, data: Sequence[int] | bytes) -> int:
        """Processes an incoming 65-byte USB-HID feature report from host."""
        if not self.is_connected:
            raise IOError("USB device disconnected / I/O error")

        report = bytes(data)
        if len(report) != 65:
            raise ValueError(f"Invalid HID report length: {len(report)} != 65")
        if report[0] != 0x00 or report[1] != 0x21:
            raise ValueError(f"Invalid report header: id=0x{report[0]:02X}, magic=0x{report[1]:02X}")

        flags = (report[2] >> 4) & 0x0F
        seq = report[2] & 0x0F
        chunk_len = report[3]
        if chunk_len > 61:
            raise ValueError(f"Invalid chunk length: {chunk_len} > 61")

        if seq != self._rx_expected_seq:
            # Emulate real Token2 firmware: out-of-order sequence counter returns 0x6FFB
            self._rx_apdu_buffer.clear()
            self._rx_expected_seq = 0
            self._enqueue_response_reports(bytes([0x6F, 0xFB]))
            return len(data)

        payload_chunk = report[4 : 4 + chunk_len]
        self._rx_apdu_buffer.extend(payload_chunk)

        if flags == 0x02:
            # Continuation chunk
            self._rx_expected_seq = (seq + 1) & 0x0F
            return len(data)
        elif flags == 0x00:
            # Final chunk: dispatch assembled APDU
            full_apdu = bytes(self._rx_apdu_buffer)
            self._rx_apdu_buffer.clear()
            self._rx_expected_seq = 0

            response_apdu = self._dispatch_apdu(full_apdu)
            self._enqueue_response_reports(response_apdu)
            return len(data)
        else:
            raise ValueError(f"Unsupported HID flag: 0x{flags:02X}")

    def get_feature_report(self, report_id: int, length: int) -> list[int]:
        """Provides next 65-byte USB-HID feature report to host."""
        if not self.is_connected:
            raise IOError("USB device disconnected / I/O error")

        # Simulate touch button polling if configured
        if self._current_polling_tick < self.touch_polling_ticks:
            self._current_polling_tick += 1
            poll_report = bytearray(65)
            poll_report[0] = 0x00
            poll_report[1] = 0x21
            poll_report[2] = 0xC0  # In-progress / touch polling flag
            poll_report[3] = 0
            return list(poll_report)

        if not self._tx_report_queue:
            empty_report = bytearray(65)
            empty_report[0] = 0x00
            empty_report[1] = 0x21
            empty_report[2] = 0x00
            empty_report[3] = 0
            return list(empty_report)

        rep = self._tx_report_queue.pop(0)
        return list(rep)

    def _enqueue_response_reports(self, response_apdu: bytes) -> None:
        """Chunks response APDU into 65-byte feature reports."""
        self._tx_report_queue.clear()
        total_len = len(response_apdu)
        pos = 0
        seq = 0

        if total_len == 0:
            rep = bytearray(65)
            rep[0] = 0x00
            rep[1] = 0x21
            rep[2] = 0x00
            rep[3] = 0
            self._tx_report_queue.append(bytes(rep))
            return

        while pos < total_len:
            chunk = response_apdu[pos : pos + 61]
            pos += len(chunk)
            is_last = pos >= total_len
            flags = 0x00 if is_last else 0x02

            rep = bytearray(65)
            rep[0] = 0x00
            rep[1] = 0x21
            rep[2] = (flags << 4) | (seq & 0x0F)
            rep[3] = len(chunk)
            rep[4 : 4 + len(chunk)] = chunk
            self._tx_report_queue.append(bytes(rep))
            seq = (seq + 1) & 0x0F

    def _dispatch_apdu(self, apdu: bytes) -> bytes:
        if len(apdu) < 4:
            return b"\x6F\x00"

        cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
        if cla != 0x80:
            return b"\x6E\x00"

        # 1. GET_INFO (80 33 00 00)
        if ins == 0x33 and p1 == 0x00 and p2 == 0x00:
            sn_bytes = self.serial_number.encode("utf-8")
            return bytes([0xD1, len(sn_bytes)]) + sn_bytes + b"\x90\x00"

        # 2. GET_ECDH_PUBKEY (80 C5 01 00)
        if ins == 0xC5 and p1 == 0x01 and p2 == 0x00:
            # Token2 PIN+ hardware over USB-HID strictly rejects short 4-byte APDU without extended Lc with 0x6FFB
            if len(apdu) == 4:
                return b"\x6F\xFB"
            return self.hw_pub_bytes + b"\x90\x00"

        # 3. READ_OTP_PIN_FLAG (80 C5 05 04)
        if ins == 0xC5 and p1 == 0x05 and p2 == 0x04:
            flag = 0x01 if self.pin is not None else 0x00
            return bytes([flag]) + b"\x90\x00"

        # 4. VERIFY_OTP_PIN (80 C5 05 06)
        if ins == 0xC5 and p1 == 0x05 and p2 == 0x06:
            pin_payload = apdu[4:].lstrip(b"\x00")
            try:
                candidate_pin = pin_payload.decode("utf-8", errors="replace").strip("\x00")
            except Exception:
                candidate_pin = ""

            if self.pin is None or candidate_pin == self.pin:
                self.is_pin_verified = True
                self.pin_attempts_remaining = 10
                return b"\x90\x00"
            else:
                self.pin_attempts_remaining -= 1
                if self.pin_attempts_remaining <= 0:
                    return b"\x69\x82"  # Locked
                return bytes([0x63, 0xC0 | self.pin_attempts_remaining])

        if self.pin is not None and not self.is_pin_verified:
            return b"\x69\x82"

        # 5. WRITE_SEED (80 C5 05 02)
        if ins == 0xC5 and p1 == 0x05 and p2 == 0x02:
            return self._handle_write_seed(apdu)

        # 6. ENUM_CODES (80 C5 05 00)
        if ins == 0xC5 and p1 == 0x05 and p2 == 0x00:
            return self._handle_enum_codes(apdu)

        # 7. ENUM_CODES_CONTINUE (80 C5 05 01)
        if ins == 0xC5 and p1 == 0x05 and p2 == 0x01:
            return b"\x90\x00"

        # 8. READ_ONE
        if ins == 0xC5 and p1 == 0x05 and p2 == 0x00 and len(apdu) > 16:
            return b"\x90\x00"

        return b"\x6D\x00"

    def _handle_write_seed(self, apdu: bytes) -> bytes:
        if len(apdu) < 5:
            return b"\x67\x00"

        if apdu[4] == 0x00 and len(apdu) >= 7:
            data = apdu[7:]
        else:
            data = apdu[5:]

        # Empty data payload triggers Erase All
        if len(data) == 0:
            self.entries.clear()
            return b"\x90\x00"

        if len(data) < 64 + 16:
            return b"\x6A\x80"

        host_pub_raw = data[:64]
        ciphertext = data[64:]

        # ECDH Key Exchange against virtual hardware private key
        try:
            peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), b"\x04" + host_pub_raw
            )
            shared_secret = self._hw_priv.exchange(ec.ECDH(), peer_key)
            session_key = hashlib.sha256(shared_secret).digest()

            cipher = Cipher(algorithms.AES(session_key), modes.CBC(IV_1))
            decryptor = cipher.decryptor()
            padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

            unpadder = padding.PKCS7(128).unpadder()
            plain = unpadder.update(padded_plain) + unpadder.finalize()
        except Exception:
            return b"\x6A\x80"

        # Empty decrypted payload triggers Erase All
        if len(plain) == 0:
            self.entries.clear()
            return b"\x90\x00"

        try:
            entry_type = plain[0]
            algo = plain[1]
            timestep = struct.unpack(">H", plain[2:4])[0]
            digits = plain[4]
            btn_flag = plain[5]

            app_len = plain[6]
            app_name = plain[7 : 7 + app_len].decode("utf-8")
            pos = 7 + app_len

            acct_len = plain[pos]
            pos += 1
            acct_name = plain[pos : pos + acct_len].decode("utf-8")
            pos += acct_len

            seed_len = plain[pos]
            pos += 1
            raw_seed = plain[pos : pos + seed_len]
        except Exception:
            return b"\x6A\x80"

        key = (app_name, acct_name)

        # Deletion: seed_len == 0
        if seed_len == 0:
            self.entries.pop(key, None)
            return b"\x90\x00"

        # Addition / Overwrite
        if key not in self.entries and len(self.entries) >= self.max_capacity:
            return b"\x6A\x84"  # Capacity full

        self.entries[key] = VirtualToken2Entry(
            entry_type=entry_type,
            algorithm=algo,
            timestep=timestep,
            digits=digits,
            btn_flag=btn_flag,
            app_name=app_name,
            account_name=acct_name,
            raw_seed=raw_seed,
        )
        return b"\x90\x00"

    def _handle_enum_codes(self, apdu: bytes) -> bytes:
        if apdu[4] == 0x00 and len(apdu) >= 16:
            ts_bytes = apdu[8:16]
        elif len(apdu) >= 14:
            ts_bytes = apdu[6:14]
        else:
            ts_bytes = b"\x00" * 8

        timestamp = struct.unpack(">Q", ts_bytes)[0] if len(ts_bytes) == 8 else 0

        if not self.entries:
            return b"\x6A\x80"

        buf = bytearray()
        first = True

        for entry in self.entries.values():
            otp_code = self._calculate_totp(
                entry.raw_seed,
                timestamp,
                entry.digits,
                entry.timestep,
                "SHA1" if entry.algorithm == 0xC1 else "SHA256",
            )

            if first:
                buf.append(entry.entry_type & 0x7F)
                first = False
            else:
                buf.append(entry.entry_type)

            buf.append(entry.algorithm)
            buf.extend(struct.pack(">H", entry.timestep))
            buf.append(entry.digits)
            buf.append(entry.btn_flag)

            app_bytes = entry.app_name.encode("utf-8")
            buf.append(len(app_bytes))
            buf.extend(app_bytes)

            acct_bytes = entry.account_name.encode("utf-8")
            buf.append(len(acct_bytes))
            buf.extend(acct_bytes)

            if entry.entry_type == 0x01 and entry.btn_flag == 0x00:
                otp_bytes = otp_code.encode("utf-8")
                buf.append(len(otp_bytes))
                buf.extend(otp_bytes)

        buf.extend(b"\x90\x00")
        return bytes(buf)

    @staticmethod
    def _calculate_totp(secret: bytes, timestamp: int, digits: int, period: int, algo: str) -> str:
        if period <= 0:
            period = 30
        counter = timestamp // period
        msg = struct.pack(">Q", counter)
        h = hmac.new(secret, msg, hashlib.sha1 if algo == "SHA1" else hashlib.sha256).digest()
        offset = h[-1] & 0x0F
        code = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(code % (10**digits)).zfill(digits)


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture
def simulated_token2() -> SimulatedToken2HIDDevice:
    """Provides an isolated in-process SimulatedToken2HIDDevice instance."""
    return SimulatedToken2HIDDevice()


@pytest.fixture
def mock_token2_hid(
    simulated_token2: SimulatedToken2HIDDevice,
    monkeypatch: pytest.MonkeyPatch,
) -> SimulatedToken2HIDDevice:
    """Hooks hidapi boundary to route directly to simulated_token2 device.

    Zero production logic mocking: all application cryptography, APDU serializers,
    and 65-byte USB feature report framing execute genuine production code.
    """
    class MockHIDDev:
        def __init__(self) -> None:
            self.sim = simulated_token2

        def open(self, vid: int, pid: int) -> None:
            pass

        def open_path(self, path: bytes) -> None:
            pass

        def send_feature_report(self, data: Sequence[int] | bytes) -> int:
            return self.sim.send_feature_report(data)

        def get_feature_report(self, report_id: int, length: int) -> list[int]:
            return self.sim.get_feature_report(report_id, length)

        def close(self) -> None:
            pass

    fake_hid = types.ModuleType("hid")
    setattr(fake_hid, "device", MockHIDDev)
    setattr(
        fake_hid,
        "enumerate",
        lambda vid=0, pid=0: (
            []
            if not simulated_token2.is_connected
            else [
                {
                    "vendor_id": 0x349E,
                    "product_id": 0x0022,
                    "path": b"SIM_PATH_001",
                    "manufacturer_string": "TOKEN2",
                    "product_string": "FIDO2 Security Key",
                    "serial_number": simulated_token2.serial_number,
                }
            ]
        ),
    )

    monkeypatch.setitem(sys.modules, "hid", fake_hid)

    # Route CLI's Token2CLIAdapter call to Token2Adapter in direct mode
    with contextlib.suppress(Exception):
        from t2_kpxc_sync.token2 import Token2Adapter
        monkeypatch.setattr(
            "t2_kpxc_sync.cli.Token2CLIAdapter",
            lambda cli_binary="token2-otp-cli", pin=None: Token2Adapter(backend="direct", pin=pin),
            raising=False,
        )

    return simulated_token2


@pytest.fixture
def isolated_config_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirects config path to an isolated temporary directory."""
    conf_dir = tmp_path / "config" / "t2-kpxc-sync"
    conf_dir.mkdir(parents=True, exist_ok=True)
    conf_file = conf_dir / "config.toml"

    with contextlib.suppress(Exception):
        monkeypatch.setattr("t2_kpxc_sync.config.DEFAULT_CONFIG_PATH", conf_file, raising=False)

    return conf_file


@pytest.fixture
def sample_vault_with_entries(tmp_path: Path) -> Path:
    """Generates a multi-schema KDBX test database with 5 distinct TOTP accounts."""
    vault_path = tmp_path / "sample_vault.kdbx"
    kp = KDBXFactory.create_vault(vault_path, password="masterpassword123")

    # 1. Standard GitHub (SHA1, 6d, 30s)
    KDBXFactory.add_otpauth_entry(
        kp,
        title="GitHub",
        username="octocat",
        secret="JBSWY3DPEHPK3PXP",
        issuer="GitHub",
        algorithm="SHA1",
        digits=6,
        period=30,
    )

    # 2. Standard AWS (SHA256, 8d, 60s)
    KDBXFactory.add_otpauth_entry(
        kp,
        title="AWS",
        username="admin",
        secret="GEZDGNBVGY3TQOJQ",
        issuer="AWS",
        algorithm="SHA256",
        digits=8,
        period=60,
    )

    # 3. TimeOtp custom property entry (Google)
    KDBXFactory.add_timeotp_entry(
        kp,
        title="Google",
        username="user@gmail.com",
        secret="KVKFKRCPNZQUYMLX",
        algorithm="HMAC-SHA-1",
        digits=6,
        period=30,
    )

    # 4. Standard Cloudflare (SHA1, 6d, 30s)
    KDBXFactory.add_otpauth_entry(
        kp,
        title="Cloudflare",
        username="ops",
        secret="MFRGGZDFMZTWQ2LK",
        issuer="Cloudflare",
        algorithm="SHA1",
        digits=6,
        period=30,
    )

    # 5. Non-OTP standard entry (should be ignored by sync)
    KDBXFactory.add_standard_entry(kp, title="PersonalMail", username="me")

    return vault_path
