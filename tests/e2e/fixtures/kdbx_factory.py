"""tests/e2e/fixtures/kdbx_factory.py: Programmatic KDBX test database generator.

Supports:
- KDBX 4.0 generation with AES-256, ChaCha20, Twofish ciphers
- Standard RFC 6238 otpauth:// URI entries
- KeeOtp / TrayTOTP TimeOtp-* custom property entries
- Normal non-OTP login entries
- Binary keyfile generation (32-byte)
- Fault injection: corrupted headers and corrupted payload bytes
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from pykeepass import PyKeePass, create_database


class KDBXFactory:
    """Helper for generating and mutating KeePass test databases."""

    @staticmethod
    def create_vault(
        path: Path,
        password: Optional[str] = "test-master-password",
        keyfile: Optional[Path] = None,
        cipher: str = "aes256",  # "aes256", "chacha20", "twofish"
    ) -> PyKeePass:
        """Creates a base database, optionally configuring cipher."""
        path.parent.mkdir(parents=True, exist_ok=True)
        kp = create_database(
            str(path),
            password=password,
            keyfile=str(keyfile) if keyfile else None,
        )

        cipher_normalized = cipher.lower().strip()
        if cipher_normalized != "aes256":
            # Switch dynamic cipher header
            kp.kdbx.header.value.dynamic_header.cipher_id.data = cipher_normalized
            kp.save()
            # Reload to initialize internal cipher engine
            kp = PyKeePass(str(path), password=password, keyfile=str(keyfile) if keyfile else None)

        return kp

    @staticmethod
    def add_otpauth_entry(
        kp: PyKeePass,
        group: Any = None,
        title: str = "GitHub",
        username: str = "octocat",
        secret: str = "JBSWY3DPEHPK3PXP",
        issuer: Optional[str] = None,
        algorithm: str = "SHA1",
        digits: int = 6,
        period: int = 30,
        save: bool = True,
    ) -> Any:
        """Adds an entry configured with standard otpauth:// URI in entry.otp."""
        target_group = group or kp.root_group
        e = kp.add_entry(target_group, title, username, "dummy-password-123")
        iss = issuer or title
        e.otp = (
            f"otpauth://totp/{iss}:{username}"
            f"?secret={secret}&issuer={iss}&algorithm={algorithm}&digits={digits}&period={period}"
        )
        if save:
            kp.save()
        return e

    @staticmethod
    def add_timeotp_entry(
        kp: PyKeePass,
        group: Any = None,
        title: str = "AWS",
        username: str = "admin",
        secret: str = "GEZDGNBVGY3TQOJQ",
        algorithm: str = "HMAC-SHA-256",
        digits: int = 8,
        period: int = 60,
        save: bool = True,
    ) -> Any:
        """Adds an entry configured with KeeOtp / TrayTOTP custom properties."""
        target_group = group or kp.root_group
        e = kp.add_entry(target_group, title, username, "dummy-password-123")
        e.set_custom_property("TimeOtp-Secret-Base32", secret)
        e.set_custom_property("TimeOtp-Algorithm", algorithm)
        e.set_custom_property("TimeOtp-Length", str(digits))
        e.set_custom_property("TimeOtp-Period", str(period))
        if save:
            kp.save()
        return e

    @staticmethod
    def add_standard_entry(
        kp: PyKeePass,
        group: Any = None,
        title: str = "WebMail",
        username: str = "user",
        save: bool = True,
    ) -> Any:
        """Adds a standard login entry WITHOUT any TOTP configuration."""
        target_group = group or kp.root_group
        e = kp.add_entry(target_group, title, username, "login-only-password")
        if save:
            kp.save()
        return e

    @staticmethod
    def create_keyfile(path: Path, length: int = 32) -> Path:
        """Creates a raw binary keyfile."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(os.urandom(length))
        return path

    @staticmethod
    def corrupt_file_header(path: Path) -> None:
        """Corrupts first 4 magic bytes of KDBX file."""
        data = bytearray(path.read_bytes())
        data[0:4] = b"XXXX"
        path.write_bytes(data)

    @staticmethod
    def corrupt_file_payload(path: Path) -> None:
        """Corrupts ciphertext payload bytes of KDBX file."""
        data = bytearray(path.read_bytes())
        if len(data) > 60:
            data[-50:-20] = b"\x00" * 30
        else:
            data[len(data) // 2 :] = b"\x00" * (len(data) // 2)
        path.write_bytes(data)
