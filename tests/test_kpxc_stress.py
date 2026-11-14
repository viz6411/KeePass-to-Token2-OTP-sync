"""Adversarial stress and edge-case test suite for Milestone 1 KeePass direct reader.

Authored by Challenger M1.1.
Tests extreme inputs, corrupt headers/payloads, zero-byte files, random noise,
unusual TOTP configurations, malformed URIs, and custom property case variations.
"""

import base64
import os
import shutil
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pykeepass

from t2_kpxc_sync.kpxc import (
    KeePassCorruptedError,
    KeePassCredentialsError,
    KeePassXCError,
    clean_base32,
    extract_totp_from_entry,
    is_entry_excluded,
    normalize_algorithm,
    parse_otpauth_uri,
    parse_totp_settings,
    read_kdbx_direct,
    read_kpxc_entries,
)
from t2_kpxc_sync.models import TOTPEntry
from tests.test_kpxc_direct import make_test_vault, make_keyfile


# ==============================================================================
# 1. Extreme Passwords & Master Keys
# ==============================================================================

def test_stress_empty_password_vault(tmp_path):
    """KDBX vault created with empty string password."""
    db = make_test_vault(
        tmp_path / "empty_pw.kdbx",
        password="",
        entries=[{"title": "EmptyPWTest", "otp": "otpauth://totp/EmptyPWTest?secret=JBSWY3DPEHPK3PXP"}],
    )
    # Direct read with empty string password
    entries = read_kdbx_direct(db, password="")
    assert len(entries) == 1
    assert entries[0].secret == "JBSWY3DPEHPK3PXP"

    # Auto facade with empty string password
    entries_auto = read_kpxc_entries(db, password="", backend="auto")
    assert len(entries_auto) == 1

    # Reading with bytearray empty password
    entries_ba = read_kdbx_direct(db, password=bytearray(b""))
    assert len(entries_ba) == 1

    # Reading with bytes empty password
    entries_b = read_kdbx_direct(db, password=b"")
    assert len(entries_b) == 1


def test_stress_unicode_multilingual_passwords(tmp_path):
    """KDBX vaults created with diverse Unicode passwords (Cyrillic, CJK, Emojis, Accents)."""
    passwords = [
        "Пароль_123!_Секрет",  # Cyrillic
        "🔑パスワード_テスト_12345",  # CJK + Emoji
        "🔥🛡️🚀💾✨",  # Multi-emoji
        "äöüß_éèêë_ñ_ç_Å",  # European accented chars
        "مرحبا_كلمة_السر_123",  # Arabic RTL
        "password with spaces and \t tabs",  # Whitespace inside
    ]
    for idx, pw in enumerate(passwords):
        db = make_test_vault(
            tmp_path / f"unicode_pw_{idx}.kdbx",
            password=pw,
            entries=[{"title": f"Service_{idx}", "otp": "otpauth://totp/Service?secret=JBSWY3DPEHPK3PXP"}],
        )
        # Read as str
        entries = read_kdbx_direct(db, password=pw)
        assert len(entries) == 1
        assert entries[0].secret == "JBSWY3DPEHPK3PXP"

        # Read as UTF-8 bytes
        entries_b = read_kdbx_direct(db, password=pw.encode("utf-8"))
        assert len(entries_b) == 1

        # Read as bytearray
        entries_ba = read_kdbx_direct(db, password=bytearray(pw.encode("utf-8")))
        assert len(entries_ba) == 1


def test_stress_invalid_utf8_password_bytes(tmp_path):
    """Passing invalid non-UTF8 bytes to read_kdbx_direct does not crash with unhandled exception."""
    db = make_test_vault(
        tmp_path / "valid_vault.kdbx",
        password="correct-password",
        entries=[{"title": "Test", "otp": "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"}],
    )
    # b"\xff\xfe\x80\x00" is invalid UTF-8
    with pytest.raises(KeePassCredentialsError):
        read_kdbx_direct(db, password=b"\xff\xfe\x80\x00")


def test_stress_massive_password_handling(tmp_path):
    """Passing a massive 100,000-char password fails gracefully as invalid credentials."""
    db = make_test_vault(
        tmp_path / "normal_vault.kdbx",
        password="normal",
        entries=[{"title": "Test", "otp": "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"}],
    )
    huge_pw = "A" * 100_000
    with pytest.raises(KeePassCredentialsError):
        read_kdbx_direct(db, password=huge_pw)


def test_stress_null_bytes_in_password(tmp_path):
    """Password containing embedded null bytes."""
    pw_with_null = "pass\x00word"
    db = make_test_vault(
        tmp_path / "null_pw.kdbx",
        password=pw_with_null,
        entries=[{"title": "NullTest", "otp": "otpauth://totp/NullTest?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password=pw_with_null)
    assert len(entries) == 1


# ==============================================================================
# 2. Corrupted Files, Garbage Noise, and Extreme File Boundaries
# ==============================================================================

def test_stress_random_garbage_files(tmp_path):
    """Random binary garbage files of various sizes raise KeePassCorruptedError."""
    sizes = [16, 64, 256, 1024, 65536]
    for idx, sz in enumerate(sizes):
        f = tmp_path / f"garbage_{idx}_{sz}b.bin"
        f.write_bytes(os.urandom(sz))

        with pytest.raises(KeePassCorruptedError):
            read_kdbx_direct(f, password="dummy")

        with pytest.raises(KeePassCorruptedError):
            read_kpxc_entries(f, password="dummy", backend="auto")


def test_stress_kdbx4_magic_with_truncated_header(tmp_path):
    """Valid KDBX 4.0 magic header (0x9AA2D903 0xB54BFB67) but truncated immediately after."""
    kdbx4_sig = bytes([0x03, 0xD9, 0xA2, 0x9A, 0x67, 0xFB, 0x4B, 0xB5])
    lengths = [8, 9, 10, 11, 12, 16, 24]
    for idx, l in enumerate(lengths):
        f = tmp_path / f"magic_trunc_{idx}.kdbx"
        f.write_bytes(kdbx4_sig + os.urandom(l - 8))
        with pytest.raises(KeePassCorruptedError):
            read_kdbx_direct(f, password="dummy")


def test_stress_valid_kdbx_with_scrambled_payload(tmp_path):
    """Valid KDBX 4.0 file whose encrypted payload is corrupted/truncated."""
    db = make_test_vault(
        tmp_path / "corrupt_payload.kdbx",
        password="secret",
        entries=[{"title": "Test", "otp": "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"}],
    )
    raw = bytearray(db.read_bytes())
    # Corrupt last 100 bytes
    for i in range(max(0, len(raw) - 100), len(raw)):
        raw[i] ^= 0xFF
    db.write_bytes(raw)

    with pytest.raises((KeePassCorruptedError, KeePassCredentialsError)):
        read_kdbx_direct(db, password="secret")


def test_stress_directory_passed_as_db_path(tmp_path):
    """Passing a directory path instead of a file."""
    dir_path = tmp_path / "some_dir.kdbx"
    dir_path.mkdir()

    with pytest.raises(KeePassXCError):
        read_kdbx_direct(dir_path, password="secret")


def test_stress_directory_passed_as_keyfile_path(tmp_path):
    """Passing a directory path as keyfile."""
    db = make_test_vault(
        tmp_path / "kf_test.kdbx",
        password="secret",
        entries=[{"title": "Test", "otp": "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP"}],
    )
    dir_kf = tmp_path / "dir_keyfile"
    dir_kf.mkdir()

    with pytest.raises(KeePassXCError):
        read_kdbx_direct(db, password="secret", keyfile_path=dir_kf)


def test_stress_corrupted_xml_keyfile(tmp_path):
    """Corrupted XML keyfile with broken syntax or bad base64."""
    db_path = tmp_path / "vault_kf.kdbx"
    kf_valid = make_keyfile(tmp_path / "valid.key", fmt="xml")
    make_test_vault(db_path, password=None, keyfile_path=kf_valid)

    # Malformed XML syntax
    kf_bad_xml = tmp_path / "bad_syntax.key"
    kf_bad_xml.write_text("<KeyFile><Key><Data>broken-xml", encoding="utf-8")
    with pytest.raises(KeePassXCError):
        read_kdbx_direct(db_path, password=None, keyfile_path=kf_bad_xml)

    # Valid XML but invalid Base64 in <Data>
    kf_bad_b64 = tmp_path / "bad_b64.key"
    kf_bad_b64.write_text(
        '<?xml version="1.0" encoding="utf-8"?><KeyFile><Key><Data>!@#$%^&*</Data></Key></KeyFile>',
        encoding="utf-8",
    )
    with pytest.raises(KeePassXCError):
        read_kdbx_direct(db_path, password=None, keyfile_path=kf_bad_b64)

    # Empty XML keyfile (0 bytes)
    kf_empty = tmp_path / "empty.key"
    kf_empty.write_bytes(b"")
    with pytest.raises(KeePassXCError):
        read_kdbx_direct(db_path, password=None, keyfile_path=kf_empty)


# ==============================================================================
# 3. Base32, Algorithm, Settings & Normalization Adversarial Probes
# ==============================================================================

def test_stress_clean_base32_edge_cases():
    """clean_base32 handling of edge cases and invalid formats."""
    # Valid secrets with weird formatting
    assert clean_base32("  jbsw-y3dp ehpk-3pxp \t \n") == "JBSWY3DPEHPK3PXP"
    assert clean_base32("JBSWY3DPEHPK3PXP====") == "JBSWY3DPEHPK3PXP"
    assert clean_base32("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP"

    # Odd valid Base32 lengths requiring padding
    # "MY" -> b"f", len 2 -> needs 6 '='
    assert clean_base32("MY") == "MY"
    # "MZXW6" -> b"foo", len 5 -> needs 3 '='
    assert clean_base32("MZXW6") == "MZXW6"

    # Invalid characters (1, 8, 9, 0 are not RFC 4648 Base32)
    assert clean_base32("1890") is None
    assert clean_base32("JBSWY3DPEHPK3PXP!") is None
    assert clean_base32("JBSW@Y3DPEHPK3PXP") is None
    assert clean_base32("JBSW#Y3DPEHPK3PXP") is None

    # Empty, whitespace-only, dash-only
    assert clean_base32("") is None
    assert clean_base32("   ") is None
    assert clean_base32("---") is None
    assert clean_base32(" - - ") is None

    # Non-string input
    assert clean_base32(None) is None
    assert clean_base32(12345) is None
    assert clean_base32(["JBSWY3DPEHPK3PXP"]) is None

    # Equals sign in the middle
    assert clean_base32("JBSW=Y3DPEHPK3PXP") is None


def test_stress_normalize_algorithm():
    """normalize_algorithm mapping and fallback to RFC 6238 default SHA1."""
    assert normalize_algorithm("sha1") == "SHA1"
    assert normalize_algorithm("SHA-1") == "SHA1"
    assert normalize_algorithm("HMAC-SHA-1") == "SHA1"
    assert normalize_algorithm("hmac_sha1") == "SHA1"

    assert normalize_algorithm("sha256") == "SHA256"
    assert normalize_algorithm("SHA-256") == "SHA256"
    assert normalize_algorithm("HMAC-SHA-256") == "SHA256"
    assert normalize_algorithm("hmac_sha256") == "SHA256"

    assert normalize_algorithm("sha512") == "SHA512"
    assert normalize_algorithm("SHA-512") == "SHA512"
    assert normalize_algorithm("HMAC-SHA-512") == "SHA512"

    # Unsupported or weird algorithms should safely fallback to SHA1
    assert normalize_algorithm("MD5") == "SHA1"
    assert normalize_algorithm("BLAKE2b") == "SHA1"
    assert normalize_algorithm("UNKNOWN_ALGO") == "SHA1"
    assert normalize_algorithm("") == "SHA1"
    assert normalize_algorithm("   ") == "SHA1"
    assert normalize_algorithm(None) == "SHA1"


def test_stress_parse_totp_settings():
    """parse_totp_settings with irregular formatting."""
    # Semicolon delimited
    assert parse_totp_settings("60;8;SHA256") == (60, 8, "SHA256")
    assert parse_totp_settings("30;6") == (30, 6, "SHA1")
    assert parse_totp_settings("45") == (45, 6, "SHA1")

    # Colon delimited
    assert parse_totp_settings("60:8:SHA512") == (60, 8, "SHA512")
    assert parse_totp_settings("30:8") == (30, 8, "SHA1")

    # Whitespace in parts
    assert parse_totp_settings(" 60 ; 8 ; SHA256 ") == (60, 8, "SHA256")

    # Empty parts / missing values
    assert parse_totp_settings(";;") == (30, 6, "SHA1")
    assert parse_totp_settings(";;SHA256") == (30, 6, "SHA256")
    assert parse_totp_settings("abc;def;xyz") == (30, 6, "SHA1")
    assert parse_totp_settings("") == (30, 6, "SHA1")
    assert parse_totp_settings(None) == (30, 6, "SHA1")


# ==============================================================================
# 4. URI & Custom Property Adversarial Probes
# ==============================================================================

def test_stress_parse_otpauth_uri_adversarial():
    """parse_otpauth_uri with invalid, malformed, or hostile inputs."""
    # Scheme is not otpauth
    assert parse_otpauth_uri("https://example.com/totp?secret=JBSWY3DPEHPK3PXP") is None
    assert parse_otpauth_uri("ftp://totp/account?secret=JBSWY3DPEHPK3PXP") is None
    assert parse_otpauth_uri("data:text/plain;base64,JBSWY3DPEHPK3PXP") is None

    # HOTP type must be rejected
    assert parse_otpauth_uri("otpauth://hotp/Bank:user?secret=JBSWY3DPEHPK3PXP&counter=1") is None

    # Missing secret query param
    assert parse_otpauth_uri("otpauth://totp/Test:user") is None
    assert parse_otpauth_uri("otpauth://totp/Test:user?secret=") is None
    assert parse_otpauth_uri("otpauth://totp/Test:user?secret=1890") is None  # Invalid B32

    # Non-numeric digits and period fallback safely
    entry = parse_otpauth_uri("otpauth://totp/Test:user?secret=JBSWY3DPEHPK3PXP&digits=eight&period=sixty")
    assert entry is not None
    assert entry.digits == 6
    assert entry.period == 30

    # Complex URL encoded characters in issuer/account
    entry2 = parse_otpauth_uri(
        "otpauth://totp/My%20Awesome%20Service%3Aalice%2Btest%40example.com?secret=JBSWY3DPEHPK3PXP"
    )
    assert entry2 is not None
    assert entry2.issuer == "My Awesome Service"
    assert entry2.account == "alice+test@example.com"

    # Query param issuer precedence over path issuer
    entry3 = parse_otpauth_uri(
        "otpauth://totp/PathIssuer:alice?secret=JBSWY3DPEHPK3PXP&issuer=QueryIssuer"
    )
    assert entry3 is not None
    assert entry3.issuer == "QueryIssuer"
    assert entry3.account == "alice"

    # Completely empty or non-string URI
    assert parse_otpauth_uri("") is None
    assert parse_otpauth_uri("   ") is None
    assert parse_otpauth_uri(None) is None


def test_stress_custom_property_case_variations():
    """Case-insensitive custom properties (TimeOtp-*, TOTP Seed, TOTP Settings)."""
    class MockEntry:
        def __init__(self, title, username, custom_props, otp=None):
            self.title = title
            self.username = username
            self.custom_properties = custom_props
            self.otp = otp

    # Upper case
    e1 = MockEntry(
        "ServiceA",
        "userA",
        {
            "TIMEOTP-SECRET-BASE32": "JBSWY3DPEHPK3PXP",
            "TIMEOTP-PERIOD": "45",
            "TIMEOTP-DIGITS": "8",
            "TIMEOTP-ALGORITHM": "HMAC-SHA-256",
        },
    )
    totp1 = extract_totp_from_entry(e1)
    assert totp1 is not None
    assert totp1.secret == "JBSWY3DPEHPK3PXP"
    assert totp1.period == 45
    assert totp1.digits == 8
    assert totp1.algorithm == "SHA256"

    # KeeTrayTOTP properties lowercase
    e2 = MockEntry(
        "ServiceB",
        "userB",
        {
            "totp seed": "JBSWY3DPEHPK3PXP",
            "totp settings": "60;8;SHA512",
        },
    )
    totp2 = extract_totp_from_entry(e2)
    assert totp2 is not None
    assert totp2.secret == "JBSWY3DPEHPK3PXP"
    assert totp2.period == 60
    assert totp2.digits == 8
    assert totp2.algorithm == "SHA512"

    # Custom property OTP containing KeeOtp query string
    e3 = MockEntry(
        "ServiceC",
        "userC",
        {
            "OTP": "key=JBSWY3DPEHPK3PXP&step=15&size=7&enc=SHA1",
        },
    )
    totp3 = extract_totp_from_entry(e3)
    assert totp3 is not None
    assert totp3.secret == "JBSWY3DPEHPK3PXP"
    assert totp3.period == 15
    assert totp3.digits == 7
    assert totp3.algorithm == "SHA1"

    # Custom properties with None keys or None values
    e4 = MockEntry(
        "ServiceD",
        "userD",
        {
            None: "dummy",
            "timeotp-secret-base32": "JBSWY3DPEHPK3PXP",
            "some-other-prop": None,
        },
    )
    totp4 = extract_totp_from_entry(e4)
    assert totp4 is not None
    assert totp4.secret == "JBSWY3DPEHPK3PXP"

    # HOTP in custom property OTP is ignored
    e5 = MockEntry(
        "ServiceE",
        "userE",
        {"OTP": "otpauth://hotp/ServiceE?secret=JBSWY3DPEHPK3PXP&counter=1"},
    )
    assert extract_totp_from_entry(e5) is None


# ==============================================================================
# 5. Full End-to-End Adversarial Vault Probing
# ==============================================================================

def test_stress_vault_with_mixed_hostile_entries(tmp_path):
    """KDBX vault with mixed valid, invalid, corrupted, and edge-case entries."""
    mixed_entries = [
        # 1. Valid TOTP entry
        {
            "title": "ValidEntry",
            "username": "alice",
            "otp": "otpauth://totp/ValidEntry:alice?secret=JBSWY3DPEHPK3PXP",
        },
        # 2. Corrupt Base32 secret (should be skipped)
        {
            "title": "BadB32Entry",
            "username": "bob",
            "otp": "otpauth://totp/BadB32Entry:bob?secret=INVALID!1890#$",
        },
        # 3. HOTP entry (must be skipped)
        {
            "title": "HotpEntry",
            "username": "charlie",
            "otp": "otpauth://hotp/HotpEntry:charlie?secret=JBSWY3DPEHPK3PXP&counter=5",
        },
        # 4. Normal login without TOTP (must be skipped)
        {
            "title": "RegularLogin",
            "username": "dave",
            "password": "Password123!",
        },
        # 5. KeePass 2.47 custom property with whitespace in secret
        {
            "title": "KeePass247Entry",
            "username": "eve",
            "custom_properties": {
                "TimeOtp-Secret-Base32": "  jbsw-y3dp ehpk-3pxp  ",
                "TimeOtp-Period": "60",
                "TimeOtp-Digits": "8",
                "TimeOtp-Algorithm": "HMAC-SHA-256",
            },
        },
        # 6. KeeTrayTOTP format
        {
            "title": "KeeTrayEntry",
            "username": "frank",
            "custom_properties": {
                "TOTP Seed": "MZXW6===",
                "TOTP Settings": "30;6",
            },
        },
        # 7. Excluded entry in Recycle Bin
        {
            "title": "DeletedEntry",
            "username": "grace",
            "otp": "otpauth://totp/DeletedEntry:grace?secret=JBSWY3DPEHPK3PXP",
            "in_recycle_bin": True,
        },
        # 8. Entry in custom excluded group
        {
            "title": "ArchivedEntry",
            "username": "heidi",
            "group": "Archive/OldTokens",
            "otp": "otpauth://totp/ArchivedEntry:heidi?secret=JBSWY3DPEHPK3PXP",
        },
    ]

    db = make_test_vault(
        tmp_path / "mixed_hostile.kdbx",
        password="master-password-123",
        entries=mixed_entries,
    )

    extracted = read_kdbx_direct(
        db,
        password="master-password-123",
        excluded_groups=["Archive", "Recycle Bin"],
    )

    extracted_titles = [e.issuer for e in extracted]

    # ValidEntry, KeePass247Entry, KeeTrayEntry should succeed
    assert len(extracted) == 3
    assert "ValidEntry" in extracted_titles
    assert "KeePass247Entry" in extracted_titles
    assert "KeeTrayEntry" in extracted_titles

    # Deleted, Archived, HOTP, BadB32, RegularLogin must NOT be extracted
    assert "DeletedEntry" not in extracted_titles
    assert "ArchivedEntry" not in extracted_titles
    assert "HotpEntry" not in extracted_titles
    assert "BadB32Entry" not in extracted_titles
    assert "RegularLogin" not in extracted_titles
