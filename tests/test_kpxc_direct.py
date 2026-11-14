"""Unit and integration tests for direct in-memory KDBX reader and hybrid routing."""

import base64
import gzip
import os
import weakref
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest
import pykeepass
from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids

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
    read_kpxc_entries_cli,
)
from t2_kpxc_sync.models import TOTPEntry
from t2_kpxc_sync.security import scrub_bytes

# Embedded test fixtures for legacy KDBX 3.1 verification (upstream pykeepass test3)
KDBX3_KEY_B64 = """PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4NCjxLZXlGaWxlPg0KCTxNZXRhPg0KCQk8VmVyc2lvbj4xLjAwPC9WZXJzaW9uPg0KCTwvTWV0YT4NCgk8S2V5Pg0KCQk8RGF0YT5RcDlNckZNMVJwU0xPOGlIWkhHQWlQYnI4WitoREZwcDBjZ3RIK1JNMGh3PTwvRGF0YT4NCgk8L0tleT4NCjwvS2V5RmlsZT4NCg=="""

KDBX3_DB_GZ_B64 = """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"""


def make_test_vault(
    vault_path: Path,
    password: Optional[str] = "test-master-password",
    keyfile_path: Optional[Path] = None,
    version: tuple[int, int] = (4, 0),
    cipher: str = "aes256",
    kdf: str = "argon2",
    entries: Optional[List[Dict[str, Any]]] = None,
    fast_kdf: bool = True,
) -> Path:
    """Programmatically constructs a KDBX vault in tmp_path with configured entries."""
    kp = pykeepass.create_database(
        filename=str(vault_path),
        password=password,
        keyfile=str(keyfile_path) if keyfile_path else None,
    )

    # Version adjustment (KDBX 4.1)
    if version == (4, 1):
        kp.kdbx.header.value.minor_version = 1

    # Cipher adjustment
    if cipher in ("chacha20", "twofish"):
        kp.kdbx.header.value.dynamic_header.cipher_id.data = cipher

    # KDF adjustment
    hdr_dict = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    if kdf == "argon2id":
        hdr_dict["$UUID"].value = kdf_uuids["argon2id"]

    # Ultra-fast Argon2 test tuning (reduces derivation from ~880ms to ~2ms)
    if fast_kdf and "I" in hdr_dict and "M" in hdr_dict:
        hdr_dict["I"].value = 1
        hdr_dict["M"].value = 65536  # 64 KB

    # Populate groups and entries
    root = kp.root_group
    group_map = {"": root}

    if entries:
        for item in entries:
            grp_name = item.get("group", "")
            if grp_name and grp_name not in group_map:
                current_grp = root
                for part in grp_name.split("/"):
                    existing = [g for g in current_grp.subgroups if g.name == part]
                    if existing:
                        current_grp = existing[0]
                    else:
                        current_grp = kp.add_group(current_grp, part)
                group_map[grp_name] = current_grp

            target_grp = group_map.get(grp_name, root)
            entry = kp.add_entry(
                target_grp,
                title=item.get("title", "Untitled"),
                username=item.get("username", "user"),
                password=item.get("password", "pass"),
            )

            # Standard OTP URI
            if "otp" in item:
                entry.otp = item["otp"]

            # Custom string properties (TimeOtp-*, TOTP Settings, etc.)
            if "custom_properties" in item:
                for k, v in item["custom_properties"].items():
                    entry.set_custom_property(k, v)

            # Recycle bin action
            if item.get("in_recycle_bin", False):
                kp.trash_entry(entry)

    kp.save()
    return vault_path


def make_keyfile(kf_path: Path, fmt: str = "binary") -> Path:
    """Creates a temporary test keyfile in binary, hex, or XML format."""
    if fmt == "binary":
        kf_path.write_bytes(os.urandom(32))
    elif fmt == "hex":
        kf_path.write_text(os.urandom(32).hex(), encoding="ascii")
    elif fmt == "xml":
        raw = os.urandom(32)
        b64 = base64.b64encode(raw).decode("ascii")
        xml_content = f"""<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
    <Meta><Version>1.0</Version></Meta>
    <Key><Data>{b64}</Data></Key>
</KeyFile>"""
        kf_path.write_text(xml_content, encoding="utf-8")
    return kf_path


# ==============================================================================
# Group A: Multi-Version & Cipher In-Memory Decryption
# ==============================================================================

def test_direct_read_kdbx40_default(tmp_path):
    """Verifies reading a standard KDBX 4.0 database."""
    db = make_test_vault(
        tmp_path / "kdbx40.kdbx",
        entries=[{"title": "GitHub", "username": "octocat", "otp": "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password="test-master-password")
    assert len(entries) == 1
    assert entries[0].issuer == "GitHub"
    assert entries[0].account == "octocat"
    assert entries[0].secret == "JBSWY3DPEHPK3PXP"


def test_direct_read_kdbx41_minor_version(tmp_path):
    """Verifies reading a KDBX 4.1 database."""
    db = make_test_vault(
        tmp_path / "kdbx41.kdbx",
        version=(4, 1),
        entries=[{"title": "AWS", "username": "admin", "otp": "otpauth://totp/AWS:admin?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password="test-master-password")
    assert len(entries) == 1
    assert entries[0].issuer == "AWS"
    assert entries[0].account == "admin"


def test_direct_read_kdbx31_legacy(tmp_path):
    """Verifies reading a legacy KDBX 3.1 database with XML v1.0 keyfile."""
    db_path = tmp_path / "test3.kdbx"
    key_path = tmp_path / "test3.key"

    db_path.write_bytes(gzip.decompress(base64.b64decode(KDBX3_DB_GZ_B64)))
    key_path.write_bytes(base64.b64decode(KDBX3_KEY_B64))

    entries = read_kdbx_direct(db_path, password="password", keyfile_path=key_path)
    assert len(entries) == 1
    assert entries[0].issuer == "foobar_entry"
    assert entries[0].account == "foobar"
    assert entries[0].secret == "OTPSECRETT"


def test_direct_read_cipher_chacha20(tmp_path):
    """Verifies reading a database encrypted with ChaCha20."""
    db = make_test_vault(
        tmp_path / "chacha.kdbx",
        cipher="chacha20",
        entries=[{"title": "ChaCha", "otp": "otpauth://totp/ChaCha:u?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password="test-master-password")
    assert len(entries) == 1
    assert entries[0].issuer == "ChaCha"


def test_direct_read_cipher_twofish(tmp_path):
    """Verifies reading a database encrypted with Twofish."""
    db = make_test_vault(
        tmp_path / "twofish.kdbx",
        cipher="twofish",
        entries=[{"title": "TwoFish", "otp": "otpauth://totp/TwoFish:u?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password="test-master-password")
    assert len(entries) == 1
    assert entries[0].issuer == "TwoFish"


def test_direct_read_kdf_argon2id(tmp_path):
    """Verifies reading a database using Argon2id KDF."""
    db = make_test_vault(
        tmp_path / "argon2id.kdbx",
        kdf="argon2id",
        entries=[{"title": "Argon2id", "otp": "otpauth://totp/Argon2id:u?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password="test-master-password")
    assert len(entries) == 1
    assert entries[0].issuer == "Argon2id"


# ==============================================================================
# Group B: Credentials Authentication Matrix
# ==============================================================================

def test_direct_read_password_str(tmp_path):
    """Verifies password passed as str."""
    db = make_test_vault(
        tmp_path / "pw_str.kdbx",
        password="MyStringPassword123!",
        entries=[{"title": "PWStr", "otp": "otpauth://totp/PWStr:u?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password="MyStringPassword123!")
    assert len(entries) == 1


def test_direct_read_password_bytearray(tmp_path):
    """Verifies password passed as mutable bytearray."""
    db = make_test_vault(
        tmp_path / "pw_ba.kdbx",
        password="MyBAPassword123!",
        entries=[{"title": "PWBA", "otp": "otpauth://totp/PWBA:u?secret=JBSWY3DPEHPK3PXP"}],
    )
    ba = bytearray(b"MyBAPassword123!")
    entries = read_kdbx_direct(db, password=ba)
    assert len(entries) == 1


def test_direct_read_password_bytes(tmp_path):
    """Verifies password passed as immutable bytes."""
    db = make_test_vault(
        tmp_path / "pw_bytes.kdbx",
        password="MyBytesPassword123!",
        entries=[{"title": "PWBytes", "otp": "otpauth://totp/PWBytes:u?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password=b"MyBytesPassword123!")
    assert len(entries) == 1


def test_direct_read_keyfile_binary_only(tmp_path):
    """Verifies authentication using raw 32-byte binary keyfile without password."""
    kf = make_keyfile(tmp_path / "bin.key", fmt="binary")
    db = make_test_vault(
        tmp_path / "kf_bin.kdbx",
        password=None,
        keyfile_path=kf,
        entries=[{"title": "KFBin", "otp": "otpauth://totp/KFBin:u?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password=None, keyfile_path=kf)
    assert len(entries) == 1


def test_direct_read_keyfile_xml_only(tmp_path):
    """Verifies authentication using XML keyfile without password."""
    kf = make_keyfile(tmp_path / "xml.key", fmt="xml")
    db = make_test_vault(
        tmp_path / "kf_xml.kdbx",
        password=None,
        keyfile_path=kf,
        entries=[{"title": "KFXML", "otp": "otpauth://totp/KFXML:u?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password=None, keyfile_path=kf)
    assert len(entries) == 1


def test_direct_read_password_and_keyfile(tmp_path):
    """Verifies combined password and keyfile authentication."""
    kf = make_keyfile(tmp_path / "combo.key", fmt="binary")
    db = make_test_vault(
        tmp_path / "combo.kdbx",
        password="SecretComboPassword!",
        keyfile_path=kf,
        entries=[{"title": "Combo", "otp": "otpauth://totp/Combo:u?secret=JBSWY3DPEHPK3PXP"}],
    )
    entries = read_kdbx_direct(db, password="SecretComboPassword!", keyfile_path=kf)
    assert len(entries) == 1


# ==============================================================================
# Group C: Multi-Schema TOTP Parsing
# ==============================================================================

def test_direct_read_standard_otpauth_uri(tmp_path):
    """Verifies standard KeePassXC otpauth:// URI parsing with non-default parameters."""
    entries_spec = [
        {
            "title": "MyEntry",
            "username": "user1",
            "otp": "otpauth://totp/CustomIssuer:user1?secret=JBSWY3DPEHPK3PXP&issuer=QueryIssuer&algorithm=SHA256&digits=8&period=60",
        }
    ]
    db = make_test_vault(tmp_path / "uri.kdbx", entries=entries_spec)
    extracted = read_kdbx_direct(db, password="test-master-password")
    assert len(extracted) == 1
    e = extracted[0]
    assert e.issuer == "QueryIssuer"
    assert e.account == "user1"
    assert e.secret == "JBSWY3DPEHPK3PXP"
    assert e.algorithm == "SHA256"
    assert e.digits == 8
    assert e.period == 60


def test_direct_read_custom_properties_keeotp(tmp_path):
    """Verifies legacy KeeOtp format in entry.otp and custom properties."""
    entries_spec = [
        {
            "title": "LegacyField",
            "username": "u1",
            "otp": "key=JBSWY3DPEHPK3PXP&step=45&size=8&enc=HMAC-SHA-256",
        },
        {
            "title": "CustomOTP",
            "username": "u2",
            "custom_properties": {
                "OTP": "key=GEZDGNBVGY3TQOJQ&step=30&size=6",
            },
        },
    ]
    db = make_test_vault(tmp_path / "keeotp.kdbx", entries=entries_spec)
    extracted = read_kdbx_direct(db, password="test-master-password")
    assert len(extracted) == 2
    keys = {e.account: e for e in extracted}
    assert keys["u1"].period == 45
    assert keys["u1"].digits == 8
    assert keys["u1"].algorithm == "SHA256"
    assert keys["u2"].secret == "GEZDGNBVGY3TQOJQ"


def test_direct_read_custom_properties_traytotp(tmp_path):
    """Verifies KeePass 2.47+ native fields and KeeTrayTOTP properties."""
    entries_spec = [
        {
            "title": "NativeKeePass",
            "username": "u1",
            "custom_properties": {
                "TimeOtp-Secret-Base32": "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ",
                "TimeOtp-Period": "60",
                "TimeOtp-Length": "8",
                "TimeOtp-Algorithm": "HMAC-SHA-256",
            },
        },
        {
            "title": "TrayTOTP",
            "username": "u2",
            "custom_properties": {
                "TOTP Seed": "GEZDGNBVGY3TQOJQ",
                "TOTP Settings": "60;8;SHA512",
            },
        },
    ]
    db = make_test_vault(tmp_path / "traytotp.kdbx", entries=entries_spec)
    extracted = read_kdbx_direct(db, password="test-master-password")
    assert len(extracted) == 2
    keys = {e.issuer: e for e in extracted}
    assert keys["NativeKeePass"].algorithm == "SHA256"
    assert keys["NativeKeePass"].digits == 8
    assert keys["NativeKeePass"].period == 60
    assert keys["TrayTOTP"].algorithm == "SHA512"
    assert keys["TrayTOTP"].digits == 8
    assert keys["TrayTOTP"].period == 60


def test_direct_read_secret_cleaning_and_padding(tmp_path):
    """Verifies secret cleaning: spaces, hyphens, lowercase, unpadded base32."""
    entries_spec = [
        {
            "title": "SpacedDashed",
            "username": "u1",
            "otp": "otpauth://totp/Spaced:u1?secret=jbsw-y3dp ehpk-3pxp",
        },
        {
            "title": "Unpadded15Chars",
            "username": "u2",
            "custom_properties": {
                "TimeOtp-Secret-Base32": "JBSWY3DPEHPK3PX",
            },
        },
    ]
    db = make_test_vault(tmp_path / "cleaning.kdbx", entries=entries_spec)
    extracted = read_kdbx_direct(db, password="test-master-password")
    assert len(extracted) == 2
    assert extracted[0].secret == "JBSWY3DPEHPK3PXP"
    assert extracted[1].secret == "JBSWY3DPEHPK3PX"


def test_direct_read_mixed_entries_and_logins(tmp_path):
    """Verifies that non-OTP credentials are ignored and do not crash the reader."""
    entries_spec = [
        {"title": "ValidOTP", "otp": "otpauth://totp/Service:u?secret=JBSWY3DPEHPK3PXP"},
        {"title": "PlainPasswordOnly", "username": "admin", "password": "SuperSecretPassword123"},
        {"title": "EmptyNotes", "username": "empty"},
    ]
    db = make_test_vault(tmp_path / "mixed.kdbx", entries=entries_spec)
    extracted = read_kdbx_direct(db, password="test-master-password")
    assert len(extracted) == 1
    assert extracted[0].issuer == "Service"


def test_direct_read_hotp_ignored(tmp_path):
    """Verifies that counter-based HOTP entries are strictly ignored."""
    entries_spec = [
        {
            "title": "HOTPEntry",
            "otp": "otpauth://hotp/Counter:user?secret=JBSWY3DPEHPK3PXP&counter=1",
        }
    ]
    db = make_test_vault(tmp_path / "hotp.kdbx", entries=entries_spec)
    extracted = read_kdbx_direct(db, password="test-master-password")
    assert len(extracted) == 0


# ==============================================================================
# Group D: Group Hierarchy & Exclusion Filters
# ==============================================================================

def test_direct_read_nested_groups(tmp_path):
    """Verifies entries in nested group structures are parsed successfully."""
    entries_spec = [
        {"title": "RootEntry", "group": "", "otp": "otpauth://totp/Root:u?secret=JBSWY3DPEHPK3PXP"},
        {"title": "DeepEntry", "group": "Level1/Level2/Level3", "otp": "otpauth://totp/Deep:u?secret=JBSWY3DPEHPK3PXP"},
    ]
    db = make_test_vault(tmp_path / "nested.kdbx", entries=entries_spec)
    extracted = read_kdbx_direct(db, password="test-master-password")
    assert len(extracted) == 2
    issuers = {e.issuer for e in extracted}
    assert "Root" in issuers
    assert "Deep" in issuers


def test_direct_read_recycle_bin_excluded(tmp_path):
    """Verifies that entries moved to the Recycle Bin are excluded."""
    entries_spec = [
        {"title": "Active", "otp": "otpauth://totp/Active:u?secret=JBSWY3DPEHPK3PXP"},
        {"title": "Deleted", "otp": "otpauth://totp/Deleted:u?secret=JBSWY3DPEHPK3PXP", "in_recycle_bin": True},
    ]
    db = make_test_vault(tmp_path / "bin_ex.kdbx", entries=entries_spec)
    extracted = read_kdbx_direct(db, password="test-master-password")
    assert len(extracted) == 1
    assert extracted[0].issuer == "Active"


def test_direct_read_recycle_bin_subgroups_excluded(tmp_path):
    """Verifies that entries inside subgroups of the Recycle Bin are excluded."""
    db_path = tmp_path / "bin_sub.kdbx"
    kp = pykeepass.create_database(str(db_path), password="test-master-password")
    hdr = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    hdr["I"].value = 1
    hdr["M"].value = 65536

    # Normal entry
    e_active = kp.add_entry(kp.root_group, "Active", "user", "pass")
    e_active.otp = "otpauth://totp/Active:u?secret=JBSWY3DPEHPK3PXP"

    # Trashed entry
    e_trash = kp.add_entry(kp.root_group, "ToTrash", "user", "pass")
    e_trash.otp = "otpauth://totp/Trash:u?secret=JBSWY3DPEHPK3PXP"
    kp.trash_entry(e_trash)

    # Subgroup inside recycle bin
    rb = kp.recyclebin_group
    if rb:
        sub_rb = kp.add_group(rb, "DeepTrash")
        e_sub_trash = kp.add_entry(sub_rb, "SubTrash", "user", "pass")
        e_sub_trash.otp = "otpauth://totp/SubTrash:u?secret=JBSWY3DPEHPK3PXP"

    kp.save()

    extracted = read_kdbx_direct(db_path, password="test-master-password")
    assert len(extracted) == 1
    assert extracted[0].issuer == "Active"


def test_direct_read_custom_excluded_groups(tmp_path):
    """Verifies custom excluded groups and their descendants are filtered out."""
    entries_spec = [
        {"title": "Normal", "group": "Personal", "otp": "otpauth://totp/Normal:u?secret=JBSWY3DPEHPK3PXP"},
        {"title": "Archived1", "group": "Archive", "otp": "otpauth://totp/Arch1:u?secret=JBSWY3DPEHPK3PXP"},
        {"title": "Archived2", "group": "Archive/2024", "otp": "otpauth://totp/Arch2:u?secret=JBSWY3DPEHPK3PXP"},
        {"title": "OldVault", "group": "Legacy", "otp": "otpauth://totp/Legacy:u?secret=JBSWY3DPEHPK3PXP"},
    ]
    db = make_test_vault(tmp_path / "custom_ex.kdbx", entries=entries_spec)
    extracted = read_kdbx_direct(
        db,
        password="test-master-password",
        excluded_groups=["Archive", "Legacy"],
    )
    assert len(extracted) == 1
    assert extracted[0].issuer == "Normal"


def test_direct_read_history_entries_excluded(tmp_path):
    """Verifies pykeepass excludes historical entry revisions."""
    db_path = tmp_path / "history.kdbx"
    kp = pykeepass.create_database(str(db_path), password="test-master-password")
    hdr = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    hdr["I"].value = 1
    hdr["M"].value = 65536

    entry = kp.add_entry(kp.root_group, "HistoricalService", "user", "pwd1")
    entry.otp = "otpauth://totp/Hist:u?secret=JBSWY3DPEHPK3PXP"
    kp.save()

    # Modify entry to trigger history generation
    kp_mod = pykeepass.PyKeePass(str(db_path), password="test-master-password")
    e = kp_mod.entries[0]
    e.password = "pwd2_modified"
    kp_mod.save()

    extracted = read_kdbx_direct(db_path, password="test-master-password")
    # Only the active entry should be returned, not historical duplicates
    assert len(extracted) == 1


# ==============================================================================
# Group E: Error Handling & Resilience
# ==============================================================================

def test_direct_read_wrong_password_raises_credentials_error(tmp_path):
    """Verifies wrong password raises KeePassCredentialsError."""
    db = make_test_vault(tmp_path / "wrong_pw.kdbx", password="RightPassword")
    with pytest.raises(KeePassCredentialsError) as exc_info:
        read_kdbx_direct(db, password="WrongPassword")
    assert isinstance(exc_info.value, KeePassXCError)


def test_direct_read_wrong_keyfile_raises_credentials_error(tmp_path):
    """Verifies wrong keyfile raises KeePassCredentialsError."""
    kf_right = make_keyfile(tmp_path / "right.key", fmt="binary")
    kf_wrong = make_keyfile(tmp_path / "wrong.key", fmt="binary")
    db = make_test_vault(tmp_path / "wrong_kf.kdbx", password="pw", keyfile_path=kf_right)

    with pytest.raises(KeePassCredentialsError):
        read_kdbx_direct(db, password="pw", keyfile_path=kf_wrong)


def test_direct_read_missing_db_raises_not_found(tmp_path):
    """Verifies non-existent database file raises KeePassXCError."""
    non_existent = tmp_path / "does_not_exist.kdbx"
    with pytest.raises(KeePassXCError, match="database not found"):
        read_kdbx_direct(non_existent, password="pw")


def test_direct_read_missing_keyfile_raises_not_found(tmp_path):
    """Verifies non-existent keyfile raises KeePassXCError."""
    db = make_test_vault(tmp_path / "db.kdbx", password="pw")
    non_existent_kf = tmp_path / "does_not_exist.key"
    with pytest.raises(KeePassXCError, match="Keyfile not found"):
        read_kdbx_direct(db, password="pw", keyfile_path=non_existent_kf)


def test_direct_read_corrupted_header_raises_error(tmp_path):
    """Verifies corrupted header bytes raise KeePassCorruptedError."""
    corrupted = tmp_path / "bad_header.kdbx"
    corrupted.write_bytes(b"NOT_A_KEEPASS_DATABASE_HEADER_XYZ")
    with pytest.raises(KeePassCorruptedError):
        read_kdbx_direct(corrupted, password="pw")


def test_direct_read_corrupted_payload_raises_error(tmp_path):
    """Verifies corrupted database payload raises KeePassCorruptedError."""
    db = make_test_vault(tmp_path / "bad_payload.kdbx", password="pw")
    data = bytearray(db.read_bytes())
    # Corrupt last 64 bytes of payload
    for i in range(len(data) - 64, len(data)):
        data[i] ^= 0xAA
    db.write_bytes(data)

    with pytest.raises(KeePassCorruptedError):
        read_kdbx_direct(db, password="pw")


def test_direct_read_zero_byte_file_raises_error(tmp_path):
    """Verifies zero-byte file raises KeePassCorruptedError."""
    empty_file = tmp_path / "empty.kdbx"
    empty_file.write_bytes(b"")
    with pytest.raises(KeePassCorruptedError):
        read_kdbx_direct(empty_file, password="pw")


def test_direct_read_unsupported_kdf_raises_error(tmp_path):
    """Verifies corrupted/unsupported KDF raises KeePassCorruptedError or KeePassXCError."""
    db = make_test_vault(tmp_path / "bad_kdf.kdbx", password="pw")
    data = bytearray(db.read_bytes())
    argon2_uuid = kdf_uuids["argon2"]
    assert argon2_uuid in data
    # Mutate KDF UUID to invalid garbage
    data = data.replace(argon2_uuid, b"\x00" * 16, 1)
    db.write_bytes(data)

    with pytest.raises((KeePassCorruptedError, KeePassXCError)):
        read_kdbx_direct(db, password="pw")


# ==============================================================================
# Group F: Memory Scrubbing & Lifecycle Security
# ==============================================================================

def test_direct_read_memory_scrubbing_lifecycle(tmp_path):
    """Verifies PyKeePass instance is cleanly deallocated and garbage collected on exit."""
    db = make_test_vault(tmp_path / "scrub_ok.kdbx", password="MasterSecretPassword")
    captured = {}
    orig_pykeepass = pykeepass.PyKeePass

    def spy_pykeepass(*args, **kwargs):
        inst = orig_pykeepass(*args, **kwargs)
        captured["ref"] = weakref.ref(inst)
        return inst

    with patch("pykeepass.PyKeePass", side_effect=spy_pykeepass):
        entries = read_kdbx_direct(db, password="MasterSecretPassword")
        assert len(entries) == 0

    assert captured.get("ref") is not None
    assert captured["ref"]() is None, "PyKeePass instance was not garbage collected!"


def test_direct_read_memory_scrubbing_on_exception(tmp_path):
    """Verifies references are purged even when decryption fails with an exception."""
    db = make_test_vault(tmp_path / "scrub_err.kdbx", password="CorrectPassword")
    captured = {}
    orig_pykeepass = pykeepass.PyKeePass

    def spy_pykeepass(*args, **kwargs):
        inst = orig_pykeepass(*args, **kwargs)
        captured["ref"] = weakref.ref(inst)
        return inst

    with patch("pykeepass.PyKeePass", side_effect=spy_pykeepass):
        with pytest.raises(KeePassXCError):
            read_kdbx_direct(db, password="WrongPassword")

    assert captured.get("ref") is None or captured["ref"]() is None


def test_direct_read_internal_buffer_zeroed():
    """Verifies scrub_bytes properly zeroes mutable memoryview and bytearray."""
    data = bytearray(b"SecretCredentialsBuffer123")
    assert any(b != 0 for b in data)
    scrub_bytes(data)
    assert all(b == 0 for b in data)

    # Test with memoryview
    mv_data = bytearray(b"AnotherSecretBuffer")
    mv = memoryview(mv_data)
    scrub_bytes(mv)
    assert all(b == 0 for b in mv_data)


# ==============================================================================
# Group G: Hybrid Facade Routing
# ==============================================================================

def test_hybrid_routing_auto_without_yubikey(tmp_path):
    """Verifies backend='auto' without YubiKey dispatches to read_kdbx_direct."""
    db = make_test_vault(tmp_path / "route1.kdbx")
    with patch("t2_kpxc_sync.kpxc.read_kdbx_direct") as mock_direct:
        mock_direct.return_value = []
        read_kpxc_entries(db, password="p", yubikey_slot=None, backend="auto")
        assert mock_direct.called


def test_hybrid_routing_auto_with_yubikey(tmp_path):
    """Verifies backend='auto' with YubiKey dispatches to read_kpxc_entries_cli."""
    db = make_test_vault(tmp_path / "route2.kdbx")
    with patch("t2_kpxc_sync.kpxc.read_kpxc_entries_cli") as mock_cli:
        mock_cli.return_value = []
        read_kpxc_entries(db, password="p", yubikey_slot=1, backend="auto")
        assert mock_cli.called


def test_hybrid_routing_direct_explicit(tmp_path):
    """Verifies backend='direct' dispatches to read_kdbx_direct."""
    db = make_test_vault(tmp_path / "route3.kdbx")
    with patch("t2_kpxc_sync.kpxc.read_kdbx_direct") as mock_direct:
        mock_direct.return_value = []
        read_kpxc_entries(db, password="p", backend="direct")
        assert mock_direct.called


def test_hybrid_routing_direct_with_yubikey_raises(tmp_path):
    """Verifies backend='direct' with YubiKey raises KeePassXCError."""
    db = make_test_vault(tmp_path / "route4.kdbx")
    with pytest.raises(KeePassXCError, match="YubiKey"):
        read_kpxc_entries(db, password="p", yubikey_slot=1, backend="direct")


def test_hybrid_routing_cli_explicit(tmp_path):
    """Verifies backend='cli' dispatches to read_kpxc_entries_cli."""
    db = make_test_vault(tmp_path / "route5.kdbx")
    with patch("t2_kpxc_sync.kpxc.read_kpxc_entries_cli") as mock_cli:
        mock_cli.return_value = []
        read_kpxc_entries(db, password="p", backend="cli")
        assert mock_cli.called


def test_hybrid_routing_invalid_backend_raises(tmp_path):
    """Verifies invalid backend name raises ValueError."""
    db = make_test_vault(tmp_path / "route6.kdbx")
    with pytest.raises(ValueError, match="Invalid backend"):
        read_kpxc_entries(db, password="p", backend="unsupported_backend")
