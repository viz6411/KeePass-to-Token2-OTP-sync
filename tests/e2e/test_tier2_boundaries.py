"""Tier 2: Boundary & Corner Cases (Chaos, Fault Injection & Edge Conditions).

Tests boundary behaviors across:
- KDBX edge cases (empty vault, 100+ entries, corrupted files, zero bytes, unicode)
- Token2 protocol limits (300 capacity limit, empty token, disconnect, wrong PIN, button polling)
- TUI & CLI edge conditions (EOF on prompt, invalid choices, non-interactive fallback, narrow width)
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from t2_kpxc_sync.cli import (
    apply_sync,
    display_diff_table,
    main,
    run_interactive_menu,
)
from t2_kpxc_sync.diff import TOKEN2_MAX_CAPACITY, DiffResult, compute_diff
from t2_kpxc_sync.kpxc import (
    KeePassCorruptedError,
    KeePassCredentialsError,
    KeePassXCError,
    read_kdbx_direct,
    read_kpxc_entries,
)
from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.token2 import (
    Token2Adapter,
    Token2DirectClient,
    Token2Error,
    Token2MemoryFullError,
    Token2PINError,
    Token2TimeoutError,
    Token2TransportError,
)
from tests.e2e.conftest import SimulatedToken2HIDDevice
from tests.e2e.fixtures.kdbx_factory import KDBXFactory
from tests.e2e.harness import run_cli_subprocess, run_interactive_session, strip_ansi


# ============================================================================
# 1. KDBX Reader Boundaries & Fault Injection
# ============================================================================

def test_t2_kdbx_empty_vault(tmp_path: Path):
    """Verifies that an empty database (0 entries) returns an empty list without error."""
    vault = tmp_path / "empty.kdbx"
    KDBXFactory.create_vault(vault, password="empty_password")
    entries = read_kdbx_direct(vault, password="empty_password")
    assert entries == []


def test_t2_kdbx_non_totp_entries_only(tmp_path: Path):
    """Verifies that a vault containing 50 standard login entries with 0 OTP returns []."""
    vault = tmp_path / "login_only.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")
    for i in range(50):
        KDBXFactory.add_standard_entry(kp, title=f"Website_{i}", username=f"user_{i}", save=False)
    kp.save()
    entries = read_kdbx_direct(vault, password="pwd")
    assert len(entries) == 0


def test_t2_kdbx_unicode_emojis_cyrillic(tmp_path: Path):
    """Verifies that Cyrillic titles, emojis, and non-ASCII passwords preserve UTF-8."""
    vault = tmp_path / "unicode.kdbx"
    kp = KDBXFactory.create_vault(vault, password="Пароль_🔑_123!")

    KDBXFactory.add_otpauth_entry(
        kp,
        title="Госуслуги 🇷🇺",
        username="иван@домен.рф",
        secret="JBSWY3DPEHPK3PXP",
        issuer="Госуслуги 🇷🇺",
    )
    KDBXFactory.add_otpauth_entry(
        kp,
        title="微信支付 🧧",
        username="用户123",
        secret="GEZDGNBVGY3TQOJQ",
        issuer="微信支付 🧧",
    )

    entries = read_kdbx_direct(vault, password="Пароль_🔑_123!")
    assert len(entries) == 2
    e_cyrillic = next(e for e in entries if "Госуслуги" in e.issuer)
    assert e_cyrillic.account == "иван@домен.рф"
    assert e_cyrillic.issuer == "Госуслуги 🇷🇺"

    e_emoji = next(e for e in entries if "微信支付" in e.issuer)
    assert e_emoji.issuer == "微信支付 🧧"


def test_t2_kdbx_large_vault_150_entries(tmp_path: Path):
    """Verifies high-volume vault containing 150 entries (100 TOTP + 50 standard)."""
    vault = tmp_path / "large_vault.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")

    for i in range(50):
        KDBXFactory.add_otpauth_entry(
            kp,
            title=f"StandardService_{i}",
            username=f"user_{i}",
            secret="JBSWY3DPEHPK3PXP",
            save=False,
        )
    for i in range(50):
        KDBXFactory.add_timeotp_entry(
            kp,
            title=f"TimeOtpService_{i}",
            username=f"user_{i}",
            secret="GEZDGNBVGY3TQOJQ",
            save=False,
        )
    for i in range(50):
        KDBXFactory.add_standard_entry(
            kp,
            title=f"LoginOnly_{i}",
            username=f"user_{i}",
            save=False,
        )
    kp.save()

    entries = read_kdbx_direct(vault, password="pwd")
    assert len(entries) == 100


def test_t2_kdbx_invalid_password(tmp_path: Path):
    """Verifies that an incorrect password raises KeePassCredentialsError."""
    vault = tmp_path / "valid.kdbx"
    KDBXFactory.create_vault(vault, password="correct_password")

    with pytest.raises(KeePassCredentialsError):
        read_kdbx_direct(vault, password="wrong_password")


def test_t2_kdbx_corrupted_header(tmp_path: Path):
    """Verifies that tampered KDBX magic header bytes raise KeePassCorruptedError."""
    vault = tmp_path / "corrupt_hdr.kdbx"
    KDBXFactory.create_vault(vault, password="pwd")
    KDBXFactory.corrupt_file_header(vault)

    with pytest.raises(KeePassCorruptedError):
        read_kdbx_direct(vault, password="pwd")


def test_t2_kdbx_corrupted_payload(tmp_path: Path):
    """Verifies that tampered ciphertext bytes raise KeePassCorruptedError."""
    vault = tmp_path / "corrupt_payload.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")
    KDBXFactory.add_otpauth_entry(kp, title="PayloadTest")
    KDBXFactory.corrupt_file_payload(vault)

    with pytest.raises(KeePassCorruptedError):
        read_kdbx_direct(vault, password="pwd")


def test_t2_kdbx_zero_byte_file(tmp_path: Path):
    """Verifies that an empty 0-byte file raises KeePassCorruptedError or KeePassXCError."""
    empty_file = tmp_path / "zero.kdbx"
    empty_file.write_bytes(b"")

    with pytest.raises((KeePassCorruptedError, KeePassXCError)):
        read_kdbx_direct(empty_file, password="pwd")


def test_t2_kdbx_nonexistent_file(tmp_path: Path):
    """Verifies that a non-existent database file raises KeePassXCError."""
    non_existent = tmp_path / "does_not_exist.kdbx"
    with pytest.raises(KeePassXCError, match="KeePassXC database not found"):
        read_kdbx_direct(non_existent, password="pwd")


def test_t2_kdbx_nonexistent_keyfile(tmp_path: Path):
    """Verifies that a non-existent keyfile path raises KeePassXCError."""
    vault = tmp_path / "vault_keyfile.kdbx"
    KDBXFactory.create_vault(vault, password="pwd")
    fake_keyfile = tmp_path / "missing.key"

    with pytest.raises(KeePassXCError, match="Keyfile not found"):
        read_kdbx_direct(vault, password="pwd", keyfile_path=fake_keyfile)


# ============================================================================
# 2. Token2 Protocol Boundaries & Hardware Edge Conditions
# ============================================================================

def test_t2_token2_capacity_exhaustion(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies that provisioning beyond max capacity raises Token2MemoryFullError."""
    client = Token2DirectClient()
    client.open()
    try:
        # Pre-seed simulated token to max capacity (limit = 5 for test speed)
        mock_token2_hid.max_capacity = 3
        for i in range(3):
            client.write_entry(f"App_{i}", f"user_{i}", "JBSWY3DPEHPK3PXP")

        assert len(client.list_entries()) == 3

        # Writing the 4th entry must trigger 0x6A84 memory full
        with pytest.raises(Token2MemoryFullError):
            client.write_entry("OverflowApp", "user", "GEZDGNBVGY3TQOJQ")

        # Existing 3 entries remain untouched
        assert len(client.list_entries()) == 3
    finally:
        client.close()


def test_t2_token2_empty_device(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies that querying an unprovisioned empty device returns [] without error."""
    client = Token2DirectClient()
    client.open()
    try:
        entries = client.list_entries()
        assert entries == []
    finally:
        client.close()


def test_t2_token2_disconnect_mid_transfer(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies that USB disconnection raises transport error without hang."""
    client = Token2DirectClient()
    client.open()
    mock_token2_hid.disconnect()
    with pytest.raises((Token2TransportError, IOError)):
        client.write_entry("DisconnectApp", "user", "JBSWY3DPEHPK3PXP")
    mock_token2_hid.reconnect()


def test_t2_token2_pin_wrong_pin_abort(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies that wrong PIN verification fails and preserves retry counter."""
    mock_token2_hid.pin = "123456"
    mock_token2_hid.is_pin_verified = False

    client = Token2DirectClient()
    client.open()
    try:
        # Send verify PIN APDU with wrong PIN
        from t2_kpxc_sync.token2 import parse_status_word
        wrong_pin_apdu = bytes([0x80, 0xC5, 0x05, 0x06, 0x06]) + b"000000"
        resp = client.transport.send_apdu(wrong_pin_apdu)
        _, sw = parse_status_word(resp)
        # 0x63CX indicating attempts remaining
        assert (sw >> 8) == 0x63
        assert mock_token2_hid.pin_attempts_remaining == 9
        assert not mock_token2_hid.is_pin_verified
    finally:
        client.close()


def test_t2_token2_device_without_pin(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies that device without PIN configured allows operations seamlessly."""
    mock_token2_hid.pin = None
    mock_token2_hid.is_pin_verified = True

    client = Token2DirectClient()
    client.open()
    try:
        client.write_entry("NoPinApp", "user", "JBSWY3DPEHPK3PXP")
        profiles = client.list_entries()
        assert len(profiles) == 1
        assert profiles[0].issuer == "NoPinApp"
    finally:
        client.close()


def test_t2_token2_invalid_secret_base32(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies that malformed base32 seed is rejected at the domain boundary."""
    client = Token2DirectClient()
    client.open()
    try:
        with pytest.raises(ValueError, match="Invalid Base32 secret"):
            client.write_entry("InvalidApp", "user", "1890InvalidBase32Symbols!@#")
    finally:
        client.close()


def test_t2_token2_touch_button_polling(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies that transport cleanly polls 0xC0 frames before returning response."""
    mock_token2_hid.touch_polling_ticks = 2
    client = Token2DirectClient()
    client.open()
    try:
        # Polling countdown should complete after 2 ticks
        info = client.get_info()
        assert info == mock_token2_hid.serial_number
    finally:
        client.close()


def test_t2_token2_short_apdu_rejected_with_6ffb(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies that 4-byte short APDU without extended Lc returns 0x6FFB, while extended APDU succeeds."""
    from t2_kpxc_sync.token2 import HIDTransport, parse_status_word

    transport = HIDTransport()
    transport.open()
    try:
        # 1. 4-byte short APDU without extended Lc is rejected by hardware simulation with SW 0x6FFB
        short_apdu = bytes.fromhex("80C50100")
        resp_short = transport.send_apdu(short_apdu)
        _, sw_short = parse_status_word(resp_short)
        assert sw_short == 0x6FFB

        # 2. 7-byte extended APDU with Lc 00 00 00 succeeds with SW 0x9000
        extended_apdu = bytes.fromhex("80C50100000000")
        resp_ext = transport.send_apdu(extended_apdu)
        data_ext, sw_ext = parse_status_word(resp_ext)
        assert sw_ext == 0x9000
        assert len(data_ext) == 64
    finally:
        transport.close()


# ============================================================================
# 3. TUI & CLI Boundaries
# ============================================================================

def test_t2_tui_prompt_eof_handling():
    """Verifies that empty input / EOF on interactive menu defaults safely to Cancel (4)."""
    with run_interactive_session("") as (si, so, se):
        res = run_interactive_menu()
        assert res == "4"


def test_t2_tui_menu_invalid_choices_recovery():
    """Verifies that unrecognized modes in apply_sync cleanly perform 0 operations."""
    mock_adapter = MagicMock()
    diff = DiffResult(to_add=[TOTPEntry(issuer="A", account="u", secret="S")])
    ops = apply_sync(mock_adapter, diff, [], mode="invalid_mode_99")
    assert ops == 0
    mock_adapter.write_entry.assert_not_called()


def test_t2_tui_non_interactive_stdin_fallback(tmp_path: Path):
    """Verifies that running without --db or config in non-interactive environment exits 1."""
    res = run_cli_subprocess([])
    assert res.exit_code == 1
    assert "Error: No KeePassXC database specified" in res.clean_text


def test_t2_tui_terminal_narrow_width_overflow():
    """Verifies that narrow terminal width (40 columns) renders without Rich crash."""
    entry_add = TOTPEntry(issuer="VeryLongEnterpriseServiceNameHere", account="verylonguseremailaddress@subdomain.example.com", secret="JBSWY3DPEHPK3PXP")
    diff = DiffResult(to_add=[entry_add], final_slot_count=1)

    with run_interactive_session([], width=40) as (si, so, se):
        display_diff_table(diff, total_current_slots=0)
        out = strip_ansi(so.getvalue())
        assert "ADD" in out
        assert "Summary" in out


def test_t2_diff_capacity_exceeded_guard():
    """Verifies that 301 entries against 300-slot token triggers capacity exceeded flag."""
    entries_kpxc = [
        TOTPEntry(issuer=f"Svc_{i}", account=f"acct_{i}", secret="JBSWY3DPEHPK3PXP")
        for i in range(301)
    ]
    diff = compute_diff(entries_kpxc, [])
    assert diff.final_slot_count == 301
    assert diff.is_capacity_exceeded is True

    # Attempting apply_sync on exceeded capacity raises Token2Error
    mock_adapter = MagicMock()
    with pytest.raises(Token2Error, match="exceeds hardware limit 300"):
        apply_sync(mock_adapter, diff, [], mode="add_only")


def test_t2_cli_invalid_mode_argument():
    """Verifies that an unrecognized --mode argument is rejected by argparse with exit 2."""
    res = run_cli_subprocess(["--mode", "non_existent_mode_xyz"])
    assert res.exit_code == 2
    assert "invalid choice" in res.clean_stderr
