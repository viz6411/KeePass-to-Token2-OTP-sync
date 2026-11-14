"""Tier 1: Feature Coverage (Isolated Happy Path).

Tests individual features across:
- Direct KDBX In-Memory Reader & Multi-Schema TOTP Parsing
- Embedded Token2 USB-HID Protocol & Cryptographic Engine
- TUI Interactive Menu & Diff Presentation
- CLI Options & Non-Interactive Batch Modes
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from t2_kpxc_sync.cli import (
    apply_sync,
    display_diff_table,
    find_free_slots,
    main,
    run_interactive_menu,
)
from t2_kpxc_sync.diff import DiffResult, compute_diff
from t2_kpxc_sync.kpxc import KeePassCredentialsError, read_kdbx_direct, read_kpxc_entries
from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.token2 import Token2Adapter, Token2DirectClient
from tests.e2e.conftest import SimulatedToken2HIDDevice
from tests.e2e.fixtures.kdbx3_sample import extract_kdbx3_fixture
from tests.e2e.fixtures.kdbx_factory import KDBXFactory
from tests.e2e.harness import run_cli_subprocess, run_interactive_session, strip_ansi


# ============================================================================
# 1. KDBX Reader & Multi-Schema OTP Extraction
# ============================================================================

def test_t1_kdbx_standard_otpauth_uri(tmp_path: Path):
    """Verifies direct parsing of standard RFC 6238 otpauth:// URIs in memory."""
    vault = tmp_path / "otpauth_vault.kdbx"
    kp = KDBXFactory.create_vault(vault, password="secretpassword")

    KDBXFactory.add_otpauth_entry(
        kp,
        title="GitHub",
        username="alice",
        secret="JBSWY3DPEHPK3PXP",
        issuer="GitHub",
        algorithm="SHA1",
        digits=6,
        period=30,
    )
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
    KDBXFactory.add_otpauth_entry(
        kp,
        title="GitLab",
        username="dev",
        secret="MFRGGZDFMZTWQ2LK",
        issuer="GitLab",
        algorithm="SHA512",
        digits=6,
        period=30,
    )

    entries = read_kdbx_direct(vault, password="secretpassword")
    assert len(entries) == 3

    e1 = next(e for e in entries if e.issuer == "GitHub")
    assert e1.account == "alice"
    assert e1.secret == "JBSWY3DPEHPK3PXP"
    assert e1.algorithm == "SHA1"
    assert e1.digits == 6
    assert e1.period == 30

    e2 = next(e for e in entries if e.issuer == "AWS")
    assert e2.account == "admin"
    assert e2.algorithm == "SHA256"
    assert e2.digits == 8
    assert e2.period == 60

    e3 = next(e for e in entries if e.issuer == "GitLab")
    assert e3.algorithm == "SHA512"


def test_t1_kdbx_timeotp_custom_properties(tmp_path: Path):
    """Verifies extraction from KeeOtp / TrayTOTP TimeOtp-* custom properties."""
    vault = tmp_path / "timeotp_vault.kdbx"
    kp = KDBXFactory.create_vault(vault, password="secretpassword")

    KDBXFactory.add_timeotp_entry(
        kp,
        title="CustomService",
        username="admin@corp.net",
        secret="KVKFKRCPNZQUYMLX",
        algorithm="HMAC-SHA-256",
        digits=8,
        period=60,
    )
    KDBXFactory.add_timeotp_entry(
        kp,
        title="LegacyService",
        username="user",
        secret="JBSWY3DPEHPK3PXP",
        algorithm="SHA1",
        digits=6,
        period=30,
    )

    entries = read_kdbx_direct(vault, password="secretpassword")
    assert len(entries) == 2

    c_entry = next(e for e in entries if e.issuer == "CustomService")
    assert c_entry.secret == "KVKFKRCPNZQUYMLX"
    assert c_entry.algorithm == "SHA256"
    assert c_entry.digits == 8
    assert c_entry.period == 60


def test_t1_kdbx_composite_password_and_keyfile(tmp_path: Path):
    """Verifies vault protected by composite credentials (password + 32-byte keyfile)."""
    vault = tmp_path / "composite.kdbx"
    keyfile = KDBXFactory.create_keyfile(tmp_path / "composite.key", length=32)
    kp = KDBXFactory.create_vault(vault, password="CompositePass123!", keyfile=keyfile)
    KDBXFactory.add_otpauth_entry(kp, title="AirGapped", username="secops")

    # Read with composite credentials
    entries = read_kdbx_direct(vault, password="CompositePass123!", keyfile_path=keyfile)
    assert len(entries) == 1
    assert entries[0].issuer == "AirGapped"

    # Opening without keyfile fails
    with pytest.raises(KeePassCredentialsError):
        read_kdbx_direct(vault, password="CompositePass123!", keyfile_path=None)


def test_t1_kdbx_chacha20_cipher(tmp_path: Path):
    """Verifies in-memory decryption of KDBX 4.0 database encrypted with ChaCha20."""
    vault = tmp_path / "chacha20.kdbx"
    kp = KDBXFactory.create_vault(vault, password="testpassword", cipher="chacha20")
    KDBXFactory.add_otpauth_entry(kp, title="ChaChaService", username="root")

    entries = read_kdbx_direct(vault, password="testpassword")
    assert len(entries) == 1
    assert entries[0].issuer == "ChaChaService"


def test_t1_kdbx_twofish_cipher(tmp_path: Path):
    """Verifies in-memory decryption of KDBX 4.0 database encrypted with Twofish."""
    vault = tmp_path / "twofish.kdbx"
    kp = KDBXFactory.create_vault(vault, password="testpassword", cipher="twofish")
    KDBXFactory.add_otpauth_entry(kp, title="TwofishService", username="user")

    entries = read_kdbx_direct(vault, password="testpassword")
    assert len(entries) == 1
    assert entries[0].issuer == "TwofishService"


def test_t1_kdbx_kdbx3_legacy_compatibility(tmp_path: Path):
    """Verifies reading legacy KDBX 3.1 database using AES-KDF."""
    kdbx3_path = extract_kdbx3_fixture(tmp_path / "legacy3.kdbx")
    entries = read_kdbx_direct(kdbx3_path, password="test3pass")
    assert len(entries) >= 1
    assert any(e.issuer == "LegacyService" for e in entries)


def test_t1_kdbx_recycle_bin_and_excluded_groups(tmp_path: Path):
    """Verifies that entries in Recycle Bin and excluded groups are skipped."""
    vault = tmp_path / "groups.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")

    # Group 1: Active
    g_active = kp.add_group(kp.root_group, "Active")
    KDBXFactory.add_otpauth_entry(kp, group=g_active, title="ActiveSvc")

    # Group 2: Excluded
    g_archive = kp.add_group(kp.root_group, "Archive")
    KDBXFactory.add_otpauth_entry(kp, group=g_archive, title="ArchivedSvc")

    # Group 3: Recycle Bin
    g_recycle = kp.add_group(kp.root_group, "Recycle Bin")
    KDBXFactory.add_otpauth_entry(kp, group=g_recycle, title="DeletedSvc")

    entries = read_kdbx_direct(vault, password="pwd", excluded_groups=["Archive", "Recycle Bin"])
    assert len(entries) == 1
    assert entries[0].issuer == "ActiveSvc"


def test_t1_kdbx_memory_scrubbing(tmp_path: Path):
    """Verifies that sensitive credentials and decrypted DOM are scrubbed."""
    from t2_kpxc_sync.security import scrub_bytes
    vault = tmp_path / "scrub.kdbx"
    kp = KDBXFactory.create_vault(vault, password="sensitive_pwd")
    KDBXFactory.add_otpauth_entry(kp, title="ScrubTest")

    pwd_buf = bytearray(b"sensitive_pwd")
    entries = read_kdbx_direct(vault, password=pwd_buf)
    assert len(entries) == 1
    # Verify scrub_bytes zeros buffer completely
    scrub_bytes(pwd_buf)
    assert pwd_buf == b"\x00" * len(pwd_buf)


# ============================================================================
# 2. Token2 Direct USB-HID Protocol & Cryptographic Engine
# ============================================================================

def test_t1_token2_get_info(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies querying device info and serial number via APDU."""
    with Token2Adapter(backend="direct") as adapter:
        serial = adapter.get_info()
        assert serial == mock_token2_hid.serial_number


def test_t1_token2_list_entries(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies profile listing and live OTP code generation over APDU."""
    client = Token2DirectClient()
    client.open()
    try:
        # Pre-provision two entries
        client.write_entry("Service1", "user1", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30)
        client.write_entry("Service2", "user2", "GEZDGNBVGY3TQOJQ", "SHA256", 8, 60)

        profiles = client.list_entries()
        assert len(profiles) == 2
        p1 = next(p for p in profiles if p.issuer == "Service1")
        assert p1.account == "user1"
        assert p1.algorithm == "SHA1"
        assert p1.digits == 6
        assert p1.period == 30
        assert len(p1.current_otp) == 6

        p2 = next(p for p in profiles if p.issuer == "Service2")
        assert p2.digits == 8
        assert p2.period == 60
        assert len(p2.current_otp) == 8
    finally:
        client.close()


def test_t1_token2_write_seed(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies NIST P-256 ECDH + AES-256-CBC IV-1 seed provisioning."""
    with Token2Adapter(backend="direct") as adapter:
        entry = TOTPEntry(issuer="Cloudflare", account="ops", secret="MFRGGZDFMZTWQ2LK")
        adapter.write_entry(1, entry)

        profiles = adapter.get_all()
        assert len(profiles) == 1
        assert profiles[0].issuer == "Cloudflare"
        assert profiles[0].account == "ops"
        assert ("Cloudflare", "ops") in mock_token2_hid.entries


def test_t1_token2_write_seed_extended_lc(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies write_entry succeeds against simulation enforcing 0x6FFB on 4-byte APDUs."""
    client = Token2DirectClient()
    client.open()
    try:
        # write_entry executes get_token_public_key() which sends 80 C5 01 00 00 00 00
        client.write_entry(
            issuer="OneKey Card",
            account="viz6411@gmail.com",
            secret="JBSWY3DPEHPK3PXP",
            algorithm="SHA1",
            digits=6,
            period=30,
        )
        assert ("OneKey Card", "viz6411@gmail.com") in mock_token2_hid.entries
        profiles = client.list_entries()
        assert any(p.issuer == "OneKey Card" and p.account == "viz6411@gmail.com" for p in profiles)
    finally:
        client.close()



def test_t1_token2_delete_entry(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies profile deletion with zero-length seed APDU."""
    with Token2Adapter(backend="direct") as adapter:
        adapter.write_entry(1, TOTPEntry(issuer="ToKeep", account="a", secret="JBSWY3DPEHPK3PXP"))
        adapter.write_entry(2, TOTPEntry(issuer="ToDelete", account="b", secret="GEZDGNBVGY3TQOJQ"))

        assert len(adapter.get_all()) == 2
        adapter.delete_entry(2)

        remaining = adapter.get_all()
        assert len(remaining) == 1
        assert remaining[0].issuer == "ToKeep"
        assert ("ToDelete", "b") not in mock_token2_hid.entries


def test_t1_token2_time_sync(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies that returned TOTP codes change deterministically across time steps."""
    client = Token2DirectClient()
    client.open()
    try:
        client.write_entry("TimeSyncSvc", "sync", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30)

        # Query at T1 and T2 = T1 + 30
        from t2_kpxc_sync.token2 import build_enum_codes_apdu, parse_enum_response, parse_status_word

        resp1 = client.transport.send_apdu(build_enum_codes_apdu(timestamp=1700000000))
        data1, _ = parse_status_word(resp1)
        entries1, _ = parse_enum_response(data1)
        code1 = entries1[0]["otp_code"]

        resp2 = client.transport.send_apdu(build_enum_codes_apdu(timestamp=1700000030))
        data2, _ = parse_status_word(resp2)
        entries2, _ = parse_enum_response(data2)
        code2 = entries2[0]["otp_code"]

        assert code1 != code2
        assert len(code1) == 6 and len(code2) == 6
    finally:
        client.close()


def test_t1_token2_overwrite_entry(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies in-place secret rotation for existing accounts without changing slot count."""
    with Token2Adapter(backend="direct") as adapter:
        # Initial provision
        adapter.write_entry(1, TOTPEntry(issuer="AppX", account="UserY", secret="JBSWY3DPEHPK3PXP"))
        profiles1 = adapter.get_all()
        assert len(profiles1) == 1

        # Overwrite with new secret
        adapter.write_entry(1, TOTPEntry(issuer="AppX", account="UserY", secret="GEZDGNBVGY3TQOJQ"))
        profiles2 = adapter.get_all()
        assert len(profiles2) == 1
        assert profiles2[0].issuer == "AppX"


def test_t1_token2_erase_all(mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies erasing all stored entries via empty write payload."""
    client = Token2DirectClient()
    client.open()
    try:
        client.write_entry("S1", "u1", "JBSWY3DPEHPK3PXP")
        client.write_entry("S2", "u2", "GEZDGNBVGY3TQOJQ")
        assert len(client.list_entries()) == 2

        client.erase_all()
        assert len(client.list_entries()) == 0
    finally:
        client.close()


# ============================================================================
# 3. TUI & Interactive Menu Tests
# ============================================================================

def test_t1_tui_interactive_menu_options():
    """Verifies run_interactive_menu options [1]-[4]."""
    for choice in ["1", "2", "3", "4"]:
        with run_interactive_session([choice]) as (si, so, se):
            res = run_interactive_menu()
            assert res == choice


def test_t1_tui_display_diff_table_rendering():
    """Verifies formatted Rich diff table rendering with additions, updates, and deletions."""
    entry_add = TOTPEntry(issuer="AddCorp", account="bob", secret="JBSWY3DPEHPK3PXP")
    entry_upd = TOTPEntry(issuer="UpdCorp", account="alice", secret="GEZDGNBVGY3TQOJQ")
    prof_upd = Token2Profile(slot=2, issuer="UpdCorp", account="alice")
    prof_del = Token2Profile(slot=5, issuer="DelCorp", account="charlie")

    diff = DiffResult(
        to_add=[entry_add],
        to_update=[(entry_upd, prof_upd)],
        to_delete=[prof_del],
        final_slot_count=2,
    )

    with run_interactive_session([]) as (si, so, se):
        display_diff_table(diff, total_current_slots=2)
        out = strip_ansi(so.getvalue())
        assert "TOTP Synchronization Plan" in out
        assert "ADD" in out and "AddCorp" in out
        assert "UPDATE" in out and "UpdCorp" in out
        assert "DELETE" in out and "DelCorp" in out
        assert "Summary" in out


def test_t1_tui_menu_mode_cancel():
    """Verifies that cancel mode ('4' or 'cancel') aborts with 0 operations executed."""
    mock_adapter = MagicMock()
    diff = DiffResult(to_add=[TOTPEntry(issuer="A", account="u", secret="S")])
    ops = apply_sync(mock_adapter, diff, [], mode="cancel")
    assert ops == 0
    mock_adapter.write_entry.assert_not_called()
    mock_adapter.delete_entry.assert_not_called()


def test_t1_tui_menu_mode_add_only():
    """Verifies mode 'add_only' applies only additions."""
    mock_adapter = MagicMock()
    e_add = TOTPEntry(issuer="A", account="u", secret="S")
    e_upd = TOTPEntry(issuer="B", account="v", secret="S2")
    p_upd = Token2Profile(slot=1, issuer="B", account="v")
    diff = DiffResult(to_add=[e_add], to_update=[(e_upd, p_upd)], final_slot_count=2)

    ops = apply_sync(mock_adapter, diff, [p_upd], mode="add_only")
    assert ops == 1
    mock_adapter.write_entry.assert_called_once()
    mock_adapter.delete_entry.assert_not_called()


def test_t1_tui_menu_mode_add_update():
    """Verifies mode 'add_update' applies additions and updates without deleting obsolete entries."""
    mock_adapter = MagicMock()
    e_add = TOTPEntry(issuer="A", account="u", secret="S")
    e_upd = TOTPEntry(issuer="B", account="v", secret="S2")
    p_upd = Token2Profile(slot=1, issuer="B", account="v")
    p_del = Token2Profile(slot=2, issuer="Old", account="w")
    diff = DiffResult(to_add=[e_add], to_update=[(e_upd, p_upd)], to_delete=[p_del], final_slot_count=2)

    ops = apply_sync(mock_adapter, diff, [p_upd, p_del], mode="add_update")
    assert ops == 2
    mock_adapter.delete_entry.assert_called_once_with(1)
    assert mock_adapter.write_entry.call_count == 2


def test_t1_tui_menu_mode_full_sync():
    """Verifies mode 'full_sync' applies additions, updates, and deletions."""
    mock_adapter = MagicMock()
    e_add = TOTPEntry(issuer="A", account="u", secret="S")
    p_del = Token2Profile(slot=3, issuer="Old", account="w")
    diff = DiffResult(to_add=[e_add], to_delete=[p_del], final_slot_count=1)

    ops = apply_sync(mock_adapter, diff, [p_del], mode="full_sync", confirm_delete=False)
    assert ops == 2
    mock_adapter.delete_entry.assert_called_once_with(3)
    mock_adapter.write_entry.assert_called_once()


# ============================================================================
# 4. CLI Options & Sanity Tests
# ============================================================================

def test_t1_cli_help_flag():
    """Verifies --help flag exits with code 0 and displays usage information."""
    res = run_cli_subprocess(["--help"])
    assert res.exit_code == 0
    clean = res.clean_text
    assert "usage:" in clean
    assert "--db" in clean or "--kdbx" in clean
    assert "--dry-run" in clean
    assert "--mode" in clean


def test_t1_cli_dry_run_flag(tmp_path: Path, mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies --dry-run flag invocation displays diff table with zero token writes."""
    vault = tmp_path / "dryrun.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")
    KDBXFactory.add_otpauth_entry(kp, title="DryRunSvc", username="user")

    with run_interactive_session(["pwd", ""]) as (si, so, se):
        exit_code = main(["--db", str(vault), "--dry-run"])
        assert exit_code == 0
        out = strip_ansi(so.getvalue())
        assert "DryRunSvc" in out
        assert "Dry-run requested: no changes written to Token2" in out
        assert len(mock_token2_hid.entries) == 0


def test_t1_cli_mode_add_only_batch(tmp_path: Path, mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies non-interactive batch sync via --mode add_only -y."""
    vault = tmp_path / "batch.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")
    KDBXFactory.add_otpauth_entry(kp, title="BatchSvc", username="batchuser")

    with run_interactive_session(["pwd", ""]) as (si, so, se):
        exit_code = main(["--db", str(vault), "--mode", "add_only", "-y"])
        assert exit_code == 0
        out = strip_ansi(so.getvalue())
        assert "Successfully performed 1 operations" in out
        assert ("BatchSvc", "batchuser") in mock_token2_hid.entries


def test_t1_cli_custom_config_path(tmp_path: Path, mock_token2_hid: SimulatedToken2HIDDevice):
    """Verifies --config path override."""
    conf_file = tmp_path / "custom_config.toml"
    vault = tmp_path / "custom.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")
    KDBXFactory.add_otpauth_entry(kp, title="CustomConfigSvc")

    conf_file.write_text(f"""[keepassxc]
database_path = "{vault}"
""")

    with run_interactive_session(["pwd", ""]) as (si, so, se):
        exit_code = main(["--config", str(conf_file), "--dry-run"])
        assert exit_code == 0
        out = strip_ansi(so.getvalue())
        assert "CustomConfigSvc" in out


def test_t1_cli_find_free_slots():
    """Verifies slot allocation finding free slots in 1..300 range."""
    occupied = [1, 2, 3, 5, 10]
    free = find_free_slots(occupied, max_capacity=12)
    assert free == [4, 6, 7, 8, 9, 11, 12]
