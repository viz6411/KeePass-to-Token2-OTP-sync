"""Tests for TUI Onboarding Wizard, Main Menu, and Settings Editor."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from t2_kpxc_sync.config import AppConfig, KeePassXCConfig, Token2Config, load_config
from t2_kpxc_sync.diff import TOKEN2_MAX_CAPACITY, DiffResult
from t2_kpxc_sync.kpxc import KeePassCredentialsError, KeePassXCError
from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.token2 import Token2Adapter, Token2Error, Token2PINError
from t2_kpxc_sync.tui import (
    apply_sync,
    display_diff_table,
    find_free_slots,
    handle_settings_menu,
    handle_sync_action,
    render_header_panel,
    run_interactive_menu,
    run_main_menu,
    run_onboarding_wizard,
)


def test_display_diff_table_rendering():
    entry_add = TOTPEntry(issuer="AddSvc", account="u1", secret="JBSWY3DPEHPK3PXP")
    entry_upd = TOTPEntry(issuer="UpdSvc", account="u2", secret="GEZDGNBVGY3TQOJQ")
    prof_upd = Token2Profile(slot=1, issuer="UpdSvc", account="u2")
    prof_del = Token2Profile(slot=2, issuer="DelSvc", account="u3")
    entry_skip = TOTPEntry(issuer="SkipSvc", account="u4", secret="JBSWY3DPEHPK3PXP", period=45)

    diff = DiffResult(
        to_add=[entry_add],
        to_update=[(entry_upd, prof_upd)],
        to_delete=[prof_del],
        skipped=[entry_skip],
        final_slot_count=2,
    )

    test_console = Console(record=True, width=120)
    display_diff_table(diff, total_current_slots=2, con=test_console)
    output = test_console.export_text()

    assert "ADD" in output
    assert "UPDATE" in output
    assert "DELETE" in output
    assert "SKIP" in output
    assert "AddSvc" in output
    assert "UpdSvc" in output
    assert "DelSvc" in output
    assert "SkipSvc" in output
    assert "Token2 Capacity: 2 / 300 slots used" in output


def test_display_diff_table_capacity_warning():
    diff = DiffResult(
        to_add=[TOTPEntry(issuer="S", account="a", secret="JBSWY3DPEHPK3PXP")] * 301,
        final_slot_count=301,
        is_capacity_exceeded=True,
    )
    test_console = Console(record=True, width=120)
    display_diff_table(diff, total_current_slots=0, con=test_console)
    output = test_console.export_text()

    assert "WARNING: Capacity limit of 300 slots would be exceeded!" in output


def test_find_free_slots():
    assert find_free_slots([], max_capacity=3) == [1, 2, 3]
    assert find_free_slots([1, 2, 3], max_capacity=3) == []
    assert find_free_slots([2], max_capacity=4) == [1, 3, 4]


def test_apply_sync_modes():
    entry = TOTPEntry(issuer="Service", account="user", secret="JBSWY3DPEHPK3PXP")
    profile = Token2Profile(slot=1, issuer="Old", account="user")
    diff = DiffResult(to_add=[entry], to_delete=[profile], final_slot_count=1)

    mock_adapter = MagicMock()

    # Cancel
    res = apply_sync(mock_adapter, diff, [profile], mode="4")
    assert res == 0
    mock_adapter.write_entry.assert_not_called()

    # Add only
    res = apply_sync(mock_adapter, diff, [profile], mode="1")
    assert res == 1
    mock_adapter.write_entry.assert_called_once_with(2, entry)

    # Full sync abort deletion
    mock_adapter.reset_mock()
    test_console = Console(record=True)
    with patch.object(test_console, "input", return_value="n"):
        res = apply_sync(mock_adapter, diff, [profile], mode="3", confirm_delete=True, con=test_console)
        assert res == 0
        mock_adapter.delete_entry.assert_not_called()


def test_apply_sync_capacity_guard():
    diff = DiffResult(final_slot_count=301, is_capacity_exceeded=True)
    mock_adapter = MagicMock()
    with pytest.raises(Token2Error, match="exceeds hardware limit 300"):
        apply_sync(mock_adapter, diff, [], mode="add_only")


def test_wizard_manual_full_flow(tmp_path):
    vault = tmp_path / "test_vault.kdbx"
    vault.write_bytes(b"dummy kdbx")
    keyfile = tmp_path / "test.key"
    keyfile.write_bytes(b"dummy key")
    cfg_file = tmp_path / "config.toml"

    inputs = [
        "M",  # Step 1: manual
        str(vault),  # db path
        "M",  # Step 2: manual
        str(keyfile),  # keyfile path
        "1",  # Step 3: slot 1
        "Finance, Admin",  # Step 4: groups
        "Y",  # Confirm save
    ]

    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(vault.resolve())
    assert cfg.keepassxc.keyfile_path == str(keyfile.resolve())
    assert cfg.keepassxc.yubikey_slot == "1"
    assert cfg.keepassxc.excluded_groups == ["Finance", "Admin"]

    assert cfg_file.exists()
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.database_path == str(vault.resolve())
    assert loaded.keepassxc.keyfile_path == str(keyfile.resolve())
    assert loaded.keepassxc.yubikey_slot == "1"
    assert loaded.keepassxc.excluded_groups == ["Finance", "Admin"]


def test_wizard_browse_flow(tmp_path):
    vault = tmp_path / "browse_vault.kdbx"
    vault.write_bytes(b"dummy kdbx")
    keyfile = tmp_path / "browse.key"
    keyfile.write_bytes(b"dummy key")
    cfg_file = tmp_path / "config.toml"

    inputs = [
        "O",  # Step 1: browse
        "O",  # Step 2: browse
        "",   # Step 3: skip slot
        "",   # Step 4: default groups
        "Y",  # Confirm save
    ]

    def _mock_pick(title, **kw):
        if "Database" in title:
            return str(vault)
        return str(keyfile)

    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=inputs), patch("t2_kpxc_sync.tui.pick_file", side_effect=_mock_pick):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(vault.resolve())
    assert cfg.keepassxc.keyfile_path == str(keyfile.resolve())
    assert cfg.keepassxc.yubikey_slot == ""
    assert cfg.keepassxc.excluded_groups == ["Recycle Bin", "Archive"]


def test_wizard_path_validation_and_retry(tmp_path):
    vault = tmp_path / "valid.kdbx"
    vault.write_bytes(b"dummy")
    cfg_file = tmp_path / "config.toml"

    inputs = [
        str(tmp_path / "non_existent.kdbx"),  # invalid path
        str(vault),  # valid path
        "",  # skip keyfile
        "",  # skip slot
        "",  # default groups
        "y",  # save
    ]

    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(vault.resolve())


def test_wizard_non_kdbx_extension_confirmation(tmp_path):
    not_kdbx = tmp_path / "vault.dat"
    not_kdbx.write_bytes(b"dummy")
    cfg_file = tmp_path / "config.toml"

    inputs = [
        str(not_kdbx),
        "n",  # reject warning
        str(not_kdbx),
        "y",  # accept warning
        "",  # skip keyfile
        "",  # skip slot
        "",  # default groups
        "y",  # save
    ]

    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(not_kdbx.resolve())


def test_wizard_quotes_and_tilde(tmp_path, monkeypatch):
    vault = tmp_path / "home_vault.kdbx"
    vault.write_bytes(b"dummy")
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg_file = tmp_path / "config.toml"

    inputs = [
        '  "~/home_vault.kdbx"  ',
        "",  # skip keyfile
        "",  # skip slot
        "",  # default groups
        "y",  # save
    ]

    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(vault.resolve())


def test_wizard_cancel_save(tmp_path):
    vault = tmp_path / "test.kdbx"
    vault.write_bytes(b"dummy")
    cfg_file = tmp_path / "unsaved_config.toml"

    inputs = [
        str(vault),
        "",  # skip keyfile
        "",  # skip slot
        "",  # default groups
        "n",  # DO NOT SAVE
    ]

    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(vault.resolve())
    assert not cfg_file.exists()


def test_render_header_panel(tmp_path):
    cfg_empty = AppConfig()
    panel = render_header_panel(cfg_empty)
    assert "Not configured" in panel.renderable

    valid_file = tmp_path / "db.kdbx"
    valid_file.write_bytes(b"x")
    cfg_valid = AppConfig(keepassxc=KeePassXCConfig(database_path=str(valid_file)))
    panel_valid = render_header_panel(cfg_valid)
    assert str(valid_file) in panel_valid.renderable

    missing_file = tmp_path / "missing.kdbx"
    cfg_missing = AppConfig(keepassxc=KeePassXCConfig(database_path=str(missing_file)))
    panel_missing = render_header_panel(cfg_missing)
    assert "file not found!" in panel_missing.renderable


def test_main_menu_exit():
    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=["4"]):
        run_main_menu(AppConfig(), con=test_console)

    with patch.object(test_console, "input", side_effect=["exit"]):
        run_main_menu(AppConfig(), con=test_console)


def test_main_menu_sync_up_to_date(tmp_path):
    vault = tmp_path / "db.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    entry = TOTPEntry(issuer="Google", account="user", secret="JBSWY3DPEHPK3PXP")
    profile = Token2Profile(slot=1, issuer="Google", account="user")

    test_console = Console(record=True)
    mock_adapter = MagicMock()
    mock_adapter.get_all.return_value = [profile]

    with (
        patch.object(test_console, "input", side_effect=["1", "", "4"]),
        patch("getpass.getpass", side_effect=["pwd", "123456"]),
        patch("t2_kpxc_sync.tui.read_kpxc_entries", return_value=[entry]),
        patch("t2_kpxc_sync.tui.Token2Adapter", return_value=mock_adapter),
    ):
        run_main_menu(cfg, con=test_console)

    output = test_console.export_text()
    assert "Token2 is already up to date with KeePassXC" in output


def test_main_menu_sync_apply_add(tmp_path):
    vault = tmp_path / "db.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    entry = TOTPEntry(issuer="Google", account="user", secret="JBSWY3DPEHPK3PXP")

    test_console = Console(record=True)
    mock_adapter = MagicMock()
    mock_adapter.get_all.return_value = []

    # Sequence: 1 (Sync) -> 1 (Add Only) -> 1 (Standard format) -> Enter (return to menu) -> 4 (Exit)
    with (
        patch.object(test_console, "input", side_effect=["1", "1", "1", "", "4"]),
        patch("getpass.getpass", side_effect=["pwd", "123456"]),
        patch("t2_kpxc_sync.tui.read_kpxc_entries", return_value=[entry]),
        patch("t2_kpxc_sync.tui.Token2Adapter", return_value=mock_adapter),
    ):
        run_main_menu(cfg, con=test_console)

    mock_adapter.write_entry.assert_called_once_with(1, entry)


def test_main_menu_sync_apply_add_touch_required(tmp_path):
    vault = tmp_path / "db.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    entry = TOTPEntry(issuer="Google", account="user", secret="JBSWY3DPEHPK3PXP")

    test_console = Console(record=True)
    mock_adapter = MagicMock()
    mock_adapter.get_all.return_value = []

    # Sequence: 1 (Sync) -> 1 (Add Only) -> 2 (Touch required format) -> Enter (return to menu) -> 4 (Exit)
    with (
        patch.object(test_console, "input", side_effect=["1", "1", "2", "", "4"]),
        patch("getpass.getpass", side_effect=["pwd", "123456"]),
        patch("t2_kpxc_sync.tui.read_kpxc_entries", return_value=[entry]),
        patch("t2_kpxc_sync.tui.Token2Adapter", return_value=mock_adapter),
    ):
        run_main_menu(cfg, con=test_console)

    mock_adapter.write_entry.assert_called_once_with(1, entry, btn_flag=1)


def test_main_menu_dry_run(tmp_path):
    vault = tmp_path / "db.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    entry = TOTPEntry(issuer="Google", account="user", secret="JBSWY3DPEHPK3PXP")

    test_console = Console(record=True)
    mock_adapter = MagicMock()
    mock_adapter.get_all.return_value = []

    with (
        patch.object(test_console, "input", side_effect=["2", "", "4"]),
        patch("getpass.getpass", side_effect=["pwd", "123456"]),
        patch("t2_kpxc_sync.tui.read_kpxc_entries", return_value=[entry]),
        patch("t2_kpxc_sync.tui.Token2Adapter", return_value=mock_adapter),
    ):
        run_main_menu(cfg, con=test_console)

    output = test_console.export_text()
    assert "Dry-run complete: no changes were written to Token2" in output
    mock_adapter.write_entry.assert_not_called()


def test_main_menu_kpxc_credentials_error(tmp_path):
    vault = tmp_path / "db.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    test_console = Console(record=True)

    with (
        patch.object(test_console, "input", side_effect=["1", "", "4"]),
        patch("getpass.getpass", return_value="bad_pwd"),
        patch("t2_kpxc_sync.tui.read_kpxc_entries", side_effect=KeePassCredentialsError("Invalid master password")),
    ):
        run_main_menu(cfg, con=test_console)

    output = test_console.export_text()
    assert "KeePassXC Authentication Failed: Invalid master password" in output


def test_main_menu_token2_pin_error(tmp_path):
    vault = tmp_path / "db.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    test_console = Console(record=True)
    mock_adapter = MagicMock()
    mock_adapter.get_all.side_effect = Token2PINError("Wrong PIN: 2 retries remaining")

    with (
        patch.object(test_console, "input", side_effect=["1", "", "4"]),
        patch("getpass.getpass", return_value="1234"),
        patch("t2_kpxc_sync.tui.read_kpxc_entries", return_value=[]),
        patch("t2_kpxc_sync.tui.Token2Adapter", return_value=mock_adapter),
    ):
        run_main_menu(cfg, con=test_console)

    output = test_console.export_text()
    assert "Token2 Security Error: Wrong PIN: 2 retries remaining" in output
    assert "Aborting immediately to protect token from lockout" in output


def test_settings_editor_edit_all_fields(tmp_path):
    cfg_file = tmp_path / "config.toml"
    vault = tmp_path / "new_vault.kdbx"
    vault.write_bytes(b"dummy")
    keyfile = tmp_path / "new_keyfile.key"
    keyfile.write_bytes(b"dummy")

    initial_cfg = AppConfig()
    test_console = Console(record=True)

    inputs = [
        "1",  # Edit DB
        str(vault),
        "2",  # Edit keyfile
        str(keyfile),
        "3",  # Edit YubiKey slot
        "2",
        "4",  # Edit excluded groups
        "Stale, Archive",
        "5",  # Edit backend
        "2",  # direct
        "6",  # Edit default TOTP format
        "2",  # Touch required
        "2",  # Edit keyfile again -> Clear it
        "C",
        "8",  # Back
    ]

    with patch.object(test_console, "input", side_effect=inputs):
        updated_cfg = handle_settings_menu(initial_cfg, cfg_file, con=test_console)

    assert updated_cfg.keepassxc.database_path == str(vault.resolve())
    assert updated_cfg.keepassxc.keyfile_path == ""
    assert updated_cfg.keepassxc.yubikey_slot == "2"
    assert updated_cfg.keepassxc.excluded_groups == ["Stale", "Archive"]
    assert updated_cfg.keepassxc.backend == "direct"
    assert updated_cfg.token2.button_required is True

    # Verify persisted to TOML
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.database_path == str(vault.resolve())
    assert loaded.keepassxc.keyfile_path == ""
    assert loaded.keepassxc.yubikey_slot == "2"
    assert loaded.keepassxc.excluded_groups == ["Stale", "Archive"]
    assert loaded.keepassxc.backend == "direct"
    assert loaded.token2.button_required is True


def test_settings_editor_reset_defaults(tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg = AppConfig(
        keepassxc=KeePassXCConfig(database_path="/custom/path.kdbx", yubikey_slot="1"),
        token2=Token2Config(button_required=True),
    )

    test_console = Console(record=True)
    inputs = [
        "7",  # Reset defaults
        "y",  # confirm
        "8",  # back
    ]

    with patch.object(test_console, "input", side_effect=inputs):
        reset_cfg = handle_settings_menu(cfg, cfg_file, con=test_console)

    assert reset_cfg.keepassxc.database_path == ""
    assert reset_cfg.keepassxc.yubikey_slot == ""
    assert reset_cfg.token2.button_required is False
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.database_path == ""
    assert loaded.token2.button_required is False


def test_prompt_entry_format_choices():
    """Verifies prompt_entry_format interactive handling."""
    from t2_kpxc_sync.tui import prompt_entry_format

    c = Console(record=True)

    # 1. User picks '1' -> Standard (0)
    with patch.object(c, "input", return_value="1"):
        assert prompt_entry_format(default_button_required=False, con=c) == 0

    # 2. User picks '2' -> Touch required (1)
    with patch.object(c, "input", return_value="2"):
        assert prompt_entry_format(default_button_required=False, con=c) == 1

    # 3. User hits Enter with default False -> 0
    with patch.object(c, "input", return_value=""):
        assert prompt_entry_format(default_button_required=False, con=c) == 0

    # 4. User hits Enter with default True -> 1
    with patch.object(c, "input", return_value=""):
        assert prompt_entry_format(default_button_required=True, con=c) == 1

    # 5. User interrupts -> returns default
    with patch.object(c, "input", side_effect=KeyboardInterrupt):
        assert prompt_entry_format(default_button_required=True, con=c) == 1


def test_main_menu_keyboard_interrupt_handled():
    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=KeyboardInterrupt):
        run_main_menu(AppConfig(), con=test_console)
    output = test_console.export_text()
    assert "Session interrupted by user" in output
