"""Tests for CLI interaction, sync mode execution, and interactive TUI routing."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from t2_kpxc_sync.cli import (
    _has_explicit_batch_args,
    apply_sync,
    find_free_slots,
    main,
)
from t2_kpxc_sync.config import AppConfig, KeePassXCConfig, load_config, save_config
from t2_kpxc_sync.diff import DiffResult
from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.token2 import Token2CLIAdapter, Token2Error, Token2PINError


def test_find_free_slots():
    occupied = [1, 2, 5]
    free = find_free_slots(occupied, max_capacity=6)
    assert free == [3, 4, 6]


def test_sync_modes():
    # Setup test diff
    entry_add = TOTPEntry(issuer="NewService", account="user", secret="JBSWY3DPEHPK3PXP")
    entry_upd = TOTPEntry(issuer="UpdService", account="user", secret="GEZDGNBVGY3TQOJQ")
    prof_upd = Token2Profile(slot=2, issuer="UpdService", account="user")
    prof_del = Token2Profile(slot=3, issuer="OldService", account="user")

    diff = DiffResult(
        to_add=[entry_add],
        to_update=[(entry_upd, prof_upd)],
        to_delete=[prof_del],
        final_slot_count=2,
    )
    existing_profiles = [prof_upd, prof_del]

    # 1. Mode: Add Only -> only adds, does not delete or update
    mock_adapter = MagicMock(spec=Token2CLIAdapter)
    ops = apply_sync(mock_adapter, diff, existing_profiles, mode="add_only")
    assert ops == 1
    mock_adapter.write_entry.assert_called_once_with(1, entry_add)
    mock_adapter.delete_entry.assert_not_called()

    # 2. Mode: Add & Update -> adds and updates, does not delete obsolete
    mock_adapter.reset_mock()
    ops = apply_sync(mock_adapter, diff, existing_profiles, mode="add_update")
    assert ops == 2
    # Update deletes old slot then writes updated
    mock_adapter.delete_entry.assert_called_once_with(2)
    assert mock_adapter.write_entry.call_count == 2

    # 3. Mode: Full Sync with confirmation -> adds, updates, and deletes obsolete
    mock_adapter.reset_mock()
    ops = apply_sync(mock_adapter, diff, existing_profiles, mode="full_sync", confirm_delete=False)
    assert ops == 3
    # Deleted prof_del (slot 3) and old prof_upd (slot 2)
    assert mock_adapter.delete_entry.call_count == 2
    assert mock_adapter.write_entry.call_count == 2

    # 4. Mode: Cancel -> 0 operations
    mock_adapter.reset_mock()
    ops = apply_sync(mock_adapter, diff, existing_profiles, mode="cancel")
    assert ops == 0
    mock_adapter.write_entry.assert_not_called()
    mock_adapter.delete_entry.assert_not_called()


def test_capacity_exceeded_guard():
    diff = DiffResult(
        to_add=[TOTPEntry(issuer="S", account="a", secret="S")] * 301,
        final_slot_count=301,
        is_capacity_exceeded=True,
    )
    mock_adapter = MagicMock(spec=Token2CLIAdapter)
    with pytest.raises(Token2Error) as exc_info:
        apply_sync(mock_adapter, diff, [], mode="add_only")
    assert "exceeds hardware limit 300" in str(exc_info.value)


def test_has_explicit_batch_args():
    class Args:
        kdbx = None
        dry_run = False
        mode = None
        keyfile = None
        yubikey = None
        yes = False

    args = Args()
    assert _has_explicit_batch_args(args) is False

    args.dry_run = True
    assert _has_explicit_batch_args(args) is True

    args.dry_run = False
    args.kdbx = Path("vault.kdbx")
    assert _has_explicit_batch_args(args) is True


def test_cli_non_interactive_no_db_exit_1(tmp_path):
    cfg_file = tmp_path / "empty_config.toml"
    with patch("sys.stdin.isatty", return_value=False):
        exit_code = main(["--config", str(cfg_file)])
        assert exit_code == 1


def test_cli_explicit_tui_flag(tmp_path):
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")
    cfg_file = tmp_path / "config.toml"
    save_config(AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault))), cfg_file)

    with (
        patch("t2_kpxc_sync.cli.run_main_menu") as mock_menu,
        patch("t2_kpxc_sync.cli.run_onboarding_wizard") as mock_wizard,
    ):
        exit_code = main(["--config", str(cfg_file), "--tui"])
        assert exit_code == 0
        mock_menu.assert_called_once()
        mock_wizard.assert_not_called()


def test_cli_interactive_unconfigured_triggers_wizard(tmp_path):
    cfg_file = tmp_path / "missing_config.toml"
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")
    configured_app = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    with (
        patch("sys.stdin.isatty", return_value=True),
        patch("t2_kpxc_sync.cli.run_onboarding_wizard", return_value=configured_app) as mock_wizard,
        patch("t2_kpxc_sync.cli.run_main_menu") as mock_menu,
    ):
        exit_code = main(["--config", str(cfg_file)])
        assert exit_code == 0
        mock_wizard.assert_called_once()
        mock_menu.assert_called_once()


def test_cli_token2_pin_error_exit_2(tmp_path):
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")

    mock_adapter = MagicMock()
    mock_adapter.get_all.side_effect = Token2PINError("Bad PIN")

    with (
        patch("getpass.getpass", return_value=""),
        patch("t2_kpxc_sync.cli.read_kpxc_entries", return_value=[]),
        patch("t2_kpxc_sync.cli.Token2CLIAdapter", return_value=mock_adapter),
    ):
        exit_code = main(["--db", str(vault), "--mode", "add_only", "-y"])
        assert exit_code == 2


def test_cli_invalid_arg_exit_2():
    with pytest.raises(SystemExit) as exc_info:
        main(["--mode", "invalid_choice"])
    assert exc_info.value.code == 2


def test_cli_batch_dry_run(tmp_path):
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")

    entry = TOTPEntry(issuer="A", account="u", secret="JBSWY3DPEHPK3PXP")
    mock_adapter = MagicMock()
    mock_adapter.get_all.return_value = []

    with (
        patch("getpass.getpass", return_value=""),
        patch("t2_kpxc_sync.cli.read_kpxc_entries", return_value=[entry]),
        patch("t2_kpxc_sync.cli.Token2CLIAdapter", return_value=mock_adapter),
        patch("t2_kpxc_sync.cli.apply_sync") as mock_sync,
    ):
        exit_code = main(["--db", str(vault), "--dry-run"])
        assert exit_code == 0
        mock_sync.assert_not_called()


def test_cli_batch_button_required_flag(tmp_path):
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")

    entry = TOTPEntry(issuer="A", account="u", secret="JBSWY3DPEHPK3PXP")
    mock_adapter = MagicMock()
    mock_adapter.get_all.return_value = []

    with (
        patch("getpass.getpass", return_value=""),
        patch("t2_kpxc_sync.cli.read_kpxc_entries", return_value=[entry]),
        patch("t2_kpxc_sync.cli.Token2CLIAdapter", return_value=mock_adapter),
        patch("t2_kpxc_sync.cli.apply_sync") as mock_sync,
    ):
        # 1. With --button-required
        exit_code = main(["--db", str(vault), "--mode", "add_only", "--button-required"])
        assert exit_code == 0
        _, kwargs = mock_sync.call_args
        assert kwargs.get("btn_flag") == 1

        # 2. Without --button-required (defaults to 0)
        exit_code = main(["--db", str(vault), "--mode", "add_only"])
        assert exit_code == 0
        _, kwargs = mock_sync.call_args
        assert kwargs.get("btn_flag") == 0


def test_config_save_load_windows_path_escaping(tmp_path):
    cfg_file = tmp_path / "win_config.toml"
    win_path = r"C:\Users\tester\Documents\passwords.kdbx"
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=win_path))

    save_config(cfg, cfg_file)
    assert cfg_file.exists()

    loaded = load_config(cfg_file)
    assert loaded.keepassxc.database_path == win_path


def test_config_save_atomic(tmp_path):
    cfg_file = tmp_path / "atomic.toml"
    cfg = AppConfig()
    save_config(cfg, cfg_file)
    assert cfg_file.exists()
    assert not cfg_file.with_suffix(".tmp").exists()
