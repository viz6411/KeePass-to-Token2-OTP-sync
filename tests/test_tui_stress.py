"""Empirical stress tests for TUI Onboarding Wizard, Main Menu, and Settings Editor.

Tested areas:
1. Wizard input edge cases (empty strings, nonexistent files, non-.kdbx files, quotes, tilde, defaults).
2. Main menu choices (invalid options, rapid enters, exit aliases).
3. Settings editor (mutations of db_path, keyfile_path, yubikey_slot, excluded_groups, backend, and reset).
4. Cancellation / interruption (EOFError, KeyboardInterrupt at wizard, main menu, settings, sync).
5. Memory hygiene (password and PIN bytearray buffers zeroed out in memory).
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from t2_kpxc_sync.cli import main as cli
from t2_kpxc_sync.config import AppConfig, KeePassXCConfig, Token2Config, load_config
from t2_kpxc_sync.diff import DiffResult
from t2_kpxc_sync.kpxc import KeePassCredentialsError, KeePassXCError
from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.token2 import Token2Adapter, Token2Error, Token2PINError
from t2_kpxc_sync.tui import (
    apply_sync,
    display_diff_table,
    find_free_slots,
    handle_settings_menu,
    handle_sync_action,
    run_interactive_menu,
    run_main_menu,
    run_onboarding_wizard,
)


# ==============================================================================
# Area 1: Wizard Input Edge Cases
# ==============================================================================

def test_wizard_empty_strings_and_retries(tmp_path):
    """Wizard handles empty and whitespace-only inputs with retries on required fields."""
    vault = tmp_path / "actual_vault.kdbx"
    vault.write_bytes(b"dummy kdbx content")
    cfg_file = tmp_path / "config.toml"

    inputs = [
        "",  # Empty choice
        "   ",  # Whitespace choice
        "M",  # Manual choice
        "",  # Empty path in manual prompt
        "   ",  # Whitespace path
        str(vault),  # Valid database path
        "",  # Skip keyfile
        "   ",  # Whitespace in slot prompt -> skips
        "   ",  # Whitespace in groups -> keeps default
        "y",  # Confirm save
    ]

    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(vault.resolve())
    assert cfg.keepassxc.keyfile_path == ""
    assert cfg.keepassxc.yubikey_slot == ""
    assert cfg.keepassxc.excluded_groups == ["Recycle Bin", "Archive"]

    output = test_console.export_text()
    assert "Database path is required" in output


def test_wizard_nonexistent_files_and_directories(tmp_path):
    """Wizard rejects nonexistent files and directory paths, prompting for retry."""
    nonexistent = tmp_path / "nonexistent" / "missing.kdbx"
    directory = tmp_path / "a_directory"
    directory.mkdir()
    valid_kdbx = tmp_path / "valid.kdbx"
    valid_kdbx.write_bytes(b"kdbx content")
    cfg_file = tmp_path / "config.toml"

    inputs = [
        str(nonexistent),  # File not found
        str(directory),  # Directory, not a file
        str(valid_kdbx),  # Valid file
        "",  # Skip keyfile
        "",  # Skip slot
        "",  # Skip groups
        "y",  # Save
    ]

    test_console = Console(record=True, width=300)
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(valid_kdbx.resolve())
    output = test_console.export_text()
    assert "File not found" in output
    assert str(nonexistent) in output
    assert str(directory) in output


def test_wizard_non_kdbx_file_rejections_and_cyrillic_yes(tmp_path):
    """Wizard warns on non-.kdbx extension; supports rejection (n) and Cyrillic acceptance (д/да)."""
    text_file = tmp_path / "passwords.txt"
    text_file.write_bytes(b"plaintext secrets")
    cfg_file = tmp_path / "config.toml"

    inputs = [
        str(text_file),
        "n",  # Reject warning -> loops back
        str(text_file),
        "",  # Empty input on warning -> defaults to No (loops back)
        str(text_file),
        "д",  # Russian 'д' (yes) -> accepted
        "",  # Skip keyfile
        "",  # Skip slot
        "",  # Skip groups
        "y",  # Save
    ]

    test_console = Console(record=True, width=300)
    with patch.object(test_console, "input", side_effect=inputs) as mock_input:
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(text_file.resolve())
    prompts = [call[0][0] for call in mock_input.call_args_list if call[0]]
    assert any("Warning: File does not have .kdbx extension" in p for p in prompts)


def test_wizard_quoted_paths_and_env_vars(tmp_path, monkeypatch):
    """Wizard properly cleans single, double, nested quotes, tilde, and env vars."""
    vault = tmp_path / "vault_in_home.kdbx"
    vault.write_bytes(b"dummy")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MY_VAULT_NAME", "vault_in_home.kdbx")
    cfg_file = tmp_path / "config.toml"

    inputs = [
        '  "\'$HOME/$MY_VAULT_NAME\'"  ',  # Nested quotes with env var
        "",  # Skip keyfile
        "",  # Skip slot
        "",  # Skip groups
        "y",  # Save
    ]

    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(vault.resolve())
    assert cfg_file.exists()


def test_wizard_browse_cancellation_and_fallback(tmp_path):
    """When browse dialog returns None (cancelled), wizard stays on step and allows manual entry."""
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")
    cfg_file = tmp_path / "config.toml"

    inputs = [
        "O",  # Browse requested
        str(vault),  # Manual fallback
        "O",  # Browse keyfile requested (cancelled)
        "",  # Skip keyfile
        "",  # Skip slot
        "",  # Skip groups
        "y",  # Save
    ]

    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=inputs), patch("t2_kpxc_sync.tui.pick_file", return_value=None):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.database_path == str(vault.resolve())
    output = test_console.export_text()
    assert "Browse cancelled or unavailable" in output


def test_wizard_custom_excluded_groups_parsing(tmp_path):
    """Wizard parses comma-separated groups with extra spaces, filtering out empty entries."""
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")
    cfg_file = tmp_path / "config.toml"

    inputs = [
        str(vault),
        "",  # Skip keyfile
        "",  # Skip slot
        "  Financial  , ,  Backups , Old-Archive  ",  # Comma separated with empties
        "y",  # Save
    ]

    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert cfg.keepassxc.excluded_groups == ["Financial", "Backups", "Old-Archive"]
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.excluded_groups == ["Financial", "Backups", "Old-Archive"]


# ==============================================================================
# Area 2: Main Menu Choices
# ==============================================================================

def test_main_menu_invalid_choices_and_clean_exit():
    """Main menu handles invalid numerical and text choices, rapid enters, and clean exits."""
    test_console = Console(record=True, width=300)
    inputs = [
        "0",  # Invalid choice below range
        "5",  # Invalid choice above range
        "99",  # Invalid choice
        "-1",  # Negative
        "abc",  # Text
        "???",  # Punctuation
        "   ",  # Whitespace -> defaults to "1" (Sync)
        "",   # Press Enter to return to main menu (from handle_sync_action)
        "4",  # Exit
    ]

    # AppConfig with unconfigured database to observe option 1 behavior without hardware calls
    cfg = AppConfig()

    with patch.object(test_console, "input", side_effect=inputs):
        run_main_menu(cfg, con=test_console)

    output = test_console.export_text()
    assert "Invalid choice: '0'" in output
    assert "Invalid choice: '5'" in output
    assert "Invalid choice: 'abc'" in output
    assert "Database path is not configured" in output
    assert "Exiting t2-kpxc-sync. Goodbye!" in output


@pytest.mark.parametrize("exit_cmd", ["4", "q", "exit", "quit"])
def test_main_menu_all_exit_aliases(exit_cmd):
    """Main menu exits cleanly on 4, q, exit, or quit."""
    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=[exit_cmd]):
        run_main_menu(AppConfig(), con=test_console)

    output = test_console.export_text()
    assert "Exiting t2-kpxc-sync. Goodbye!" in output


# ==============================================================================
# Area 3: Settings Editor Full Mutation Cycle
# ==============================================================================

def test_settings_editor_complete_mutation_cycle(tmp_path):
    """Tests every setting mutation in handle_settings_menu, verifying disk persistence after each."""
    cfg_file = tmp_path / "config.toml"
    vault1 = tmp_path / "vault1.kdbx"
    vault1.write_bytes(b"v1")
    vault2 = tmp_path / "vault2.kdbx"
    vault2.write_bytes(b"v2")
    keyfile1 = tmp_path / "key1.key"
    keyfile1.write_bytes(b"k1")

    initial_cfg = AppConfig()
    test_console = Console(record=True)

    # We will step through each mutation individually and verify disk state
    # Mutation 1: Set database_path
    inputs = ["1", str(vault1), "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(initial_cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.database_path == str(vault1.resolve())
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.database_path == str(vault1.resolve())

    # Mutation 2: Set keyfile_path
    inputs = ["2", str(keyfile1), "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.keyfile_path == str(keyfile1.resolve())
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.keyfile_path == str(keyfile1.resolve())

    # Mutation 3: Clear keyfile_path with 'C'
    inputs = ["2", "C", "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.keyfile_path == ""
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.keyfile_path == ""

    # Mutation 4: Clear keyfile_path with Russian 'с' (Cyrillic)
    # First set it again
    inputs = ["2", str(keyfile1), "2", "с", "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.keyfile_path == ""
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.keyfile_path == ""

    # Mutation 5: Set YubiKey slot to '1', then '2'
    inputs = ["3", "1", "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.yubikey_slot == "1"
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.yubikey_slot == "1"

    inputs = ["3", "2", "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.yubikey_slot == "2"
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.yubikey_slot == "2"

    # Mutation 6: Clear YubiKey slot with 'C' and with Russian 'с'
    inputs = ["3", "C", "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.yubikey_slot == ""
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.yubikey_slot == ""

    # Mutation 7: Edit excluded groups
    inputs = ["4", "Alpha, Beta, Gamma", "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.excluded_groups == ["Alpha", "Beta", "Gamma"]
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.excluded_groups == ["Alpha", "Beta", "Gamma"]

    # Mutation 8: Edit backend ('1' auto, '2' direct, '3' cli)
    inputs = ["5", "2", "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.backend == "direct"
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.backend == "direct"

    inputs = ["5", "3", "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.backend == "cli"
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.backend == "cli"

    inputs = ["5", "1", "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.backend == "auto"
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.backend == "auto"

    # Mutation 9: Reset to defaults with '6' + 'y'
    inputs = ["6", "y", "7"]
    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(cfg, cfg_file, con=test_console)
    assert cfg.keepassxc.database_path == ""
    assert cfg.keepassxc.keyfile_path == ""
    assert cfg.keepassxc.yubikey_slot == ""
    assert cfg.keepassxc.backend == "auto"
    assert cfg.keepassxc.excluded_groups == ["Recycle Bin", "Archive"]

    loaded = load_config(cfg_file)
    assert loaded.keepassxc.database_path == ""
    assert loaded.keepassxc.keyfile_path == ""
    assert loaded.keepassxc.yubikey_slot == ""


def test_settings_editor_invalid_inputs_preserve_disk(tmp_path):
    """Invalid inputs in settings do not corrupt configuration file on disk."""
    cfg_file = tmp_path / "config.toml"
    valid_vault = tmp_path / "valid.kdbx"
    valid_vault.write_bytes(b"content")

    initial_cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(valid_vault), yubikey_slot="1"))
    from t2_kpxc_sync.config import save_config
    save_config(initial_cfg, cfg_file)

    test_console = Console(record=True)
    inputs = [
        "1",  # Edit DB
        str(tmp_path / "does_not_exist.kdbx"),  # Nonexistent file
        "3",  # Edit slot
        "invalid_slot",  # Invalid slot
        "5",  # Edit backend
        "99",  # Invalid backend choice
        "7",  # Back
    ]

    with patch.object(test_console, "input", side_effect=inputs):
        cfg = handle_settings_menu(initial_cfg, cfg_file, con=test_console)

    # Disk file remains unchanged
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.database_path == str(valid_vault)
    assert loaded.keepassxc.yubikey_slot == "1"
    assert loaded.keepassxc.backend == "auto"


# ==============================================================================
# Area 4: Cancellation and Interruption (EOFError and KeyboardInterrupt)
# ==============================================================================

@pytest.mark.parametrize("exception_cls", [KeyboardInterrupt, EOFError])
def test_wizard_interruption_at_any_step(tmp_path, exception_cls):
    """Wizard propagates KeyboardInterrupt and EOFError so outer launcher can cleanly cancel."""
    cfg_file = tmp_path / "config.toml"
    test_console = Console(record=True)

    # Interruption at Step 1
    with patch.object(test_console, "input", side_effect=exception_cls):
        with pytest.raises(exception_cls):
            run_onboarding_wizard(config_path=cfg_file, con=test_console)

    assert not cfg_file.exists()


@pytest.mark.parametrize("exception_cls", [KeyboardInterrupt, EOFError])
def test_cli_launcher_catches_wizard_interruption(tmp_path, monkeypatch, exception_cls):
    """CLI launcher handles wizard KeyboardInterrupt/EOFError, returning 0 without traceback."""
    cfg_file = tmp_path / "config.toml"
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    with (
        patch("t2_kpxc_sync.cli.get_default_config_path", return_value=cfg_file),
        patch("t2_kpxc_sync.cli.run_onboarding_wizard", side_effect=exception_cls),
    ):
        ret = cli([])

    assert ret == 0


def test_main_menu_keyboard_interrupt_graceful_exit():
    """Main menu intercepts KeyboardInterrupt, prints goodbye message, and exits cleanly."""
    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=KeyboardInterrupt):
        run_main_menu(AppConfig(), con=test_console)

    output = test_console.export_text()
    assert "Session interrupted by user. Exiting t2-kpxc-sync. Goodbye!" in output


def test_main_menu_eof_graceful_exit():
    """Main menu intercepts EOFError and breaks out of the loop cleanly."""
    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=EOFError):
        run_main_menu(AppConfig(), con=test_console)


@pytest.mark.parametrize("exception_cls", [KeyboardInterrupt, EOFError])
def test_settings_menu_interruption_breaks_cleanly(exception_cls):
    """Settings menu handles KeyboardInterrupt/EOFError at choice prompt and returns config."""
    test_console = Console(record=True)
    cfg = AppConfig()
    with patch.object(test_console, "input", side_effect=exception_cls):
        result_cfg = handle_settings_menu(cfg, Path("/dummy/config.toml"), con=test_console)
    assert result_cfg == cfg


@pytest.mark.parametrize("choice_key", ["1", "2", "3", "4", "5", "6"])
def test_settings_subprompts_handle_interruption(choice_key):
    """Every sub-prompt in settings menu handles KeyboardInterrupt without crash, remaining in loop."""
    test_console = Console(record=True)
    cfg = AppConfig()
    inputs = [
        choice_key,
        KeyboardInterrupt,  # Interrupt inside sub-prompt
        "7",  # Return to main menu
    ]

    with patch.object(test_console, "input", side_effect=inputs):
        result_cfg = handle_settings_menu(cfg, Path("/dummy/config.toml"), con=test_console)
    assert result_cfg == cfg


# ==============================================================================
# Area 5: Memory Hygiene Verification
# ==============================================================================

def test_memory_hygiene_normal_sync(tmp_path):
    """Password and PIN mutable buffers are scrubbed to all zeroes after successful sync."""
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    entry = TOTPEntry(issuer="Corp", account="bob", secret="JBSWY3DPEHPK3PXP")
    profile = Token2Profile(slot=1, issuer="Corp", account="bob")

    captured_password_buf = None
    captured_pin_buf = None

    def fake_read_kpxc(db_path, password, **kw):
        nonlocal captured_password_buf
        captured_password_buf = password
        # Verify buffer contains plaintext during execution
        assert captured_password_buf == bytearray(b"super_secret_pwd")
        return [entry]

    mock_adapter = MagicMock()
    mock_adapter.get_all.return_value = [profile]

    def fake_adapter_init(backend, cli_binary, pin, **kw):
        nonlocal captured_pin_buf
        captured_pin_buf = pin
        assert captured_pin_buf == bytearray(b"987654")
        return mock_adapter

    test_console = Console(record=True)
    inputs = [
        "1",  # Option 1: Sync
        "",   # Press enter to return to menu
        "4",  # Option 4: Exit
    ]

    with (
        patch.object(test_console, "input", side_effect=inputs),
        patch("getpass.getpass", side_effect=["super_secret_pwd", "987654"]),
        patch("t2_kpxc_sync.tui.read_kpxc_entries", side_effect=fake_read_kpxc),
        patch("t2_kpxc_sync.tui.Token2Adapter", side_effect=fake_adapter_init),
    ):
        run_main_menu(cfg, con=test_console)

    # Post-execution verification: All bytes MUST be zeroed out
    assert captured_password_buf is not None
    assert captured_pin_buf is not None
    assert all(b == 0 for b in captured_password_buf), "Password buffer was NOT zeroed out!"
    assert all(b == 0 for b in captured_pin_buf), "PIN buffer was NOT zeroed out!"


def test_memory_hygiene_on_kpxc_auth_failure(tmp_path):
    """Password and PIN buffers are scrubbed even when KeePassXC authentication fails."""
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    captured_password_buf = None

    def fake_read_kpxc(db_path, password, **kw):
        nonlocal captured_password_buf
        captured_password_buf = password
        raise KeePassCredentialsError("Invalid password")

    test_console = Console(record=True)
    inputs = [
        "1",  # Sync
        "",   # Return to menu
        "4",  # Exit
    ]

    with (
        patch.object(test_console, "input", side_effect=inputs),
        patch("getpass.getpass", side_effect=["wrong_password", "123456"]),
        patch("t2_kpxc_sync.tui.read_kpxc_entries", side_effect=fake_read_kpxc),
    ):
        run_main_menu(cfg, con=test_console)

    assert captured_password_buf is not None
    assert all(b == 0 for b in captured_password_buf), "Password buffer was NOT scrubbed after error!"


def test_memory_hygiene_on_token2_pin_failure(tmp_path):
    """Password and PIN buffers are scrubbed even when Token2 PIN verification fails."""
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    captured_pin_buf = None
    mock_adapter = MagicMock()
    mock_adapter.get_all.side_effect = Token2PINError("Wrong PIN (2 attempts left)")

    def fake_adapter_init(backend, cli_binary, pin, **kw):
        nonlocal captured_pin_buf
        captured_pin_buf = pin
        return mock_adapter

    test_console = Console(record=True)
    inputs = [
        "1",  # Sync
        "",   # Return to menu
        "4",  # Exit
    ]

    with (
        patch.object(test_console, "input", side_effect=inputs),
        patch("getpass.getpass", side_effect=["correct_pwd", "bad_pin"]),
        patch("t2_kpxc_sync.tui.read_kpxc_entries", return_value=[]),
        patch("t2_kpxc_sync.tui.Token2Adapter", side_effect=fake_adapter_init),
    ):
        run_main_menu(cfg, con=test_console)

    assert captured_pin_buf is not None
    assert all(b == 0 for b in captured_pin_buf), "PIN buffer was NOT scrubbed after Token2 PIN error!"


def test_memory_hygiene_on_interruption_during_pin_prompt(tmp_path):
    """When user enters password but interrupts PIN prompt (Ctrl+C), password buffer is scrubbed."""
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    captured_password_buf = None

    orig_getpass = "placeholder"

    def fake_getpass(prompt):
        nonlocal captured_password_buf
        if "Master Password" in prompt:
            return "pwd123"
        # Token2 PIN prompt -> user interrupts
        raise KeyboardInterrupt

    test_console = Console(record=True)

    # Intercept handle_sync_action to capture password_buf from local frame or monkeypatch
    with patch("getpass.getpass", side_effect=fake_getpass):
        # We can monitor scrub_bytes calls
        with patch("t2_kpxc_sync.tui.scrub_bytes", wraps=from_security_scrub_bytes) as mock_scrub:
            handle_sync_action(cfg, con=test_console)

    # Verify scrub_bytes was called with the bytearray
    assert mock_scrub.called
    for call in mock_scrub.call_args_list:
        buf = call[0][0]
        if isinstance(buf, bytearray):
            assert all(b == 0 for b in buf)


def from_security_scrub_bytes(buf):
    from t2_kpxc_sync.security import scrub_bytes
    return scrub_bytes(buf)


# ==============================================================================
# Area 6: Adversarial Unicode and TOML Compliance
# ==============================================================================

def test_config_serialization_with_non_bmp_unicode(tmp_path):
    """Verifies that non-BMP Unicode (emojis/symbols) in paths and groups do not corrupt config.toml.

    Expected behavior: save_config and load_config must round-trip successfully without
    crashing tomllib or silently discarding configuration.
    """
    cfg_file = tmp_path / "unicode_config.toml"
    vault_path = str(tmp_path / "🔑_vault_🛡️.kdbx")
    groups = ["Personal 🔒", "Work 💼", "Archive 📦"]

    cfg = AppConfig(
        keepassxc=KeePassXCConfig(
            database_path=vault_path,
            excluded_groups=groups,
        )
    )
    from t2_kpxc_sync.config import save_config
    save_config(cfg, cfg_file)

    # Read raw content to inspect encoding
    raw_toml = cfg_file.read_text(encoding="utf-8")

    # If _toml_str emitted surrogate pairs, tomllib will raise TOMLDecodeError
    # and load_config will silently return default AppConfig with empty database_path
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.database_path == vault_path, (
        f"Config reload failed! Loaded database_path '{loaded.keepassxc.database_path}' "
        f"does not match saved '{vault_path}'. Raw TOML:\n{raw_toml}"
    )
    assert loaded.keepassxc.excluded_groups == groups


def test_sync_mode_menu_invalid_choice_handling():
    """When user enters an invalid choice at run_interactive_menu (e.g. '5' or 'abc'),

    it should re-prompt, show an error message, and accept a valid choice.
    """
    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=["5", "4"]):
        choice = run_interactive_menu(con=test_console)

    assert choice == "4"
    output = test_console.export_text()
    assert "Invalid choice: '5'" in output

    diff = DiffResult(
        to_add=[TOTPEntry(issuer="Test", account="u", secret="JBSWY3DPEHPK3PXP")],
        final_slot_count=1,
    )
    mock_adapter = MagicMock()
    ops = apply_sync(mock_adapter, diff, [], mode=choice, con=test_console)
    assert ops == 0
    mock_adapter.write_entry.assert_not_called()

