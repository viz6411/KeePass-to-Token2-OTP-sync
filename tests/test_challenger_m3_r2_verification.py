"""Empirical challenge verification test suite for Milestone 3 Iteration 2 fixes.

Verifies:
1. run_interactive_menu reprompts on invalid inputs ("5", "abc", "-1", etc.) with error feedback.
2. run_interactive_menu defaults to "4" (Cancel) on empty Enter or whitespace.
3. run_interactive_menu returns "4" (Cancel) on EOFError, KeyboardInterrupt, StopIteration.
4. apply_sync defensive guard rejects unmapped modes, returning 0 with warning and no false success.
5. apply_sync handles cancel modes ("4", "cancel") safely without operations.
6. handle_sync_action end-to-end rejects invalid menu inputs and handles cancellation safely.
7. Arbitrary Unicode, non-BMP emojis, DEL (\x7f), control characters, and multiline/quotes persist and reload with 100% fidelity.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from t2_kpxc_sync.config import (
    AppConfig,
    KeePassXCConfig,
    Token2Config,
    _toml_str,
    load_config,
    save_config,
)
from t2_kpxc_sync.diff import DiffResult
from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.tui import (
    apply_sync,
    handle_sync_action,
    run_interactive_menu,
)


@pytest.mark.parametrize("invalid_input", ["5", "abc", "-1", "0", "99", "!@#", "3.14", " 5 ", "exit"])
def test_run_interactive_menu_reprompts_on_invalid_input(invalid_input):
    """Verify that any invalid menu input reprompts the user and displays an error message."""
    test_console = Console(record=True)
    # Give invalid input, then valid choice "4"
    with patch.object(test_console, "input", side_effect=[invalid_input, "4"]):
        choice = run_interactive_menu(con=test_console)

    assert choice == "4"
    output = test_console.export_text()
    expected_err = f"Invalid choice: '{invalid_input.strip()}'. Please select 1, 2, 3, or 4."
    assert expected_err in output, f"Expected '{expected_err}' in output:\n{output}"


def test_run_interactive_menu_sequence_of_invalid_inputs():
    """Verify that multiple consecutive invalid inputs keep looping until a valid choice is entered."""
    test_console = Console(record=True)
    invalid_seq = ["5", "abc", "-1", "99", "!@#", "xyz"]
    with patch.object(test_console, "input", side_effect=invalid_seq + ["2"]):
        choice = run_interactive_menu(con=test_console)

    assert choice == "2"
    output = test_console.export_text()
    for item in invalid_seq:
        assert f"Invalid choice: '{item}'" in output


@pytest.mark.parametrize("empty_input", ["", " ", "   ", "\t", "  \t  "])
def test_run_interactive_menu_empty_enter_defaults_to_cancel_4(empty_input):
    """Verify that pressing Enter (empty or whitespace) immediately returns '4' (Cancel)."""
    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=[empty_input]):
        choice = run_interactive_menu(con=test_console)

    assert choice == "4"


def test_run_interactive_menu_invalid_then_empty_enter():
    """Verify that entering invalid choices followed by empty Enter defaults to '4' (Cancel)."""
    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=["5", "abc", ""]):
        choice = run_interactive_menu(con=test_console)

    assert choice == "4"
    output = test_console.export_text()
    assert "Invalid choice: '5'" in output
    assert "Invalid choice: 'abc'" in output


@pytest.mark.parametrize("exc_cls", [EOFError, KeyboardInterrupt, StopIteration])
def test_run_interactive_menu_abort_exceptions_return_cancel_4(exc_cls):
    """Verify that EOFError, KeyboardInterrupt, and StopIteration return '4' (Cancel)."""
    # 1. Immediate exception
    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=exc_cls):
        choice = run_interactive_menu(con=test_console)
    assert choice == "4"

    # 2. Exception after invalid attempts
    test_console = Console(record=True)
    with patch.object(test_console, "input", side_effect=["5", "bad", exc_cls]):
        choice = run_interactive_menu(con=test_console)
    assert choice == "4"
    output = test_console.export_text()
    assert "Invalid choice: '5'" in output


@pytest.mark.parametrize("bad_mode", ["5", "abc", "-1", "0", "99", "unknown", "", "   ", "INVALID"])
def test_apply_sync_defensively_rejects_unmapped_modes(bad_mode):
    """Verify that apply_sync rejects unmapped modes, returns 0, and never reports success."""
    test_console = Console(record=True)
    mock_adapter = MagicMock()
    diff = DiffResult(
        to_add=[TOTPEntry(issuer="Test", account="user@test", secret="JBSWY3DPEHPK3PXP")],
        to_delete=[Token2Profile(slot=5, issuer="Old", account="user@old")],
        to_update=[(TOTPEntry(issuer="Up", account="u@u", secret="JBSWY3DPEHPK3PXP"), Token2Profile(slot=2, issuer="Up", account="u@u"))],
        final_slot_count=1,
    )
    existing = [Token2Profile(slot=2, issuer="Up", account="u@u"), Token2Profile(slot=5, issuer="Old", account="user@old")]

    ops = apply_sync(mock_adapter, diff, existing, mode=bad_mode, con=test_console)

    assert ops == 0
    mock_adapter.write_entry.assert_not_called()
    mock_adapter.delete_entry.assert_not_called()

    output = test_console.export_text()
    assert "Unknown sync mode" in output
    assert "Successfully performed" not in output


@pytest.mark.parametrize("cancel_mode", ["4", "cancel", "CANCEL", " 4 ", " Cancel "])
def test_apply_sync_handles_cancel_modes_safely(cancel_mode):
    """Verify that apply_sync handles cancel modes safely, printing cancellation without success."""
    test_console = Console(record=True)
    mock_adapter = MagicMock()
    diff = DiffResult(
        to_add=[TOTPEntry(issuer="Test", account="user@test", secret="JBSWY3DPEHPK3PXP")],
        final_slot_count=1,
    )

    ops = apply_sync(mock_adapter, diff, [], mode=cancel_mode, con=test_console)

    assert ops == 0
    mock_adapter.write_entry.assert_not_called()
    mock_adapter.delete_entry.assert_not_called()

    output = test_console.export_text()
    assert "Sync cancelled by user." in output
    assert "Successfully performed" not in output


def test_handle_sync_action_end_to_end_invalid_menu_to_cancel(tmp_path):
    """End-to-end check that invalid menu choices in handle_sync_action reprompt, cancel on Enter, and do not write."""
    vault = tmp_path / "vault.kdbx"
    vault.write_bytes(b"dummy")
    cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=str(vault)))

    test_console = Console(record=True)
    mock_adapter = MagicMock()
    mock_adapter.get_all.return_value = []
    kpxc_entry = TOTPEntry(issuer="Test", account="user@test", secret="JBSWY3DPEHPK3PXP")

    # Inputs: "5" (invalid), "abc" (invalid), "" (empty Enter -> cancel 4), "" (Enter to return to main menu)
    inputs = ["5", "abc", "", ""]

    with (
        patch.object(test_console, "input", side_effect=inputs),
        patch("getpass.getpass", return_value="pwd123"),
        patch("t2_kpxc_sync.tui.read_kpxc_entries", return_value=[kpxc_entry]),
        patch("t2_kpxc_sync.tui.Token2Adapter", return_value=mock_adapter),
    ):
        handle_sync_action(cfg, dry_run=False, con=test_console)

    out = test_console.export_text()
    assert "Invalid choice: '5'" in out
    assert "Invalid choice: 'abc'" in out
    assert "Sync cancelled by user." in out
    assert "Successfully performed" not in out
    mock_adapter.write_entry.assert_not_called()


def test_arbitrary_unicode_persistence_and_reload_fidelity(tmp_path):
    """Verify that arbitrary Unicode, non-BMP symbols, emojis, ZWJ sequences, control chars,

    and DEL survive TOML serialization and reload with 100% fidelity without surrogate errors.
    """
    import tomllib

    cfg_file = tmp_path / "nested" / "dir" / "adversarial_unicode.toml"

    db_path = "/opt/vaults/🔑_🔐_🛡️/база_данных_日本語_👨‍👩‍👧‍👦_🏳️‍🌈.kdbx"
    kf_path = "/keys/ключ_\x7f_\"quotes\"_and_'singles'.key"
    slot = "2"
    cli_bin = "custom-kpxc-cli"
    groups = [
        "Recycle Bin 🗑️",
        "Личные записи 💼",
        "Archive \U0010FFFF (max unicode)",
        "Tab\there and line break literal",
        "Control chars: \u0000\u0001\u001f",
        "Del character: \x7f",
        "Greek: Ελληνικά / Hebrew: עברית / Arabic: العربية",
    ]

    cfg = AppConfig(
        keepassxc=KeePassXCConfig(
            database_path=db_path,
            keyfile_path=kf_path,
            yubikey_slot=slot,
            cli_binary=cli_bin,
            excluded_groups=groups,
            backend="direct",
        ),
        token2=Token2Config(cli_binary="custom-t2-cli"),
    )

    save_config(cfg, cfg_file)
    assert cfg_file.is_file()

    # Raw content check
    raw_content = cfg_file.read_text(encoding="utf-8")
    assert r"\ud83d" not in raw_content, "Found surrogate pair in TOML output!"
    assert r"\ud83c" not in raw_content, "Found surrogate pair in TOML output!"
    assert "🔑" in raw_content
    assert "🛡️" in raw_content
    assert r"\u007f" in raw_content, "DEL character (0x7F) was not escaped as \\u007f!"

    # tomllib direct parsing check
    parsed = tomllib.loads(raw_content)
    assert parsed["keepassxc"]["database_path"] == db_path
    assert parsed["keepassxc"]["keyfile_path"] == kf_path
    assert parsed["keepassxc"]["excluded_groups"] == groups

    # load_config roundtrip check
    loaded = load_config(cfg_file)
    assert loaded.keepassxc.database_path == db_path
    assert loaded.keepassxc.keyfile_path == kf_path
    assert loaded.keepassxc.yubikey_slot == slot
    assert loaded.keepassxc.cli_binary == cli_bin
    assert loaded.keepassxc.excluded_groups == groups
    assert loaded.keepassxc.backend == "direct"
    assert loaded.token2.cli_binary == "custom-t2-cli"
