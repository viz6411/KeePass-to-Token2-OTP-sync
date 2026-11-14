"""Empirical stress test harness for file_picker.py and config.py.

Stress-tests:
1. clean_path_input edge cases (quotes, spaces, Unicode, injections, empty)
2. Headless detection is_gui_available() across all platforms and env vars
3. PowerShell command construction (escaping, STA, filter formats)
4. Subprocess error handling (non-zero exits, crashes, timeouts, cancels)
5. TOML serialization and roundtrip fidelity in config.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from t2_kpxc_sync.config import (
    AppConfig,
    KeePassXCConfig,
    Token2Config,
    _toml_str,
    load_config,
    save_config,
)
from t2_kpxc_sync.file_picker import (
    GuiUnavailableError,
    _format_kdialog_filter,
    _format_tkinter_filetypes,
    _format_windows_filter,
    _format_zenity_filters,
    _open_native_gui_dialog,
    _pick_file_kdialog,
    _pick_file_macos,
    _pick_file_tkinter,
    _pick_file_windows,
    _pick_file_zenity,
    clean_path_input,
    is_gui_available,
    pick_file,
    prompt_file_path,
)


# ============================================================================
# 1. clean_path_input STRESS TESTS
# ============================================================================

class TestCleanPathInputStress:
    """Adversarial stress testing of clean_path_input."""

    def test_empty_and_whitespace(self):
        assert clean_path_input("") == ""
        assert clean_path_input(" ") == ""
        assert clean_path_input("   \t   \n   \r\n   ") == ""

    def test_surrounding_quotes_combinations(self):
        # Empty within quotes
        assert clean_path_input('""') == ""
        assert clean_path_input("''") == ""
        assert clean_path_input('"" ""') == ""  # Outer quotes peeled and inner quotes stripped
        assert clean_path_input('""""') == ""
        assert clean_path_input("''''") == ""

        # Alternating nested quotes
        assert clean_path_input('\'"/path/to/vault.kdbx"\'') == "/path/to/vault.kdbx"
        assert clean_path_input('"\'/path/to/vault.kdbx\'"') == "/path/to/vault.kdbx"
        assert clean_path_input('\'\'\'/path/to/vault.kdbx\'\'\'') == "/path/to/vault.kdbx"
        assert clean_path_input('"""/path/to/vault.kdbx"""') == "/path/to/vault.kdbx"
        assert clean_path_input('  " \' " /path/to/vault.kdbx " \' "  ') == "/path/to/vault.kdbx"

    def test_unclosed_and_mismatched_quotes(self):
        # Unclosed quotes must not crash and should leave the text as-is (except strip)
        assert clean_path_input('"/path/to/vault.kdbx') == '"/path/to/vault.kdbx'
        assert clean_path_input('/path/to/vault.kdbx"') == '/path/to/vault.kdbx"'
        assert clean_path_input("'/path/to/vault.kdbx") == "'/path/to/vault.kdbx"
        assert clean_path_input('/path/to/vault.kdbx\'') == '/path/to/vault.kdbx\''
        assert clean_path_input('"/path/to/vault.kdbx\'') == '"/path/to/vault.kdbx\''
        assert clean_path_input('\'/path/to/vault.kdbx"') == '\'/path/to/vault.kdbx"'

    def test_quotes_inside_filename(self):
        # Quotes inside the path (e.g. Linux filename with quote) must not be stripped
        assert clean_path_input('/path/to/vault "1".kdbx') == '/path/to/vault "1".kdbx'
        assert clean_path_input('"/path/to/vault \'1\'.kdbx"') == "/path/to/vault '1'.kdbx"

    def test_windows_backslashes_and_unc(self):
        win_path = r"C:\Users\Administrator\Documents\KeePass\vault.kdbx"
        assert clean_path_input(f'"{win_path}"') == win_path
        assert clean_path_input(f"'{win_path}'") == win_path

        unc_path = r"\\nas01\secure_share\keepass\vault.kdbx"
        assert clean_path_input(f'"{unc_path}"') == unc_path

    def test_spaces_preservation(self):
        spaced = "/home/user/My Documents/KeePass 2026/Database with spaces.kdbx"
        assert clean_path_input(f'  " {spaced} "  ') == spaced
        assert clean_path_input(f"  ' {spaced} '  ") == spaced

    def test_unicode_and_emojis(self):
        cyrillic = "/home/user/Документы/База данных.kdbx"
        assert clean_path_input(f'"{cyrillic}"') == cyrillic

        emoji = "/home/user/Vaults/Ключ 🔑 и замок 🔒.kdbx"
        assert clean_path_input(f'"{emoji}"') == emoji

    def test_injection_strings(self):
        # SQL injection strings
        sql_inj = "' OR '1'='1"
        assert clean_path_input(sql_inj) == sql_inj

        # HTML / XSS injection strings
        xss_inj = "<script>alert('xss')</script>"
        assert clean_path_input(xss_inj) == xss_inj

        # Shell injection attempts
        shell_inj = "/path/to/vault.kdbx; rm -rf /"
        assert clean_path_input(f'"{shell_inj}"') == shell_inj

    def test_tilde_and_environment_expansion(self, monkeypatch):
        monkeypatch.setenv("MY_VAULT_DIR", "/opt/secure/vaults")
        assert clean_path_input("$MY_VAULT_DIR/test.kdbx") == "/opt/secure/vaults/test.kdbx"
        assert clean_path_input("${MY_VAULT_DIR}/test.kdbx") == "/opt/secure/vaults/test.kdbx"
        # Undefined variable remains untouched
        assert clean_path_input("$UNDEFINED_XYZ_987/test.kdbx") == "$UNDEFINED_XYZ_987/test.kdbx"


# ============================================================================
# 2. HEADLESS DETECTION is_gui_available() STRESS TESTS
# ============================================================================

class TestHeadlessDetectionStress:
    """Adversarial stress testing of is_gui_available()."""

    def test_windows_always_true(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
        assert is_gui_available() is True

    def test_darwin_always_true(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
        assert is_gui_available() is True

    def test_linux_display_set_wayland_unset(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("DISPLAY", ":0.0")
        monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
        assert is_gui_available() is True

    def test_linux_display_unset_wayland_set(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-1")
        assert is_gui_available() is True

    def test_linux_both_set(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("DISPLAY", ":1")
        monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
        assert is_gui_available() is True

    def test_linux_both_unset(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
        assert is_gui_available() is False

    def test_linux_empty_strings(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("DISPLAY", "")
        monkeypatch.setenv("WAYLAND_DISPLAY", "")
        assert is_gui_available() is False

    def test_freebsd_checks_env(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "freebsd13")
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
        assert is_gui_available() is False
        monkeypatch.setenv("DISPLAY", ":0")
        assert is_gui_available() is True


# ============================================================================
# 3. WINDOWS POWERSHELL COMMAND CONSTRUCTION STRESS TESTS
# ============================================================================

class TestWindowsPowerShellConstructionStress:
    """Stress testing PowerShell command generation and escaping."""

    def test_powershell_binary_lookup_precedence(self, monkeypatch):
        lookups = []

        def mock_which(cmd):
            lookups.append(cmd)
            if cmd == "pwsh":
                return "C:\\Program Files\\PowerShell\\7\\pwsh.exe"
            return None

        monkeypatch.setattr("shutil.which", mock_which)
        mock_proc = MagicMock(returncode=0, stdout="C:\\vault.kdbx\r\n")
        with patch("subprocess.run", return_value=mock_proc):
            res = _pick_file_windows("Select", None, None)
            assert res == "C:\\vault.kdbx"
            assert "powershell.exe" in lookups
            assert "powershell" in lookups
            assert "pwsh.exe" in lookups
            assert "pwsh" in lookups

    def test_powershell_command_flags(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda cmd: "powershell.exe")
        mock_proc = MagicMock(returncode=0, stdout="C:\\vault.kdbx")
        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            _pick_file_windows("Select", None, None)
            args = mock_run.call_args[0][0]
            assert args[0] == "powershell.exe"
            assert "-NoProfile" in args
            assert "-NonInteractive" in args
            assert "-Sta" in args
            assert "-Command" in args

    def test_powershell_title_single_quotes_and_injection(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda cmd: "powershell.exe")
        mock_proc = MagicMock(returncode=0, stdout="C:\\vault.kdbx")
        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            title = "O'Connor's Vault; Remove-Item -Force C:\\; Write-Host '$(rm -rf)'"
            _pick_file_windows(title, None, None)
            cmd = mock_run.call_args[0][0][-1]

            # Verify single quotes are escaped by doubling them
            assert "$f.Title = 'O''Connor''s Vault; Remove-Item -Force C:\\; Write-Host ''$(rm -rf)'''" in cmd

    def test_powershell_filter_formatting_and_escaping(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda cmd: "powershell.exe")
        mock_proc = MagicMock(returncode=0, stdout="C:\\vault.kdbx")
        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            filters = [
                ("User's Database", "*.kdbx"),
                ("All files (*.*)", "*.*"),
            ]
            _pick_file_windows("Title", filters, None)
            cmd = mock_run.call_args[0][0][-1]
            assert "$f.Filter = 'User''s Database|*.kdbx|All files (*.*)|*.*'" in cmd

    def test_powershell_default_path_directory(self, monkeypatch, tmp_path):
        monkeypatch.setattr("shutil.which", lambda cmd: "powershell.exe")
        mock_proc = MagicMock(returncode=0, stdout="")
        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            _pick_file_windows("Title", None, str(tmp_path))
            cmd = mock_run.call_args[0][0][-1]
            assert f"$f.InitialDirectory = '{tmp_path}'" in cmd
            assert "$f.FileName =" not in cmd

    def test_powershell_default_path_file_with_existing_parent(self, monkeypatch, tmp_path):
        monkeypatch.setattr("shutil.which", lambda cmd: "powershell.exe")
        mock_proc = MagicMock(returncode=0, stdout="")
        target = tmp_path / "my'vault.kdbx"
        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            _pick_file_windows("Title", None, str(target))
            cmd = mock_run.call_args[0][0][-1]
            assert f"$f.InitialDirectory = '{tmp_path}'" in cmd
            assert "$f.FileName = 'my''vault.kdbx'" in cmd


# ============================================================================
# 4. SUBPROCESS ERROR HANDLING STRESS TESTS
# ============================================================================

class TestSubprocessErrorHandlingStress:
    """Stress testing error handling, timeouts, crashes, and cancellations."""

    def test_zenity_cancel_vs_crash(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/zenity" if cmd == "zenity" else None)

        # Code 1: User explicitly canceled dialog -> returns None
        mock_cancel = MagicMock(returncode=1, stdout="", stderr="")
        with patch("subprocess.run", return_value=mock_cancel):
            assert _pick_file_zenity("Title", None, None) is None

        # Code 5 / 255: Gtk display error -> raises GuiUnavailableError
        mock_gtk_err = MagicMock(returncode=5, stdout="", stderr="Gtk-WARNING: cannot open display")
        with patch("subprocess.run", return_value=mock_gtk_err):
            with pytest.raises(GuiUnavailableError, match="zenity exited with error code 5"):
                _pick_file_zenity("Title", None, None)

        # Code -11: Segmentation fault
        mock_segfault = MagicMock(returncode=-11, stdout="", stderr="Segmentation fault")
        with patch("subprocess.run", return_value=mock_segfault):
            with pytest.raises(GuiUnavailableError, match="zenity exited with error code -11"):
                _pick_file_zenity("Title", None, None)

    def test_zenity_timeout_and_oserror(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/zenity" if cmd == "zenity" else None)

        # TimeoutExpired
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["zenity"], timeout=5)):
            with pytest.raises(GuiUnavailableError, match="zenity invocation failed"):
                _pick_file_zenity("Title", None, None)

        # PermissionError / OSError
        with patch("subprocess.run", side_effect=PermissionError("Permission denied")):
            with pytest.raises(GuiUnavailableError, match="zenity invocation failed"):
                _pick_file_zenity("Title", None, None)

    def test_kdialog_cancel_vs_error(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/kdialog" if cmd == "kdialog" else None)

        # Code 1: User cancel
        mock_cancel = MagicMock(returncode=1, stdout="", stderr="")
        with patch("subprocess.run", return_value=mock_cancel):
            assert _pick_file_kdialog("Title", None, None) is None

        # Code 2: Error
        mock_err = MagicMock(returncode=2, stdout="", stderr="kdialog: error")
        with patch("subprocess.run", return_value=mock_err):
            with pytest.raises(GuiUnavailableError, match="kdialog exited with error code 2"):
                _pick_file_kdialog("Title", None, None)

        # TimeoutExpired
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["kdialog"], timeout=5)):
            with pytest.raises(GuiUnavailableError, match="kdialog invocation failed"):
                _pick_file_kdialog("Title", None, None)

    def test_macos_osascript_cancel_vs_error(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/osascript" if cmd == "osascript" else None)

        # Code 1: User cancel
        mock_cancel = MagicMock(returncode=1, stdout="", stderr="")
        with patch("subprocess.run", return_value=mock_cancel):
            assert _pick_file_macos("Title", None, None) is None

        # Code 2: Error
        mock_err = MagicMock(returncode=2, stdout="", stderr="syntax error")
        with patch("subprocess.run", return_value=mock_err):
            with pytest.raises(GuiUnavailableError, match="osascript error 2"):
                _pick_file_macos("Title", None, None)

    def test_linux_fallback_cascade(self, monkeypatch):
        """If zenity crashes, kdialog should be attempted; if kdialog crashes, tkinter should be attempted."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("DISPLAY", ":0")

        # Both zenity and kdialog exist
        monkeypatch.setattr("shutil.which", lambda cmd: f"/usr/bin/{cmd}" if cmd in ("zenity", "kdialog") else None)

        calls = []

        def mock_zenity(*a, **kw):
            calls.append("zenity")
            raise GuiUnavailableError("zenity crashed")

        def mock_kdialog(*a, **kw):
            calls.append("kdialog")
            raise GuiUnavailableError("kdialog crashed")

        def mock_tkinter(*a, **kw):
            calls.append("tkinter")
            return "/tmp/selected.kdbx"

        monkeypatch.setattr("t2_kpxc_sync.file_picker._pick_file_zenity", mock_zenity)
        monkeypatch.setattr("t2_kpxc_sync.file_picker._pick_file_kdialog", mock_kdialog)
        monkeypatch.setattr("t2_kpxc_sync.file_picker._pick_file_tkinter", mock_tkinter)

        res = _open_native_gui_dialog("Title", None, None)
        assert res == "/tmp/selected.kdbx"
        assert calls == ["zenity", "kdialog", "tkinter"]

    def test_linux_cancel_stops_cascade(self, monkeypatch):
        """If user clicks Cancel in zenity (returns None), do NOT cascade to kdialog or tkinter."""
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setenv("DISPLAY", ":0")
        monkeypatch.setattr("shutil.which", lambda cmd: f"/usr/bin/{cmd}" if cmd in ("zenity", "kdialog") else None)

        calls = []

        def mock_zenity(*a, **kw):
            calls.append("zenity")
            return None  # Cancelled!

        def mock_kdialog(*a, **kw):
            calls.append("kdialog")
            return "/tmp/kdialog.kdbx"

        monkeypatch.setattr("t2_kpxc_sync.file_picker._pick_file_zenity", mock_zenity)
        monkeypatch.setattr("t2_kpxc_sync.file_picker._pick_file_kdialog", mock_kdialog)

        res = _open_native_gui_dialog("Title", None, None)
        assert res is None
        assert calls == ["zenity"]  # Stopped immediately!

    def test_pick_file_fallback_to_console_on_gui_failure(self, monkeypatch):
        monkeypatch.setattr("t2_kpxc_sync.file_picker._open_native_gui_dialog", MagicMock(side_effect=GuiUnavailableError("Headless")))
        monkeypatch.setattr("t2_kpxc_sync.file_picker.prompt_file_path", lambda *a, **kw: "/from/console.kdbx")

        assert pick_file("Prompt", allow_console_fallback=True) == "/from/console.kdbx"
        assert pick_file("Prompt", allow_console_fallback=False) is None


# ============================================================================
# 5. TOML SERIALIZATION & ROUNDTRIP FIDELITY STRESS TESTS
# ============================================================================

class TestConfigTomlSerializationStress:
    """Stress testing TOML serialization and deserialization roundtrips in config.py."""

    def test_standard_roundtrip(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg = AppConfig(
            keepassxc=KeePassXCConfig(
                database_path="/home/user/vault.kdbx",
                keyfile_path="/home/user/vault.key",
                yubikey_slot="1",
                cli_binary="keepassxc-cli",
                excluded_groups=["Recycle Bin", "Archive", "Backups"],
                backend="direct",
            ),
            token2=Token2Config(cli_binary="token2-otp-cli"),
        )
        save_config(cfg, cfg_file)
        loaded = load_config(cfg_file)
        assert loaded.keepassxc.database_path == cfg.keepassxc.database_path
        assert loaded.keepassxc.keyfile_path == cfg.keepassxc.keyfile_path
        assert loaded.keepassxc.yubikey_slot == cfg.keepassxc.yubikey_slot
        assert loaded.keepassxc.cli_binary == cfg.keepassxc.cli_binary
        assert loaded.keepassxc.excluded_groups == cfg.keepassxc.excluded_groups
        assert loaded.keepassxc.backend == cfg.keepassxc.backend
        assert loaded.token2.cli_binary == cfg.token2.cli_binary

    def test_windows_paths_with_backslashes_and_spaces(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        win_db = r"C:\Users\John Doe\AppData\Local\KeePassXC\Vault 2026\personal_vault.kdbx"
        win_kf = r"D:\Keys & Secrets\usb_key.key"
        cfg = AppConfig(
            keepassxc=KeePassXCConfig(
                database_path=win_db,
                keyfile_path=win_kf,
                excluded_groups=[r"Deleted Items\Old", r"Drafts & Temp"],
            )
        )
        save_config(cfg, cfg_file)
        loaded = load_config(cfg_file)
        assert loaded.keepassxc.database_path == win_db
        assert loaded.keepassxc.keyfile_path == win_kf
        assert loaded.keepassxc.excluded_groups == [r"Deleted Items\Old", r"Drafts & Temp"]

    def test_bmp_cyrillic_unicode_roundtrip(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cyr_db = "/home/пользователь/Документы/БазаДанных.kdbx"
        cfg = AppConfig(
            keepassxc=KeePassXCConfig(
                database_path=cyr_db,
                excluded_groups=["Корзина", "Архивные записи", "Устаревшее"],
            )
        )
        save_config(cfg, cfg_file)
        loaded = load_config(cfg_file)
        assert loaded.keepassxc.database_path == cyr_db
        assert loaded.keepassxc.excluded_groups == ["Корзина", "Архивные записи", "Устаревшее"]

    def test_quotes_and_special_chars_in_paths_and_groups(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        special_db = '/opt/vaults/O\'Reilly "Special" Database (v2.1).kdbx'
        cfg = AppConfig(
            keepassxc=KeePassXCConfig(
                database_path=special_db,
                excluded_groups=['Group "One"', "O'Connor's Secrets", "Group; with; semicolons"],
            )
        )
        save_config(cfg, cfg_file)
        loaded = load_config(cfg_file)
        assert loaded.keepassxc.database_path == special_db
        assert loaded.keepassxc.excluded_groups == ['Group "One"', "O'Connor's Secrets", "Group; with; semicolons"]

    def test_empty_excluded_groups(self, tmp_path):
        cfg_file = tmp_path / "config.toml"
        cfg = AppConfig(
            keepassxc=KeePassXCConfig(
                database_path="/tmp/db.kdbx",
                excluded_groups=[],
            )
        )
        save_config(cfg, cfg_file)
        loaded = load_config(cfg_file)
        assert loaded.keepassxc.excluded_groups == []

    def test_non_bmp_unicode_emoji_roundtrip(self, tmp_path):
        """Tests whether paths and groups with non-BMP characters (emojis 🔑, 🔒, 🗑️) survive roundtrip."""
        cfg_file = tmp_path / "config.toml"
        emoji_db = "/home/user/vault 🔑/secret 🔒 database.kdbx"
        emoji_groups = ["Recycle Bin 🗑️", "Secure 🛡️", "Key Vault 🔑"]
        cfg = AppConfig(
            keepassxc=KeePassXCConfig(
                database_path=emoji_db,
                excluded_groups=emoji_groups,
            )
        )
        save_config(cfg, cfg_file)
        loaded = load_config(cfg_file)
        # Check if non-BMP emoji roundtrips or triggers bug
        assert loaded.keepassxc.database_path == emoji_db
        assert loaded.keepassxc.excluded_groups == emoji_groups

    def test_non_bmp_unicode_emoji_regression_guard(self, tmp_path):
        """Verifies that non-BMP emojis are serialized as raw UTF-8 and never as surrogate pairs."""
        import tomllib
        cfg_file = tmp_path / "config.toml"
        emoji_db = "/home/user/vault 🔑/secret 🔒 database.kdbx"
        cfg = AppConfig(keepassxc=KeePassXCConfig(database_path=emoji_db))
        save_config(cfg, cfg_file)

        content = cfg_file.read_text(encoding="utf-8")
        assert r"\ud83d\udd11" not in content
        assert "🔑" in content

        # Demonstrates that standard tomllib parses raw UTF-8 basic strings without error
        data = tomllib.loads(content)
        assert data["keepassxc"]["database_path"] == emoji_db

        # Demonstrates that load_config correctly restores the configuration
        loaded = load_config(cfg_file)
        assert loaded.keepassxc.database_path == emoji_db
