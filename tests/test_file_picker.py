"""Unit tests for cross-platform native file picker and headless console fallback."""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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


def test_clean_path_input_plain():
    assert clean_path_input("/path/to/vault.kdbx") == "/path/to/vault.kdbx"


def test_clean_path_input_single_quotes():
    assert clean_path_input("'/path/to/vault.kdbx'") == "/path/to/vault.kdbx"


def test_clean_path_input_double_quotes():
    assert clean_path_input('"/path/to/vault.kdbx"') == "/path/to/vault.kdbx"


def test_clean_path_input_nested_quotes():
    assert clean_path_input('\'"/path/to/vault.kdbx"\'') == "/path/to/vault.kdbx"
    assert clean_path_input('"\'/path/to/vault.kdbx\'"') == "/path/to/vault.kdbx"


def test_clean_path_input_whitespace():
    assert clean_path_input('  " /path/to/vault.kdbx "  ') == "/path/to/vault.kdbx"


def test_clean_path_input_tilde_expansion():
    res = clean_path_input("~/vault.kdbx")
    assert res == str(Path.home() / "vault.kdbx")


def test_clean_path_input_env_vars(monkeypatch):
    monkeypatch.setenv("TEST_VAULT_DIR", "/opt/secure")
    assert clean_path_input("$TEST_VAULT_DIR/vault.kdbx") == "/opt/secure/vault.kdbx"


def test_is_gui_available_win32(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert is_gui_available() is True


def test_is_gui_available_darwin(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert is_gui_available() is True


def test_is_gui_available_linux_display(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert is_gui_available() is True


def test_is_gui_available_linux_wayland(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    assert is_gui_available() is True


def test_is_gui_available_linux_headless(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    assert is_gui_available() is False


def test_format_filters():
    ft = [("KeePass DB", "*.kdbx"), ("All files", "*.*")]
    assert _format_windows_filter(ft) == "KeePass DB|*.kdbx|All files|*.*"
    assert _format_windows_filter(None) == "All files (*.*)|*.*"

    assert _format_zenity_filters(ft) == [
        "--file-filter=KeePass DB | *.kdbx",
        "--file-filter=All files | *.*",
    ]
    assert _format_zenity_filters(None) == []

    assert _format_kdialog_filter(ft) == "*.kdbx|KeePass DB\n*.*|All files"
    assert _format_kdialog_filter(None) == "*|All files (*.*)"

    assert _format_tkinter_filetypes(ft) == ft
    assert _format_tkinter_filetypes(None) == [("All files", "*.*")]


def test_pick_file_windows_success(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "C:\\Windows\\System32\\powershell.exe" if "powershell" in cmd else None)
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "C:\\vault.kdbx\r\n"
    with patch("subprocess.run", return_value=mock_proc) as mock_run:
        res = _pick_file_windows("Select DB", [("DB", "*.kdbx")], "C:\\default.kdbx")
        assert res == "C:\\vault.kdbx"
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "-Sta" in cmd
        assert "System.Windows.Forms.OpenFileDialog" in cmd[-1]


def test_pick_file_windows_cancel(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "powershell.exe")
    mock_proc = MagicMock(returncode=0, stdout="")
    with patch("subprocess.run", return_value=mock_proc):
        assert _pick_file_windows("Select DB", None, None) is None


def test_pick_file_windows_missing_binary(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: None)
    with pytest.raises(GuiUnavailableError, match="PowerShell executable not found"):
        _pick_file_windows("Select DB", None, None)


def test_pick_file_windows_error(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "powershell.exe")
    mock_proc = MagicMock(returncode=1, stderr="Failed to load assembly")
    with patch("subprocess.run", return_value=mock_proc):
        with pytest.raises(GuiUnavailableError, match="PowerShell OpenFileDialog failed"):
            _pick_file_windows("Select DB", None, None)


def test_pick_file_zenity_success(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/zenity" if cmd == "zenity" else None)
    mock_proc = MagicMock(returncode=0, stdout="/home/user/vault.kdbx\n")
    with patch("subprocess.run", return_value=mock_proc) as mock_run:
        res = _pick_file_zenity("Title", [("DB", "*.kdbx")], "/home/user/default.kdbx")
        assert res == "/home/user/vault.kdbx"
        args = mock_run.call_args[0][0]
        assert "/usr/bin/zenity" in args
        assert "--title=Title" in args


def test_pick_file_zenity_cancel(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/zenity" if cmd == "zenity" else None)
    mock_proc = MagicMock(returncode=1, stdout="")
    with patch("subprocess.run", return_value=mock_proc):
        assert _pick_file_zenity("Title", None, None) is None


def test_pick_file_zenity_error(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/zenity" if cmd == "zenity" else None)
    mock_proc = MagicMock(returncode=5, stderr="Gtk-WARNING")
    with patch("subprocess.run", return_value=mock_proc):
        with pytest.raises(GuiUnavailableError, match="zenity exited with error code 5"):
            _pick_file_zenity("Title", None, None)


def test_pick_file_kdialog_success(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/kdialog" if cmd == "kdialog" else None)
    mock_proc = MagicMock(returncode=0, stdout="/home/user/vault.kdbx\n")
    with patch("subprocess.run", return_value=mock_proc):
        res = _pick_file_kdialog("Title", None, "/home/user")
        assert res == "/home/user/vault.kdbx"


def test_pick_file_kdialog_cancel(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/kdialog" if cmd == "kdialog" else None)
    mock_proc = MagicMock(returncode=1, stdout="")
    with patch("subprocess.run", return_value=mock_proc):
        assert _pick_file_kdialog("Title", None, None) is None


def test_pick_file_macos_success(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/osascript" if cmd == "osascript" else None)
    mock_proc = MagicMock(returncode=0, stdout="/Users/test/vault.kdbx\n")
    with patch("subprocess.run", return_value=mock_proc):
        res = _pick_file_macos("Select file", None, None)
        assert res == "/Users/test/vault.kdbx"


def test_pick_file_macos_cancel(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/osascript" if cmd == "osascript" else None)
    mock_proc = MagicMock(returncode=1, stdout="")
    with patch("subprocess.run", return_value=mock_proc):
        assert _pick_file_macos("Select file", None, None) is None


def test_pick_file_macos_error(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/osascript" if cmd == "osascript" else None)
    mock_proc = MagicMock(returncode=2, stderr="execution error")
    with patch("subprocess.run", return_value=mock_proc):
        with pytest.raises(GuiUnavailableError, match="osascript error 2"):
            _pick_file_macos("Select file", None, None)


def test_pick_file_tkinter_success():
    mock_tk_module = MagicMock()
    mock_fd_module = MagicMock()
    mock_fd_module.askopenfilename.return_value = "/tmp/test.kdbx"
    mock_tk_module.filedialog = mock_fd_module
    mock_root = MagicMock()
    mock_tk_module.Tk.return_value = mock_root

    with patch.dict(sys.modules, {"tkinter": mock_tk_module, "tkinter.filedialog": mock_fd_module}):
        res = _pick_file_tkinter("Title", None, "/tmp/default.kdbx")
        assert res == "/tmp/test.kdbx"
        mock_root.withdraw.assert_called_once()
        mock_root.destroy.assert_called_once()


def test_pick_file_tkinter_cancel():
    mock_tk_module = MagicMock()
    mock_fd_module = MagicMock()
    mock_fd_module.askopenfilename.return_value = ""
    mock_tk_module.filedialog = mock_fd_module
    mock_root = MagicMock()
    mock_tk_module.Tk.return_value = mock_root

    with patch.dict(sys.modules, {"tkinter": mock_tk_module, "tkinter.filedialog": mock_fd_module}):
        assert _pick_file_tkinter("Title", None, None) is None
        mock_root.destroy.assert_called_once()


def test_pick_file_tkinter_missing():
    with patch.dict(sys.modules, {"tkinter": None}):
        with pytest.raises(GuiUnavailableError, match="Tkinter unavailable"):
            _pick_file_tkinter("Title", None, None)


def test_open_native_gui_dialog_headless(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    with pytest.raises(GuiUnavailableError, match="Graphical desktop display not available"):
        _open_native_gui_dialog("Title", None, None)


def test_prompt_file_path_valid_file(tmp_path):
    target = tmp_path / "valid.kdbx"
    target.write_bytes(b"dummy")

    with patch("builtins.input", return_value=str(target)):
        res = prompt_file_path("Enter path", must_exist=True)
        assert res == str(target.resolve())


def test_prompt_file_path_quotes_and_tilde(tmp_path, monkeypatch):
    target = tmp_path / "vault.kdbx"
    target.write_bytes(b"dummy")
    monkeypatch.setenv("HOME", str(tmp_path))

    with patch("builtins.input", return_value=f'  "~/vault.kdbx"  '):
        res = prompt_file_path("Enter path", must_exist=True)
        assert res == str(target.resolve())


def test_prompt_file_path_retry_then_success(tmp_path):
    valid = tmp_path / "valid.kdbx"
    valid.write_bytes(b"dummy")
    inputs = [str(tmp_path / "missing.kdbx"), str(valid)]

    with patch("builtins.input", side_effect=inputs), patch("sys.stdin.isatty", return_value=True):
        res = prompt_file_path("Enter path", must_exist=True, max_attempts=2)
        assert res == str(valid.resolve())


def test_prompt_file_path_directory_rejected(tmp_path):
    with patch("builtins.input", return_value=str(tmp_path)), patch("sys.stdin.isatty", return_value=False):
        res = prompt_file_path("Enter path", must_exist=True, max_attempts=1)
        assert res is None


def test_prompt_file_path_cancel_keyword():
    with patch("builtins.input", return_value="c"):
        assert prompt_file_path("Enter path") is None
    with patch("builtins.input", return_value="exit"):
        assert prompt_file_path("Enter path") is None


def test_prompt_file_path_default_accepted(tmp_path):
    target = tmp_path / "default.kdbx"
    target.write_bytes(b"dummy")

    with patch("builtins.input", return_value=""):
        res = prompt_file_path("Enter path", must_exist=True, default=str(target))
        assert res == str(target)


def test_prompt_file_path_interrupt():
    with patch("builtins.input", side_effect=KeyboardInterrupt):
        assert prompt_file_path("Enter path") is None
    with patch("builtins.input", side_effect=EOFError):
        assert prompt_file_path("Enter path") is None


def test_pick_file_gui_success(monkeypatch):
    monkeypatch.setattr("t2_kpxc_sync.file_picker._open_native_gui_dialog", lambda *a, **kw: "/picked/path.kdbx")
    assert pick_file("Select file") == "/picked/path.kdbx"


def test_pick_file_gui_fail_fallback_to_prompt(monkeypatch):
    def _mock_gui(*a, **kw):
        raise GuiUnavailableError("No GUI")

    monkeypatch.setattr("t2_kpxc_sync.file_picker._open_native_gui_dialog", _mock_gui)
    monkeypatch.setattr("t2_kpxc_sync.file_picker.prompt_file_path", lambda *a, **kw: "/prompted/path.kdbx")

    assert pick_file("Select file", allow_console_fallback=True) == "/prompted/path.kdbx"


def test_pick_file_gui_fail_no_fallback(monkeypatch):
    def _mock_gui(*a, **kw):
        raise GuiUnavailableError("No GUI")

    monkeypatch.setattr("t2_kpxc_sync.file_picker._open_native_gui_dialog", _mock_gui)
    assert pick_file("Select file", allow_console_fallback=False) is None
