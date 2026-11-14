"""Cross-platform native OS file picker and headless console fallback.

Provides native file selection dialogs via PowerShell on Windows,
zenity/kdialog/tkinter on Linux/BSD, osascript on macOS, with seamless
fallback to interactive console path entry in headless / SSH sessions.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple


class GuiUnavailableError(Exception):
    """Raised when native GUI dialog tools cannot be executed or display is absent."""
    pass


def clean_path_input(raw: str) -> str:
    """Strips whitespace, surrounding single/double/nested quotes, and expands ~ and env vars."""
    text = raw.strip()
    changed = True
    while changed and len(text) >= 2:
        changed = False
        for q in ('"', "'"):
            if text.startswith(q) and text.endswith(q):
                text = text[1:-1].strip()
                changed = True
    text = os.path.expanduser(text)
    text = os.path.expandvars(text)
    return text


def is_gui_available() -> bool:
    """Returns True if a graphical desktop environment is detected, False if headless."""
    if sys.platform in ("win32", "darwin"):
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _format_windows_filter(file_types: Optional[List[Tuple[str, str]]]) -> str:
    """Converts file_types list to .NET OpenFileDialog filter string."""
    if not file_types:
        return "All files (*.*)|*.*"
    parts = []
    for desc, pat in file_types:
        parts.append(f"{desc}|{pat}")
    return "|".join(parts)


def _format_zenity_filters(file_types: Optional[List[Tuple[str, str]]]) -> List[str]:
    """Converts file_types list to zenity --file-filter arguments."""
    if not file_types:
        return []
    args = []
    for desc, pat in file_types:
        pattern = pat.replace(";", " ")
        args.append(f"--file-filter={desc} | {pattern}")
    return args


def _format_kdialog_filter(file_types: Optional[List[Tuple[str, str]]]) -> str:
    """Converts file_types list to kdialog filter string."""
    if not file_types:
        return "*|All files (*.*)"
    lines = []
    for desc, pat in file_types:
        pattern = pat.replace(";", " ")
        lines.append(f"{pattern}|{desc}")
    return "\n".join(lines)


def _format_tkinter_filetypes(file_types: Optional[List[Tuple[str, str]]]) -> List[Tuple[str, str]]:
    """Converts file_types to tkinter filedialog format."""
    if not file_types:
        return [("All files", "*.*")]
    return [(desc, pat) for desc, pat in file_types]


def _pick_file_windows(
    title: str,
    file_types: Optional[List[Tuple[str, str]]],
    default_path: Optional[str],
) -> Optional[str]:
    """Launches OpenFileDialog via Windows PowerShell in STA mode."""
    ps_bin = (
        shutil.which("powershell.exe")
        or shutil.which("powershell")
        or shutil.which("pwsh.exe")
        or shutil.which("pwsh")
    )
    if not ps_bin:
        raise GuiUnavailableError("PowerShell executable not found")

    def _esc(s: str) -> str:
        return s.replace("'", "''")

    ps_filter = _format_windows_filter(file_types)

    script_lines = [
        "Add-Type -AssemblyName System.Windows.Forms",
        "$f = New-Object System.Windows.Forms.OpenFileDialog",
        f"$f.Title = '{_esc(title)}'",
        f"$f.Filter = '{_esc(ps_filter)}'",
        "$f.RestoreDirectory = $true",
    ]

    if default_path:
        dp = Path(default_path)
        if dp.is_dir():
            script_lines.append(f"$f.InitialDirectory = '{_esc(str(dp))}'")
        else:
            if dp.parent.exists():
                script_lines.append(f"$f.InitialDirectory = '{_esc(str(dp.parent))}'")
            script_lines.append(f"$f.FileName = '{_esc(dp.name)}'")

    script_lines.extend([
        "$res = $f.ShowDialog()",
        "if ($res -eq [System.Windows.Forms.DialogResult]::OK) {",
        "    [Console]::Out.Write($f.FileName)",
        "}",
    ])

    script = "; ".join(script_lines)

    try:
        proc = subprocess.run(
            [ps_bin, "-NoProfile", "-NonInteractive", "-Sta", "-Command", script],
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GuiUnavailableError(f"PowerShell execution failed: {exc}") from exc

    if proc.returncode == 0:
        val = proc.stdout.strip()
        return val if val else None
    else:
        raise GuiUnavailableError(f"PowerShell OpenFileDialog failed: {proc.stderr}")


def _pick_file_zenity(
    title: str,
    file_types: Optional[List[Tuple[str, str]]],
    default_path: Optional[str],
) -> Optional[str]:
    """Launches file selection dialog via zenity."""
    zenity_bin = shutil.which("zenity")
    if not zenity_bin:
        raise GuiUnavailableError("zenity not found")

    cmd = [zenity_bin, "--file-selection", f"--title={title}"]
    if default_path:
        cmd.append(f"--filename={default_path}")
    for filter_arg in _format_zenity_filters(file_types):
        cmd.append(filter_arg)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GuiUnavailableError(f"zenity invocation failed: {exc}") from exc

    if proc.returncode == 0:
        val = proc.stdout.strip()
        return val if val else None
    elif proc.returncode == 1:
        # Cancelled by user
        return None
    else:
        raise GuiUnavailableError(f"zenity exited with error code {proc.returncode}: {proc.stderr}")


def _pick_file_kdialog(
    title: str,
    file_types: Optional[List[Tuple[str, str]]],
    default_path: Optional[str],
) -> Optional[str]:
    """Launches file selection dialog via kdialog."""
    kdialog_bin = shutil.which("kdialog")
    if not kdialog_bin:
        raise GuiUnavailableError("kdialog not found")

    start_dir = default_path if default_path else "."
    k_filter = _format_kdialog_filter(file_types)
    cmd = [kdialog_bin, "--title", title, "--getopenfilename", str(start_dir), k_filter]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GuiUnavailableError(f"kdialog invocation failed: {exc}") from exc

    if proc.returncode == 0:
        val = proc.stdout.strip()
        return val if val else None
    elif proc.returncode == 1:
        # Cancelled by user
        return None
    else:
        raise GuiUnavailableError(f"kdialog exited with error code {proc.returncode}: {proc.stderr}")


def _pick_file_macos(
    title: str,
    file_types: Optional[List[Tuple[str, str]]],
    default_path: Optional[str],
) -> Optional[str]:
    """Launches AppleScript file chooser via osascript on macOS."""
    osascript_bin = shutil.which("osascript")
    if not osascript_bin:
        raise GuiUnavailableError("osascript not found")

    esc_title = title.replace('"', '\\"')
    script = f'POSIX path of (choose file with prompt "{esc_title}")'

    try:
        proc = subprocess.run([osascript_bin, "-e", script], capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise GuiUnavailableError(f"osascript invocation failed: {exc}") from exc

    if proc.returncode == 0:
        val = proc.stdout.strip()
        return val if val else None
    elif proc.returncode == 1:
        # User canceled
        return None
    else:
        raise GuiUnavailableError(f"osascript error {proc.returncode}: {proc.stderr}")


def _pick_file_tkinter(
    title: str,
    file_types: Optional[List[Tuple[str, str]]],
    default_path: Optional[str],
) -> Optional[str]:
    """Launches file dialog via standard Python tkinter."""
    try:
        import tkinter as tk
        from tkinter import filedialog
    except (ImportError, Exception) as exc:
        raise GuiUnavailableError(f"Tkinter unavailable: {exc}") from exc

    root = None
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)

        initialdir = None
        initialfile = None
        if default_path:
            dp = Path(default_path)
            if dp.is_dir():
                initialdir = str(dp)
            else:
                initialdir = str(dp.parent) if dp.parent.exists() else None
                initialfile = dp.name

        selected = filedialog.askopenfilename(
            title=title,
            initialdir=initialdir,
            initialfile=initialfile,
            filetypes=_format_tkinter_filetypes(file_types),
        )
        return selected if selected else None
    except Exception as exc:
        raise GuiUnavailableError(f"Tkinter dialog error: {exc}") from exc
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass


def _open_native_gui_dialog(
    title: str,
    file_types: Optional[List[Tuple[str, str]]],
    default_path: Optional[str],
) -> Optional[str]:
    """Attempts native GUI file dialog based on host operating system."""
    if not is_gui_available():
        raise GuiUnavailableError("Graphical desktop display not available")

    # Windows dispatch
    if sys.platform == "win32":
        try:
            return _pick_file_windows(title, file_types, default_path)
        except GuiUnavailableError:
            return _pick_file_tkinter(title, file_types, default_path)

    # macOS dispatch
    if sys.platform == "darwin":
        try:
            return _pick_file_macos(title, file_types, default_path)
        except GuiUnavailableError:
            return _pick_file_tkinter(title, file_types, default_path)

    # Linux / BSD dispatch: zenity -> kdialog -> tkinter
    if shutil.which("zenity"):
        try:
            return _pick_file_zenity(title, file_types, default_path)
        except GuiUnavailableError:
            pass

    if shutil.which("kdialog"):
        try:
            return _pick_file_kdialog(title, file_types, default_path)
        except GuiUnavailableError:
            pass

    return _pick_file_tkinter(title, file_types, default_path)


def prompt_file_path(
    prompt: str = "Enter file path",
    must_exist: bool = True,
    default: Optional[str] = None,
    max_attempts: int = 3,
) -> Optional[str]:
    """Prompt user for a file path in the terminal with validation.

    Args:
        prompt: Display prompt text.
        must_exist: Whether the path must exist as a regular file.
        default: Optional default path accepted on empty input.
        max_attempts: Maximum retry attempts before returning None.

    Returns:
        Cleaned, expanded path string, or None if cancelled or invalid.
    """
    display_prompt = (
        f"{prompt} [{default}] (or Enter to confirm, 'c' to cancel): "
        if default
        else f"{prompt} (or Enter to cancel): "
    )

    attempts = 0
    is_tty = getattr(sys.stdin, "isatty", lambda: False)()

    while attempts < max_attempts:
        attempts += 1
        try:
            raw = input(display_prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        stripped = raw.strip()
        if not stripped:
            if default:
                cleaned_default = clean_path_input(default)
                if not must_exist or Path(cleaned_default).is_file():
                    return cleaned_default
            return None

        # Check for cancel keywords unless an actual file exists with that name
        if stripped.lower() in ("c", "cancel", "q", "exit") and not Path(stripped).exists():
            return None

        cleaned = clean_path_input(stripped)
        path_obj = Path(cleaned)

        if not must_exist:
            return cleaned

        if path_obj.is_dir():
            print(f"[!] '{cleaned}' is a directory. Please enter a path to a file.")
        elif path_obj.is_file():
            return str(path_obj.resolve())
        else:
            print(f"[!] File not found: '{cleaned}'. Please check the path.")

        if not is_tty:
            break

    return None


def pick_file(
    title: str = "Select file",
    file_types: Optional[List[Tuple[str, str]]] = None,
    default_path: Optional[str] = None,
    allow_console_fallback: bool = True,
) -> Optional[str]:
    """Open native OS file dialog or fallback to console prompt if headless.

    Args:
        title: Title of dialog or console prompt.
        file_types: List of (description, pattern) tuples.
        default_path: Initial directory or default file path.
        allow_console_fallback: If True, invoke prompt_file_path() when GUI is unavailable.

    Returns:
        Selected file path string, or None if cancelled by the user.
    """
    try:
        return _open_native_gui_dialog(
            title=title,
            file_types=file_types,
            default_path=default_path,
        )
    except GuiUnavailableError:
        if allow_console_fallback:
            return prompt_file_path(
                prompt=title,
                must_exist=True,
                default=default_path,
            )
        return None
