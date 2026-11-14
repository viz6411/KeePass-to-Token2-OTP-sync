"""tests/e2e/harness.py: Headless TTY simulation and subprocess runner.

Provides:
- PseudoTTY: In-memory StringIO with isatty() == True for Rich and TUI detection.
- InteractiveTTYSession: Context manager for feeding sequential inputs to console.input()
  and getpass.getpass() without opening /dev/tty or hanging in automated test runners.
- SubprocessRunner: Timeout-guarded subprocess runner with session detachment for
  black-box CLI and binary execution.
- strip_ansi: Helper for removing terminal color and styling escape sequences.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional
from unittest.mock import patch

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def strip_ansi(text: str) -> str:
    """Removes ANSI terminal escape sequences from formatted text."""
    if not text:
        return ""
    return ANSI_ESCAPE_RE.sub("", text)


class PseudoTTY(io.StringIO):
    """StringIO subclass that reports isatty() == True and has configurable dimensions."""

    def __init__(self, initial_value: str = "", width: int = 120, height: int = 40):
        super().__init__(initial_value)
        self.width = width
        self.height = height

    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return 0


class InteractiveSessionResult:
    """Holds captured outputs and exit code from an interactive or subprocess session."""

    def __init__(self, exit_code: int, stdout: str, stderr: str = ""):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr

    @property
    def clean_text(self) -> str:
        """Returns captured stdout with all ANSI escape sequences stripped."""
        return strip_ansi(self.stdout)

    @property
    def clean_stderr(self) -> str:
        """Returns captured stderr with all ANSI escape sequences stripped."""
        return strip_ansi(self.stderr)


@contextmanager
def run_interactive_session(
    inputs: Sequence[str] | str,
    width: int = 120,
    force_tty: bool = True,
) -> Iterator[tuple[PseudoTTY, io.StringIO, io.StringIO]]:
    """Context manager feeding sequential inputs to console.input() and getpass().

    Prevents /dev/tty blocking, ensures Rich console is_terminal detection,
    and captures all terminal outputs reliably.
    """
    if isinstance(inputs, (list, tuple)):
        input_data = "\n".join(str(x) for x in inputs) + "\n"
    else:
        input_data = str(inputs)
        if not input_data.endswith("\n"):
            input_data += "\n"

    stdin_stream = (
        PseudoTTY(input_data, width=width)
        if force_tty
        else io.StringIO(input_data)
    )
    stdout_stream = io.StringIO()
    stderr_stream = io.StringIO()

    orig_stdin = sys.stdin
    orig_stdout = sys.stdout
    orig_stderr = sys.stderr

    def simulated_getpass(prompt: str = "") -> str:
        stdout_stream.write(prompt)
        line = stdin_stream.readline()
        if not line:
            raise EOFError("Unexpected EOF on getpass prompt")
        return line.rstrip("\r\n")

    sys.stdin = stdin_stream
    sys.stdout = stdout_stream
    sys.stderr = stderr_stream

    with patch("getpass.getpass", side_effect=simulated_getpass):
        try:
            yield stdin_stream, stdout_stream, stderr_stream
        finally:
            sys.stdin = orig_stdin
            sys.stdout = orig_stdout
            sys.stderr = orig_stderr


def run_cli_subprocess(
    args: list[str],
    inputs: Optional[Sequence[str] | str] = None,
    timeout: float = 5.0,
    binary_path: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
) -> InteractiveSessionResult:
    """Executes CLI or standalone binary as an isolated subprocess with strict timeout."""
    if binary_path and Path(binary_path).exists():
        cmd = [str(binary_path)] + args
    else:
        cmd = [sys.executable, "-m", "t2_kpxc_sync"] + args

    input_data = ""
    if inputs:
        if isinstance(inputs, (list, tuple)):
            input_data = "\n".join(str(x) for x in inputs) + "\n"
        else:
            input_data = str(inputs)
            if not input_data.endswith("\n"):
                input_data += "\n"

    sub_env = os.environ.copy()
    src_path = str(Path(__file__).parent.parent.parent / "src")
    existing_py_path = sub_env.get("PYTHONPATH", "")
    sub_env["PYTHONPATH"] = f"{src_path}:{existing_py_path}" if existing_py_path else src_path
    if env:
        sub_env.update(env)

    kwargs: dict[str, Any] = {}
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
    else:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=sub_env,
        **kwargs,
    )

    try:
        stdout, stderr = proc.communicate(input=input_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise TimeoutError(f"Command {' '.join(cmd)} timed out after {timeout}s! Stdout: {stdout}")

    return InteractiveSessionResult(exit_code=proc.returncode, stdout=stdout, stderr=stderr)
