"""Adapter for interacting with Token2 PIN+ hardware tokens via token2-otp-cli."""

import json
import subprocess
from typing import Any, Optional

from .models import TOTPEntry, Token2Profile
from .security import scrub_bytes


class Token2Error(Exception):
    """Base exception for Token2 CLI operations."""
    pass


class Token2PINError(Token2Error):
    """Raised when PIN authentication fails. Immediate abort without retries."""
    pass


def build_get_all_command(cli_binary: str = "token2-otp-cli") -> list[str]:
    """Builds CLI command to list all token profiles in JSON format."""
    return [cli_binary, "get_all", "--json"]


def build_write_command(
    cli_binary: str,
    slot: int,
    issuer: str,
    account: str,
    secret: str,
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30,
) -> list[str]:
    """Builds CLI command to write a TOTP profile to a specific slot."""
    return [
        cli_binary,
        "write_entry",
        "--slot",
        str(slot),
        "--issuer",
        issuer,
        "--account",
        account,
        "--secret",
        secret,
        "--algorithm",
        algorithm,
        "--digits",
        str(digits),
        "--period",
        str(period),
    ]


def build_delete_command(cli_binary: str, slot: int) -> list[str]:
    """Builds CLI command to delete a profile from a specific slot."""
    return [cli_binary, "delete_entry", "--slot", str(slot)]


def parse_entries_json(json_data: str | bytes) -> list[Token2Profile]:
    """Parses JSON output from token2-otp-cli get_all --json into Token2Profile objects."""
    if isinstance(json_data, (bytes, bytearray)):
        json_data = json_data.decode("utf-8", errors="replace")

    try:
        parsed = json.loads(json_data)
    except json.JSONDecodeError as err:
        raise Token2Error(f"Failed to parse Token2 JSON output: {err}") from err

    raw_list: list[dict[str, Any]]
    if isinstance(parsed, list):
        raw_list = parsed
    elif isinstance(parsed, dict):
        if "entries" in parsed and isinstance(parsed["entries"], list):
            raw_list = parsed["entries"]
        elif "profiles" in parsed and isinstance(parsed["profiles"], list):
            raw_list = parsed["profiles"]
        elif "data" in parsed and isinstance(parsed["data"], list):
            raw_list = parsed["data"]
        else:
            raw_list = []
    else:
        raise Token2Error(f"Unexpected JSON structure from Token2 CLI: {type(parsed)}")

    profiles: list[Token2Profile] = []
    for item in raw_list:
        if not isinstance(item, dict):
            continue

        slot_raw = item.get("slot")
        if slot_raw is None:
            continue
        try:
            slot = int(slot_raw)
        except ValueError:
            continue

        issuer = str(item.get("issuer") or "").strip()
        account = str(item.get("account") or item.get("name") or item.get("label") or "").strip()
        algorithm = str(item.get("algorithm") or "SHA1").strip().upper()

        try:
            digits = int(item.get("digits") or 6)
        except ValueError:
            digits = 6

        try:
            period = int(item.get("period") or 30)
        except ValueError:
            period = 30

        current_otp = item.get("current_otp") or item.get("otp") or item.get("code")
        if current_otp is not None:
            current_otp = str(current_otp).strip()

        profiles.append(
            Token2Profile(
                slot=slot,
                issuer=issuer,
                account=account,
                algorithm=algorithm,
                digits=digits,
                period=period,
                current_otp=current_otp,
            )
        )

    return profiles


class Token2CLIAdapter:
    """Interacts with Token2 PIN+ R3.3 hardware device via token2-otp-cli."""

    def __init__(
        self,
        cli_binary: str = "token2-otp-cli",
        pin: str | bytes | bytearray | None = None,
    ):
        self.cli_binary = cli_binary
        self._pin_buf: Optional[bytearray] = None
        if pin is not None:
            if isinstance(pin, (bytes, bytearray)):
                self._pin_buf = bytearray(pin)
            else:
                self._pin_buf = bytearray(str(pin).encode("utf-8"))

    def close(self) -> None:
        """Scrubs PIN buffer from memory."""
        if self._pin_buf is not None:
            scrub_bytes(self._pin_buf)
            self._pin_buf = None

    def __enter__(self) -> "Token2CLIAdapter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _execute(self, cmd: list[str]) -> str:
        """Executes CLI command, feeding PIN via stdin to prevent argv leak."""
        stdin_data: bytearray | None = None
        try:
            if self._pin_buf is not None:
                stdin_data = bytearray(self._pin_buf) + b"\n"
            else:
                stdin_data = bytearray(b"\n")

            try:
                proc = subprocess.run(
                    cmd,
                    input=bytes(stdin_data),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
            except FileNotFoundError as err:
                raise Token2Error(f"Token2 CLI binary not found: '{self.cli_binary}'") from err
            except Exception as err:
                raise Token2Error(f"Error executing Token2 CLI: {err}") from err

            stdout_str = proc.stdout.decode("utf-8", errors="replace")
            stderr_str = proc.stderr.decode("utf-8", errors="replace").strip()

            if proc.returncode != 0:
                combined_err = f"{stderr_str} {stdout_str}".lower()
                # Check for PIN error - immediate abort without retry to protect hardware lockout
                if "pin" in combined_err or "auth" in combined_err or "wrong pin" in combined_err:
                    raise Token2PINError(
                        f"Token2 PIN authentication failed: {stderr_str or stdout_str}"
                    )
                raise Token2Error(
                    f"Token2 CLI command failed (exit code {proc.returncode}): {stderr_str or stdout_str}"
                )

            return stdout_str
        finally:
            if stdin_data is not None:
                scrub_bytes(stdin_data)

    def get_all(self) -> list[Token2Profile]:
        """Lists all profiles stored on the hardware token."""
        cmd = build_get_all_command(self.cli_binary)
        output = self._execute(cmd)
        return parse_entries_json(output)

    def write_entry(self, slot: int, entry: TOTPEntry) -> None:
        """Writes or updates a TOTP profile at specified slot."""
        cmd = build_write_command(
            cli_binary=self.cli_binary,
            slot=slot,
            issuer=entry.issuer,
            account=entry.account,
            secret=entry.secret,
            algorithm=entry.algorithm,
            digits=entry.digits,
            period=entry.period,
        )
        self._execute(cmd)

    def delete_entry(self, slot: int) -> None:
        """Deletes a profile from specified slot."""
        cmd = build_delete_command(self.cli_binary, slot)
        self._execute(cmd)
