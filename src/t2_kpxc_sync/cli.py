"""Command-line interface and Rich TUI for KeePassXC to Token2 synchronization."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path
from typing import Optional, Sequence

from rich.console import Console

from .config import AppConfig, get_default_config_path, load_config
from .diff import compute_diff
from .kpxc import KeePassXCError, read_kpxc_entries
from .models import TOTPEntry, Token2Profile
from .security import scrub_bytes
from .token2 import Token2Adapter, Token2Error, Token2PINError

# Backwards compatibility alias for tests patching Token2CLIAdapter
Token2CLIAdapter = Token2Adapter
from .tui import (
    apply_sync,
    display_diff_table,
    find_free_slots,
    prompt_entry_format,
    run_interactive_menu,
    run_main_menu,
    run_onboarding_wizard,
)

console = Console()

__all__ = [
    "console",
    "display_diff_table",
    "find_free_slots",
    "apply_sync",
    "prompt_entry_format",
    "run_interactive_menu",
    "run_onboarding_wizard",
    "run_main_menu",
    "main",
]


def _has_explicit_batch_args(args: argparse.Namespace) -> bool:
    """Checks whether explicit command-line execution parameters were passed."""
    return bool(
        args.kdbx is not None
        or args.dry_run
        or args.mode is not None
        or args.keyfile is not None
        or args.yubikey is not None
        or args.yes
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main CLI entry point coordinating interactive TUI vs batch execution."""
    parser = argparse.ArgumentParser(
        prog="t2-kpxc-sync",
        description="Zero-disk-footprint KeePassXC to Token2 PIN+ R3.3 TOTP synchronizer",
    )
    parser.add_argument("--config", help="Path to config.toml", type=Path)
    parser.add_argument("--db", "--kdbx", dest="kdbx", help="Path to KeePassXC .kdbx file", type=Path)
    parser.add_argument("--key-file", dest="keyfile", help="Path to KeePassXC key file", type=Path)
    parser.add_argument("--yubikey", help="YubiKey slot:serial", type=str)
    parser.add_argument("--dry-run", action="store_true", help="Only show differences, do not write to token")
    parser.add_argument(
        "--mode",
        choices=["add_only", "add_update", "full_sync", "cancel"],
        help="Non-interactive execution mode",
    )
    parser.add_argument("-y", "--yes", action="store_true", help="Confirm deletions without prompting")
    parser.add_argument(
        "--button-required",
        dest="button_required",
        action="store_true",
        default=None,
        help="Require physical button press/touch on Token2 token to display code",
    )
    parser.add_argument("--tui", action="store_true", help="Launch interactive TUI management interface")

    args = parser.parse_args(argv)

    cfg: AppConfig = load_config(args.config)
    target_config_path = Path(args.config) if args.config else get_default_config_path()

    has_batch_args = _has_explicit_batch_args(args)
    is_interactive_tty = getattr(sys.stdin, "isatty", lambda: False)()

    # Route to interactive TUI if explicitly requested (--tui) OR if launched without batch args in interactive TTY
    if args.tui or (not has_batch_args and is_interactive_tty):
        if args.kdbx:
            cfg.keepassxc.database_path = str(args.kdbx)

        # First-run onboarding if config missing or database_path not set
        if not target_config_path.exists() or not cfg.keepassxc.database_path.strip():
            try:
                cfg = run_onboarding_wizard(config_path=target_config_path, con=console)
            except (KeyboardInterrupt, EOFError):
                console.print("\n[yellow]Setup cancelled by user.[/yellow]")
                return 0
            except Exception as err:
                console.print(f"[bold red]Onboarding error: {err}[/bold red]")
                return 1

        try:
            run_main_menu(cfg, config_path=target_config_path, con=console)
            return 0
        except (KeyboardInterrupt, EOFError):
            return 0

    # Batch / Non-Interactive CLI execution flow (100% backward compatible)
    db_path = args.kdbx or (Path(cfg.keepassxc.database_path) if cfg.keepassxc.database_path else None)
    if not db_path:
        console.print("[bold red]Error: No KeePassXC database specified. Use --db or configure config.toml[/bold red]")
        return 1

    keyfile_path = args.keyfile or (Path(cfg.keepassxc.keyfile_path) if cfg.keepassxc.keyfile_path else None)
    yubikey_slot = args.yubikey or cfg.keepassxc.yubikey_slot or None

    password_buf: bytearray | None = None
    pin_buf: bytearray | None = None

    try:
        raw_pwd = getpass.getpass("Enter KeePassXC Master Password (or Enter if none): ")
        if raw_pwd:
            password_buf = bytearray(raw_pwd.encode("utf-8"))
            del raw_pwd

        raw_pin = getpass.getpass("Enter Token2 PIN (or Enter if none): ")
        if raw_pin:
            pin_buf = bytearray(raw_pin.encode("utf-8"))
            del raw_pin

        # Read KeePassXC in RAM
        console.print("[cyan]Reading KeePassXC database...[/cyan]")
        try:
            kpxc_entries = read_kpxc_entries(
                db_path=db_path,
                password=password_buf,
                keyfile_path=keyfile_path,
                yubikey_slot=yubikey_slot,
                cli_binary=cfg.keepassxc.cli_binary,
                excluded_groups=cfg.keepassxc.excluded_groups,
            )
        except KeePassXCError as err:
            console.print(f"[bold red]KeePassXC Error: {err}[/bold red]")
            return 1

        # Query Token2
        console.print("[cyan]Connecting to Token2 hardware token...[/cyan]")
        adapter = Token2CLIAdapter(
            backend=getattr(cfg.token2, "backend", "auto"),
            cli_binary=cfg.token2.cli_binary,
            pin=pin_buf,
        )
        try:
            adapter.open()
            token_profiles = adapter.get_all()
        except Token2PINError as err:
            console.print(f"[bold red]Token2 Security Error: {err}[/bold red]")
            console.print("[bold red]Aborting immediately to prevent token lockout.[/bold red]")
            return 2
        except Token2Error as err:
            console.print(f"[bold red]Token2 Error: {err}[/bold red]")
            return 1

        # Diff computation
        diff = compute_diff(kpxc_entries, token_profiles)
        display_diff_table(diff, total_current_slots=len(token_profiles), con=console)

        if diff.duplicates:
            console.print(f"[bold yellow]Warning: {len(diff.duplicates)} duplicate entries detected in KeePassXC![/bold yellow]")

        if not diff.to_add and not diff.to_update and not diff.to_delete:
            console.print("[bold green]Token2 is already up to date with KeePassXC. Nothing to do.[/bold green]")
            return 0

        if args.dry_run:
            console.print("[yellow]Dry-run requested: no changes written to Token2.[/yellow]")
            return 0

        if diff.is_capacity_exceeded:
            console.print("[bold red]Error: Token capacity (300 slots) exceeded. Synchronisation cannot continue.[/bold red]")
            return 1

        mode = args.mode or run_interactive_menu(con=console)
        confirm_delete = not args.yes

        # Determine TOTP entry format (prompt if interactive, else CLI flag or config)
        if args.button_required is not None:
            btn_flag = 1 if args.button_required else 0
        elif args.mode is not None:
            btn_flag = 1 if cfg.token2.button_required else 0
        else:
            btn_flag = prompt_entry_format(default_button_required=cfg.token2.button_required, con=console)

        try:
            apply_sync(
                adapter=adapter,
                diff=diff,
                existing_profiles=token_profiles,
                mode=mode,
                confirm_delete=confirm_delete,
                con=console,
                btn_flag=btn_flag,
            )
        finally:
            adapter.close()

        return 0
    finally:
        if password_buf is not None:
            scrub_bytes(password_buf)
        if pin_buf is not None:
            scrub_bytes(pin_buf)


if __name__ == "__main__":
    sys.exit(main())
