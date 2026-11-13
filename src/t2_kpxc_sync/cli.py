"""Command-line interface and Rich TUI for KeePassXC to Token2 synchronization."""

import argparse
import getpass
import sys
from pathlib import Path
from typing import Optional, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import AppConfig, load_config
from .diff import TOKEN2_MAX_CAPACITY, DiffResult, compute_diff
from .kpxc import KeePassXCError, read_kpxc_entries
from .models import TOTPEntry, Token2Profile
from .security import SecureBuffer, scrub_bytes
from .token2 import Token2CLIAdapter, Token2Error, Token2PINError

console = Console()


def display_diff_table(diff: DiffResult, total_current_slots: int) -> None:
    """Displays formatted Rich table of differences between KeePassXC and Token2."""
    table = Table(title="TOTP Synchronization Plan", show_header=True, header_style="bold magenta")
    table.add_column("Action", style="bold", width=12)
    table.add_column("Issuer", style="cyan")
    table.add_column("Account", style="white")
    table.add_column("Details", style="dim")

    for entry in diff.to_add:
        table.add_row(
            "[green]+ ADD[/green]",
            entry.issuer,
            entry.account,
            f"{entry.algorithm} | {entry.digits}d | {entry.period}s",
        )

    for entry, profile in diff.to_update:
        table.add_row(
            "[yellow]~ UPDATE[/yellow]",
            entry.issuer,
            entry.account,
            f"Slot {profile.slot} -> {entry.algorithm}/{entry.digits}d/{entry.period}s",
        )

    for profile in diff.to_delete:
        table.add_row(
            "[red]- DELETE[/red]",
            profile.issuer,
            profile.account,
            f"Slot {profile.slot} (not in KeePassXC)",
        )

    for entry in diff.skipped:
        table.add_row(
            "[dim]SKIP[/dim]",
            entry.issuer,
            entry.account,
            f"Incompatible: {entry.algorithm}/{entry.digits}d/{entry.period}s",
        )

    console.print(table)

    summary_text = (
        f"[bold]Token2 Capacity:[/bold] {total_current_slots} / {TOKEN2_MAX_CAPACITY} slots used\n"
        f"[green]• To Add:[/green] {len(diff.to_add)}\n"
        f"[yellow]• To Update:[/yellow] {len(diff.to_update)}\n"
        f"[red]• To Delete:[/red] {len(diff.to_delete)}\n"
        f"[dim]• Incompatible / Skipped:[/dim] {len(diff.skipped)}\n"
        f"[bold]Projected Slots After Full Sync:[/bold] {diff.final_slot_count} / {TOKEN2_MAX_CAPACITY}"
    )

    if diff.is_capacity_exceeded:
        summary_text += "\n\n[bold red]WARNING: Capacity limit of 300 slots would be exceeded![/bold red]"

    console.print(Panel(summary_text, title="Summary", border_style="cyan"))


def find_free_slots(occupied_slots: Sequence[int], max_capacity: int = TOKEN2_MAX_CAPACITY) -> list[int]:
    """Returns sorted list of available slots in range 1..max_capacity."""
    occupied = set(occupied_slots)
    return [s for s in range(1, max_capacity + 1) if s not in occupied]


def apply_sync(
    adapter: Token2CLIAdapter,
    diff: DiffResult,
    existing_profiles: list[Token2Profile],
    mode: str,
    confirm_delete: bool = True,
) -> int:
    """Applies sync operations to the Token2 hardware token based on selected mode.

    Modes:
      - 'add_only': Only adds new entries
      - 'add_update': Adds new entries and updates modified ones
      - 'full_sync': Adds new, updates modified, and deletes obsolete entries
      - 'cancel': Aborts without changes

    Returns number of executed operations.
    """
    normalized_mode = mode.strip().lower()
    if normalized_mode in ("cancel", "4"):
        console.print("[yellow]Sync cancelled by user.[/yellow]")
        return 0

    if diff.is_capacity_exceeded and normalized_mode in ("add_only", "1", "add_update", "2", "full_sync", "3"):
        raise Token2Error(
            f"Cannot proceed: final slot count {diff.final_slot_count} exceeds hardware limit {TOKEN2_MAX_CAPACITY}"
        )

    ops_count = 0
    occupied = {p.slot for p in existing_profiles}

    # 1. Full Sync Deletions
    if normalized_mode in ("full_sync", "3") and diff.to_delete:
        if confirm_delete:
            ans = console.input(
                f"[bold red]Confirm deleting {len(diff.to_delete)} profiles from Token2? [y/N]: [/bold red]"
            )
            if ans.strip().lower() not in ("y", "yes"):
                console.print("[yellow]Aborted deletion on user request.[/yellow]")
                return ops_count

        for profile in diff.to_delete:
            console.print(f"[red]Deleting slot {profile.slot}: {profile.issuer} ({profile.account})...[/red]")
            adapter.delete_entry(profile.slot)
            occupied.discard(profile.slot)
            ops_count += 1

    # 2. Updates (delete old slot, then write updated entry)
    if normalized_mode in ("add_update", "2", "full_sync", "3") and diff.to_update:
        for entry, profile in diff.to_update:
            console.print(f"[yellow]Updating slot {profile.slot}: {entry.issuer} ({entry.account})...[/yellow]")
            adapter.delete_entry(profile.slot)
            adapter.write_entry(profile.slot, entry)
            ops_count += 1

    # 3. Additions
    if normalized_mode in ("add_only", "1", "add_update", "2", "full_sync", "3") and diff.to_add:
        free_slots = find_free_slots(list(occupied))
        if len(free_slots) < len(diff.to_add):
            raise Token2Error(f"Not enough free slots: {len(free_slots)} available, {len(diff.to_add)} needed")

        for entry in diff.to_add:
            slot = free_slots.pop(0)
            console.print(f"[green]Adding to slot {slot}: {entry.issuer} ({entry.account})...[/green]")
            adapter.write_entry(slot, entry)
            occupied.add(slot)
            ops_count += 1

    console.print(f"[bold green]Successfully performed {ops_count} operations.[/bold green]")
    return ops_count


def run_interactive_menu() -> str:
    """Prompts user to select synchronization mode."""
    console.print("\n[bold]Select action:[/bold]")
    console.print("  [1] Add Only (write missing entries)")
    console.print("  [2] Add & Update (write missing and overwrite changed entries)")
    console.print("  [3] Full Sync (Add, Update, and delete obsolete entries)")
    console.print("  [4] Cancel (exit without changes)")

    choice = console.input("[bold cyan]Enter choice [1-4] (default: 4): [/bold cyan]").strip()
    return choice or "4"


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main CLI entry point."""
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

    args = parser.parse_args(argv)

    cfg: AppConfig = load_config(args.config)

    db_path = args.kdbx or (Path(cfg.keepassxc.database_path) if cfg.keepassxc.database_path else None)
    if not db_path:
        console.print("[bold red]Error: No KeePassXC database specified. Use --db or configure config.toml[/bold red]")
        return 1

    keyfile_path = args.keyfile or (Path(cfg.keepassxc.keyfile_path) if cfg.keepassxc.keyfile_path else None)
    yubikey_slot = args.yubikey or cfg.keepassxc.yubikey_slot or None

    # Prompt passwords securely in memory
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
        adapter = Token2CLIAdapter(cli_binary=cfg.token2.cli_binary, pin=pin_buf)
        try:
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
        display_diff_table(diff, total_current_slots=len(token_profiles))

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

        mode = args.mode or run_interactive_menu()
        confirm_delete = not args.yes

        try:
            apply_sync(
                adapter=adapter,
                diff=diff,
                existing_profiles=token_profiles,
                mode=mode,
                confirm_delete=confirm_delete,
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
