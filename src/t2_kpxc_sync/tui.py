"""Terminal User Interface (TUI) for KeePassXC to Token2 synchronization.

Provides interactive First-Run Onboarding Wizard, Main Menu, Settings Editor,
and Rich visual table presentations.
"""

from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .config import (
    AppConfig,
    KeePassXCConfig,
    Token2Config,
    get_default_config_path,
    save_config,
)
from .diff import TOKEN2_MAX_CAPACITY, DiffResult, compute_diff
from .file_picker import clean_path_input, pick_file
from .kpxc import KeePassCredentialsError, KeePassXCError, read_kpxc_entries
from .models import TOTPEntry, Token2Profile
from .security import scrub_bytes
from .token2 import Token2Adapter, Token2Error, Token2PINError

console = Console()


def display_diff_table(diff: DiffResult, total_current_slots: int, con: Optional[Console] = None) -> None:
    """Displays formatted Rich table of differences between KeePassXC and Token2."""
    c = con or console
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

    c.print(table)

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

    c.print(Panel(summary_text, title="Summary", border_style="cyan"))


def find_free_slots(occupied_slots: Sequence[int], max_capacity: int = TOKEN2_MAX_CAPACITY) -> list[int]:
    """Returns sorted list of available slots in range 1..max_capacity."""
    occupied = set(occupied_slots)
    return [s for s in range(1, max_capacity + 1) if s not in occupied]


def apply_sync(
    adapter: Any,
    diff: DiffResult,
    existing_profiles: list[Token2Profile],
    mode: str,
    confirm_delete: bool = True,
    con: Optional[Console] = None,
    btn_flag: int = 0,
) -> int:
    """Applies sync operations to the Token2 hardware token based on selected mode.

    Modes:
      - 'add_only' / '1': Only adds new entries
      - 'add_update' / '2': Adds new entries and updates modified ones
      - 'full_sync' / '3': Adds new, updates modified, and deletes obsolete entries
      - 'cancel' / '4': Aborts without changes

    Args:
      btn_flag: 0 for Standard format (no touch), 1 for Touch / Button Press Required.

    Returns number of executed operations.
    """
    c = con or console
    normalized_mode = mode.strip().lower()
    if normalized_mode in ("cancel", "4"):
        c.print("[yellow]Sync cancelled by user.[/yellow]")
        return 0

    if normalized_mode not in ("add_only", "1", "add_update", "2", "full_sync", "3"):
        c.print(f"[bold red]Unknown sync mode: '{mode}'. No operations performed.[/bold red]")
        return 0

    if diff.is_capacity_exceeded:
        raise Token2Error(
            f"Cannot proceed: final slot count {diff.final_slot_count} exceeds hardware limit {TOKEN2_MAX_CAPACITY}"
        )

    ops_count = 0
    occupied = {p.slot for p in existing_profiles}

    # 1. Full Sync Deletions
    if normalized_mode in ("full_sync", "3") and diff.to_delete:
        if confirm_delete:
            ans = c.input(
                f"[bold red]Confirm deleting {len(diff.to_delete)} profiles from Token2? [y/N]: [/bold red]"
            )
            if ans.strip().lower() not in ("y", "yes", "д", "да"):
                c.print("[yellow]Aborted deletion on user request.[/yellow]")
                return ops_count

        for profile in diff.to_delete:
            c.print(f"[red]Deleting slot {profile.slot}: {profile.issuer} ({profile.account})...[/red]")
            adapter.delete_entry(profile.slot)
            occupied.discard(profile.slot)
            ops_count += 1

    # 2. Updates (delete old slot, then write updated entry)
    if normalized_mode in ("add_update", "2", "full_sync", "3") and diff.to_update:
        for entry, profile in diff.to_update:
            format_tag = " [touch required]" if btn_flag == 1 else ""
            c.print(f"[yellow]Updating slot {profile.slot}: {entry.issuer} ({entry.account}){format_tag}...[/yellow]")
            adapter.delete_entry(profile.slot)
            if btn_flag:
                adapter.write_entry(profile.slot, entry, btn_flag=btn_flag)
            else:
                adapter.write_entry(profile.slot, entry)
            ops_count += 1

    # 3. Additions
    if normalized_mode in ("add_only", "1", "add_update", "2", "full_sync", "3") and diff.to_add:
        free_slots = find_free_slots(list(occupied))
        if len(free_slots) < len(diff.to_add):
            raise Token2Error(f"Not enough free slots: {len(free_slots)} available, {len(diff.to_add)} needed")

        for entry in diff.to_add:
            slot = free_slots.pop(0)
            format_tag = " [touch required]" if btn_flag == 1 else ""
            c.print(f"[green]Adding to slot {slot}: {entry.issuer} ({entry.account}){format_tag}...[/green]")
            if btn_flag:
                adapter.write_entry(slot, entry, btn_flag=btn_flag)
            else:
                adapter.write_entry(slot, entry)
            occupied.add(slot)
            ops_count += 1

    c.print(f"[bold green]Successfully performed {ops_count} operations.[/bold green]")
    return ops_count


def prompt_entry_format(
    default_button_required: bool = False,
    con: Optional[Console] = None,
) -> int:
    """Prompts user to select TOTP entry format on the final step before writing.

    Options:
      [1] Standard format (no touch required)
      [2] Require a button press to show the code (touch token)

    Returns:
      0 for standard format, 1 for touch/button-required.
    """
    c = con or console
    default_choice = "2" if default_button_required else "1"

    c.print("\n[bold]Select TOTP entry format:[/bold]")
    c.print(f"  [1] Обычный формат (Standard — no touch required){' (default)' if default_choice == '1' else ''}")
    c.print(f"  [2] Требовать касания (Require button press to show code){' (default)' if default_choice == '2' else ''}")

    try:
        choice = c.input(f"Enter choice [1-2] (default: {default_choice}): ").strip()
    except (EOFError, KeyboardInterrupt):
        return 1 if default_button_required else 0

    if not choice:
        return 1 if default_button_required else 0

    if choice in ("2", "touch", "button", "касание"):
        return 1
    return 0


def run_interactive_menu(con: Optional[Console] = None) -> str:
    """Prompts user to select synchronization mode."""
    c = con or console
    c.print("\n[bold]Select action:[/bold]")
    c.print("  [1] Add Only (write missing entries)")
    c.print("  [2] Add & Update (write missing and overwrite changed entries)")
    c.print("  [3] Full Sync (Add, Update, and delete obsolete entries)")
    c.print("  [4] Cancel (exit without changes)")

    while True:
        try:
            choice = c.input("[bold cyan]Enter choice [1-4] (default: 4): [/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt, StopIteration):
            return "4"

        if not choice:
            return "4"

        if choice in ("1", "2", "3", "4"):
            return choice

        c.print(f"[bold red]Invalid choice: '{choice}'. Please select 1, 2, 3, or 4.[/bold red]")


def run_onboarding_wizard(
    config_path: Optional[Path] = None,
    con: Optional[Console] = None,
) -> AppConfig:
    """Runs interactive 4-step wizard to configure KeePassXC database, keyfile,
    YubiKey slot, and excluded groups. Saves to config.toml and returns AppConfig.
    """
    c = con or console
    target_config_path = config_path or get_default_config_path()

    c.print(
        Panel(
            "[bold cyan]Welcome to KeePassXC to Token2 TOTP Sync![/bold cyan]\n\n"
            "This wizard will guide you through the initial configuration in 4 simple steps.",
            title="First-Run Setup Wizard",
            border_style="cyan",
        )
    )

    # Step 1: Database path
    db_path = ""
    while True:
        c.print("\n[bold]Step 1/4: KeePassXC Database (.kdbx)[/bold]")
        c.print("  [O] Browse via system file dialog")
        c.print("  [M] Manual input / direct paste")
        choice = c.input("[bold cyan]Enter path or option [O/M]: [/bold cyan]").strip()

        if choice.lower() in ("o", "о", "обзор", "browse"):
            picked = pick_file(
                title="Select KeePassXC Database (.kdbx)",
                file_types=[("KeePass Database", "*.kdbx"), ("All files", "*.*")],
                allow_console_fallback=False,
            )
            if not picked:
                c.print("[yellow]Browse cancelled or unavailable. Please enter path manually.[/yellow]")
                continue
            raw_path = picked
        elif choice.lower() in ("m", "м", "manual"):
            raw_path = c.input("[cyan]Enter full path to .kdbx file: [/cyan]").strip()
        else:
            raw_path = choice

        if not raw_path:
            c.print("[bold red]Database path is required. Please provide a path.[/bold red]")
            continue

        cleaned = clean_path_input(raw_path)
        path_obj = Path(cleaned)

        if not path_obj.is_file():
            c.print(f"[bold red]File not found: '{cleaned}'. Please check the path and try again.[/bold red]")
            continue

        if path_obj.suffix.lower() != ".kdbx":
            confirm = (
                c.input("[bold yellow]Warning: File does not have .kdbx extension. Continue anyway? [y/N]: [/bold yellow]")
                .strip()
                .lower()
            )
            if confirm not in ("y", "yes", "д", "да"):
                continue

        db_path = str(path_obj.resolve())
        c.print(f"[green]✓ Database set: {db_path}[/green]")
        break

    # Step 2: Keyfile path
    keyfile_path = ""
    while True:
        c.print("\n[bold]Step 2/4: KeePassXC Keyfile (Optional)[/bold]")
        c.print("  [O] Browse via system file dialog")
        c.print("  [M] Manual input / direct paste")
        c.print("  [Enter] Skip (no keyfile)")
        choice = c.input("[bold cyan]Enter path, option [O/M], or press Enter to skip: [/bold cyan]").strip()

        if not choice:
            c.print("[dim]✓ Keyfile skipped (none)[/dim]")
            break

        if choice.lower() in ("o", "о", "обзор", "browse"):
            picked = pick_file(
                title="Select KeePass Keyfile",
                file_types=[("All files", "*.*")],
                allow_console_fallback=False,
            )
            if not picked:
                c.print("[yellow]Browse cancelled or unavailable.[/yellow]")
                continue
            raw_path = picked
        elif choice.lower() in ("m", "м", "manual"):
            raw_path = c.input("[cyan]Enter full path to keyfile: [/cyan]").strip()
        else:
            raw_path = choice

        if not raw_path:
            c.print("[dim]✓ Keyfile skipped (none)[/dim]")
            break

        cleaned = clean_path_input(raw_path)
        path_obj = Path(cleaned)

        if not path_obj.is_file():
            c.print(f"[bold red]Keyfile not found: '{cleaned}'. Please check the path and try again.[/bold red]")
            continue

        keyfile_path = str(path_obj.resolve())
        c.print(f"[green]✓ Keyfile set: {keyfile_path}[/green]")
        break

    # Step 3: YubiKey slot
    yubikey_slot = ""
    while True:
        c.print("\n[bold]Step 3/4: YubiKey Challenge-Response Slot (Optional)[/bold]")
        c.print("  1 - Slot 1")
        c.print("  2 - Slot 2")
        c.print("  [Enter] Skip (no YubiKey)")
        choice = c.input("[bold cyan]Enter slot [1/2] or press Enter to skip: [/bold cyan]").strip()

        if not choice:
            c.print("[dim]✓ YubiKey skipped (none)[/dim]")
            break
        if choice in ("1", "2"):
            yubikey_slot = choice
            c.print(f"[green]✓ YubiKey slot set: {yubikey_slot}[/green]")
            break
        c.print("[bold red]Invalid choice. Enter '1', '2', or press Enter to skip.[/bold red]")

    # Step 4: Excluded groups
    excluded_groups = ["Recycle Bin", "Archive"]
    c.print("\n[bold]Step 4/4: Excluded KeePassXC Groups[/bold]")
    c.print("  Default: Recycle Bin, Archive")
    raw_groups = c.input("[bold cyan]Enter comma-separated groups [Enter for default]: [/bold cyan]").strip()
    if raw_groups:
        parsed = [g.strip() for g in raw_groups.split(",") if g.strip()]
        if parsed:
            excluded_groups = parsed
    c.print(f"[green]✓ Excluded groups: {', '.join(excluded_groups)}[/green]")

    # Confirmation and Persistence
    summary = (
        f"[bold]Database Path:[/bold] {db_path}\n"
        f"[bold]Keyfile Path:[/bold]  {keyfile_path or '(none)'}\n"
        f"[bold]YubiKey Slot:[/bold]  {yubikey_slot or '(none)'}\n"
        f"[bold]Excluded Groups:[/bold] {', '.join(excluded_groups)}\n"
        f"[bold]Config File:[/bold]    {target_config_path}"
    )
    c.print()
    c.print(Panel(summary, title="Configuration Summary", border_style="cyan"))

    save_choice = c.input("\n[bold cyan]Save configuration? [Y/n]: [/bold cyan]").strip().lower()
    new_config = AppConfig(
        keepassxc=KeePassXCConfig(
            database_path=db_path,
            keyfile_path=keyfile_path,
            yubikey_slot=yubikey_slot,
            excluded_groups=excluded_groups,
        ),
        token2=Token2Config(),
    )

    if save_choice in ("", "y", "yes", "д", "да"):
        save_config(new_config, target_config_path)
        c.print(f"[bold green]Configuration successfully saved to {target_config_path}![/bold green]\n")
    else:
        c.print("[yellow]Configuration not saved. Using in-memory configuration for this session.[/yellow]\n")

    return new_config


def check_token_presence() -> str:
    """Checks whether a Token2 USB-HID device is currently detected."""
    try:
        import hid
        devices = hid.enumerate()
        for info in devices:
            vid = info.get("vendor_id", 0)
            mfr = (info.get("manufacturer_string") or "").upper()
            prod = (info.get("product_string") or "").upper()
            if vid == 0x349E or "TOKEN2" in mfr or "TOKEN2" in prod:
                return "[bold green]Connected[/bold green]"
        return "[bold red]Not detected[/bold red]"
    except Exception:
        return "[yellow]Unknown[/yellow]"


def render_header_panel(config: AppConfig, token_status: Optional[str] = None) -> Panel:
    """Renders the top branding panel for the main menu."""
    db_path = config.keepassxc.database_path
    if not db_path:
        db_status = "[bold red]Not configured[/bold red]"
    elif Path(db_path).is_file():
        db_status = f"[green]{db_path}[/green]"
    else:
        db_status = f"[bold yellow]{db_path} (file not found!)[/bold yellow]"

    status = token_status if token_status is not None else check_token_presence()
    content = f"Database: {db_status} | Hardware: Token2 PIN+ ({status})"
    return Panel(
        content,
        title=f"[bold cyan]KeePassXC to Token2 PIN+ R3.3 Synchronization[/bold cyan]\n[dim]v{__version__} • Standalone[/dim]",
        border_style="cyan",
    )


def handle_sync_action(
    config: AppConfig,
    dry_run: bool = False,
    con: Optional[Console] = None,
) -> None:
    """Handles Option [1] (Sync) and Option [2] (Dry Run)."""
    c = con or console
    db_path_str = config.keepassxc.database_path
    if not db_path_str:
        c.print("[bold red]Database path is not configured. Please use Settings [3] to set it.[/bold red]")
        try:
            c.input("\nPress Enter to return to main menu...")
        except (EOFError, KeyboardInterrupt):
            pass
        return

    db_path = Path(db_path_str)
    if not db_path.is_file():
        c.print(f"[bold red]KeePassXC database file not found: '{db_path_str}'[/bold red]")
        try:
            c.input("\nPress Enter to return to main menu...")
        except (EOFError, KeyboardInterrupt):
            pass
        return

    password_buf: bytearray | None = None
    pin_buf: bytearray | None = None
    adapter: Token2Adapter | None = None

    try:
        try:
            raw_pwd = getpass.getpass("Enter KeePassXC Master Password (or Enter if none): ")
        except (EOFError, KeyboardInterrupt):
            return
        if raw_pwd:
            password_buf = bytearray(raw_pwd.encode("utf-8"))
            del raw_pwd

        try:
            raw_pin = getpass.getpass("Enter Token2 PIN (or Enter if none): ")
        except (EOFError, KeyboardInterrupt):
            return
        if raw_pin:
            pin_buf = bytearray(raw_pin.encode("utf-8"))
            del raw_pin

        # 1. Read KeePassXC in RAM
        c.print("[cyan]Reading KeePassXC database in RAM...[/cyan]")
        keyfile = Path(config.keepassxc.keyfile_path) if config.keepassxc.keyfile_path else None
        yubikey = int(config.keepassxc.yubikey_slot) if config.keepassxc.yubikey_slot.isdigit() else None
        try:
            kpxc_entries = read_kpxc_entries(
                db_path=db_path,
                password=password_buf,
                keyfile_path=keyfile,
                yubikey_slot=yubikey,
                cli_binary=config.keepassxc.cli_binary,
                excluded_groups=config.keepassxc.excluded_groups,
                backend=config.keepassxc.backend,
            )
        except KeePassCredentialsError as err:
            c.print(f"[bold red]KeePassXC Authentication Failed: {err}[/bold red]")
            try:
                c.input("\nPress Enter to return to main menu...")
            except (EOFError, KeyboardInterrupt):
                pass
            return
        except KeePassXCError as err:
            c.print(f"[bold red]KeePassXC Error: {err}[/bold red]")
            try:
                c.input("\nPress Enter to return to main menu...")
            except (EOFError, KeyboardInterrupt):
                pass
            return

        # 2. Query Token2 hardware token
        c.print("[cyan]Connecting to Token2 hardware token...[/cyan]")
        adapter = Token2Adapter(
            backend=getattr(config.token2, "backend", "auto"),
            cli_binary=config.token2.cli_binary,
            pin=pin_buf,
        )
        try:
            adapter.open()
            token_profiles = adapter.get_all()
        except Token2PINError as err:
            c.print(f"[bold red]Token2 Security Error: {err}[/bold red]")
            c.print("[bold red]Aborting immediately to protect token from lockout.[/bold red]")
            try:
                c.input("\nPress Enter to return to main menu...")
            except (EOFError, KeyboardInterrupt):
                pass
            return
        except Token2Error as err:
            c.print(f"[bold red]Token2 Error: {err}[/bold red]")
            try:
                c.input("\nPress Enter to return to main menu...")
            except (EOFError, KeyboardInterrupt):
                pass
            return

        # 3. Compute Diff
        diff = compute_diff(kpxc_entries, token_profiles)
        display_diff_table(diff, total_current_slots=len(token_profiles), con=c)

        if diff.duplicates:
            c.print(f"[bold yellow]Warning: {len(diff.duplicates)} duplicate entries detected in KeePassXC![/bold yellow]")

        # 4. Dry Run check
        if dry_run:
            c.print("\n[bold yellow]Dry-run complete: no changes were written to Token2 hardware token.[/bold yellow]")
            try:
                c.input("\nPress Enter to return to main menu...")
            except (EOFError, KeyboardInterrupt):
                pass
            return

        # 5. Up to date check
        if not diff.to_add and not diff.to_update and not diff.to_delete:
            c.print("[bold green]Token2 is already up to date with KeePassXC. Nothing to do.[/bold green]")
            try:
                c.input("\nPress Enter to return to main menu...")
            except (EOFError, KeyboardInterrupt):
                pass
            return

        # 6. Capacity check
        if diff.is_capacity_exceeded:
            c.print("[bold red]Error: Token capacity (300 slots) exceeded. Synchronization cannot continue.[/bold red]")
            try:
                c.input("\nPress Enter to return to main menu...")
            except (EOFError, KeyboardInterrupt):
                pass
            return

        # 7. Select sync mode
        mode = run_interactive_menu(con=c)
        if mode in ("4", "cancel"):
            c.print("[yellow]Sync cancelled by user.[/yellow]")
            try:
                c.input("\nPress Enter to return to main menu...")
            except (EOFError, KeyboardInterrupt):
                pass
            return

        # 8. Select TOTP entry format (final step before write)
        btn_flag = prompt_entry_format(
            default_button_required=config.token2.button_required,
            con=c,
        )

        # 9. Apply Sync
        try:
            apply_sync(
                adapter=adapter,
                diff=diff,
                existing_profiles=token_profiles,
                mode=mode,
                confirm_delete=True,
                con=c,
                btn_flag=btn_flag,
            )
        except Token2Error as err:
            c.print(f"[bold red]Sync Error: {err}[/bold red]")

        try:
            c.input("\nPress Enter to return to main menu...")
        except (EOFError, KeyboardInterrupt):
            pass
    finally:
        if password_buf is not None:
            scrub_bytes(password_buf)
        if pin_buf is not None:
            scrub_bytes(pin_buf)
        if adapter is not None:
            try:
                adapter.close()
            except Exception:
                pass


def handle_settings_menu(
    config: AppConfig,
    config_path: Path,
    con: Optional[Console] = None,
) -> AppConfig:
    """Handles Option [3] (Settings Editor) and persists changes immediately."""
    c = con or console
    current_config = config

    while True:
        kpxc = current_config.keepassxc
        t2 = current_config.token2
        fmt_label = "Require touch (Button press)" if t2.button_required else "Standard (No touch)"
        settings_text = (
            f"[bold]Database path:[/bold]   {kpxc.database_path or '(not configured)'}\n"
            f"[bold]Keyfile path:[/bold]    {kpxc.keyfile_path or '(none)'}\n"
            f"[bold]YubiKey slot:[/bold]    {kpxc.yubikey_slot or '(disabled)'}\n"
            f"[bold]Excluded groups:[/bold] {', '.join(kpxc.excluded_groups)}\n"
            f"[bold]KDBX backend:[/bold]    {kpxc.backend}\n"
            f"[bold]TOTP format:[/bold]     {fmt_label}\n"
            f"[bold]Config file:[/bold]     {config_path}"
        )
        c.print()
        c.print(Panel(settings_text, title="Settings", border_style="cyan"))
        c.print("  [bold cyan][1][/bold cyan] Изменить путь к базе KeePassXC (.kdbx) [с кнопкой «Обзор»]")
        c.print("  [bold cyan][2][/bold cyan] Изменить ключевой файл [с кнопкой «Обзор»]")
        c.print("  [bold cyan][3][/bold cyan] Изменить слот YubiKey (1, 2 или отключить)")
        c.print("  [bold cyan][4][/bold cyan] Настроить исключаемые группы")
        c.print("  [bold cyan][5][/bold cyan] Изменить режим чтения KDBX (auto / direct / cli)")
        c.print("  [bold cyan][6][/bold cyan] Изменить формат TOTP по умолчанию (обычный / по касанию)")
        c.print("  [bold cyan][7][/bold cyan] Сбросить настройки на значения по умолчанию")
        c.print("  [bold cyan][8][/bold cyan] Назад в главное меню")
        c.print()

        try:
            choice = c.input("[bold cyan]Enter choice [1-8] (default: 8): [/bold cyan]").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not choice or choice in ("8", "q", "exit", "back"):
            break

        if choice == "1":
            c.print("\n[bold]Edit KeePassXC Database Path[/bold]")
            c.print("  [O] Browse via system file dialog")
            c.print("  [M] Manual input / direct paste")
            c.print("  [Enter] Cancel")
            try:
                sub = c.input("[bold cyan]Choice or path: [/bold cyan]").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not sub:
                continue
            if sub.lower() in ("o", "о", "browse", "обзор"):
                picked = pick_file(
                    title="Select KeePassXC Database",
                    file_types=[("KeePass Database", "*.kdbx"), ("All files", "*.*")],
                    allow_console_fallback=False,
                )
                if not picked:
                    c.print("[yellow]Browse cancelled.[/yellow]")
                    continue
                raw_path = picked
            elif sub.lower() in ("m", "м", "manual"):
                try:
                    raw_path = c.input("[cyan]Enter path: [/cyan]").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
            else:
                raw_path = sub

            cleaned = clean_path_input(raw_path)
            p = Path(cleaned)
            if not p.is_file():
                c.print(f"[bold red]File not found: '{cleaned}'[/bold red]")
                continue
            if p.suffix.lower() != ".kdbx":
                try:
                    conf = (
                        c.input("[bold yellow]File does not have .kdbx extension. Continue? [y/N]: [/bold yellow]")
                        .strip()
                        .lower()
                    )
                except (EOFError, KeyboardInterrupt):
                    continue
                if conf not in ("y", "yes", "д", "да"):
                    continue

            current_config.keepassxc.database_path = str(p.resolve())
            save_config(current_config, config_path)
            c.print(f"[bold green]Database path updated and saved to {config_path}[/bold green]")

        elif choice == "2":
            c.print("\n[bold]Edit Keyfile Path[/bold]")
            c.print("  [O] Browse via system file dialog")
            c.print("  [M] Manual input / direct paste")
            c.print("  [C] Clear (disable keyfile)")
            c.print("  [Enter] Cancel")
            try:
                sub = c.input("[bold cyan]Choice, path, or [C] Clear: [/bold cyan]").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not sub:
                continue
            if sub.lower() in ("c", "с", "clear"):
                current_config.keepassxc.keyfile_path = ""
                save_config(current_config, config_path)
                c.print("[bold green]Keyfile path cleared and saved.[/bold green]")
                continue
            if sub.lower() in ("o", "о", "browse", "обзор"):
                picked = pick_file(
                    title="Select Keyfile",
                    file_types=[("All files", "*.*")],
                    allow_console_fallback=False,
                )
                if not picked:
                    c.print("[yellow]Browse cancelled.[/yellow]")
                    continue
                raw_path = picked
            elif sub.lower() in ("m", "м", "manual"):
                try:
                    raw_path = c.input("[cyan]Enter path: [/cyan]").strip()
                except (EOFError, KeyboardInterrupt):
                    continue
            else:
                raw_path = sub

            cleaned = clean_path_input(raw_path)
            p = Path(cleaned)
            if not p.is_file():
                c.print(f"[bold red]Keyfile not found: '{cleaned}'[/bold red]")
                continue

            current_config.keepassxc.keyfile_path = str(p.resolve())
            save_config(current_config, config_path)
            c.print("[bold green]Keyfile path updated and saved.[/bold green]")

        elif choice == "3":
            c.print("\n[bold]Edit YubiKey Slot[/bold]")
            c.print("  1 - Slot 1")
            c.print("  2 - Slot 2")
            c.print("  [C] Clear (disable YubiKey)")
            c.print("  [Enter] Cancel")
            try:
                sub = c.input("[bold cyan]Choice [1/2/C]: [/bold cyan]").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if not sub:
                continue
            if sub.lower() in ("c", "с", "clear"):
                current_config.keepassxc.yubikey_slot = ""
                save_config(current_config, config_path)
                c.print("[bold green]YubiKey slot cleared and saved.[/bold green]")
            elif sub in ("1", "2"):
                current_config.keepassxc.yubikey_slot = sub
                save_config(current_config, config_path)
                c.print(f"[bold green]YubiKey slot set to {sub} and saved.[/bold green]")
            else:
                c.print("[bold red]Invalid option. Enter 1, 2, or C.[/bold red]")

        elif choice == "4":
            current_str = ", ".join(current_config.keepassxc.excluded_groups)
            c.print(f"\n[bold]Edit Excluded Groups[/bold] (current: {current_str})")
            try:
                raw_groups = c.input("[bold cyan]Enter comma-separated groups [Enter to cancel]: [/bold cyan]").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if raw_groups:
                parsed = [g.strip() for g in raw_groups.split(",") if g.strip()]
                current_config.keepassxc.excluded_groups = parsed
                save_config(current_config, config_path)
                c.print(f"[bold green]Excluded groups updated and saved: {', '.join(parsed)}[/bold green]")

        elif choice == "5":
            c.print(f"\n[bold]Edit KDBX Backend[/bold] (current: {current_config.keepassxc.backend})")
            c.print("  [1] auto (direct pykeepass with CLI fallback for YubiKey)")
            c.print("  [2] direct (pykeepass pure RAM)")
            c.print("  [3] cli (keepassxc-cli)")
            c.print("  [Enter] Cancel")
            try:
                sub = c.input("[bold cyan]Choice [1-3]: [/bold cyan]").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            backend_map = {"1": "auto", "2": "direct", "3": "cli"}
            if sub in backend_map:
                current_config.keepassxc.backend = backend_map[sub]
                save_config(current_config, config_path)
                c.print(f"[bold green]KDBX backend set to '{backend_map[sub]}' and saved.[/bold green]")

        elif choice == "6":
            curr_fmt = "Require touch (Button press)" if current_config.token2.button_required else "Standard (No touch)"
            c.print(f"\n[bold]Edit Default TOTP Entry Format[/bold] (current: {curr_fmt})")
            c.print("  [1] Обычный формат (Standard — no touch required)")
            c.print("  [2] Требовать касания (Require button press to show code)")
            c.print("  [Enter] Cancel")
            try:
                sub = c.input("[bold cyan]Choice [1-2]: [/bold cyan]").strip()
            except (EOFError, KeyboardInterrupt):
                continue
            if sub in ("1", "standard", "обычный"):
                current_config.token2.button_required = False
                save_config(current_config, config_path)
                c.print("[bold green]Default format set to Standard (no touch required) and saved.[/bold green]")
            elif sub in ("2", "touch", "button", "касание"):
                current_config.token2.button_required = True
                save_config(current_config, config_path)
                c.print("[bold green]Default format set to Require button press (touch) and saved.[/bold green]")

        elif choice == "7":
            try:
                conf = c.input("\n[bold red]Reset all configuration to defaults? [y/N]: [/bold red]").strip().lower()
            except (EOFError, KeyboardInterrupt):
                continue
            if conf in ("y", "yes", "д", "да"):
                current_config = AppConfig()
                save_config(current_config, config_path)
                c.print("[bold green]All configuration reset to defaults and saved.[/bold green]")

    return current_config


def run_main_menu(
    config: AppConfig,
    config_path: Optional[Path] = None,
    con: Optional[Console] = None,
) -> None:
    """Runs interactive main loop with 4 options:
    [1] Sync TOTP to Token2
    [2] Dry Run (preview diff without writing)
    [3] Settings in TUI (in-place editor persisting to config.toml)
    [4] Exit
    """
    c = con or console
    current_config = config
    target_config_path = config_path or get_default_config_path()

    while True:
        try:
            c.print()
            c.print(render_header_panel(current_config))
            c.print("  [bold cyan][1][/bold cyan] Запуск синхронизации (Sync TOTP to Token2)")
            c.print("  [bold cyan][2][/bold cyan] Тестовый прогон (Dry Run — preview diff without writing)")
            c.print("  [bold cyan][3][/bold cyan] Настройки в TUI (Settings — paths, keyfiles, groups)")
            c.print("  [bold cyan][4][/bold cyan] Выход (Exit)")
            c.print()

            choice = c.input("[bold cyan]Enter choice [1-4] (default: 1): [/bold cyan]").strip()
            if not choice:
                choice = "1"

            if choice == "1":
                handle_sync_action(current_config, dry_run=False, con=c)
            elif choice == "2":
                handle_sync_action(current_config, dry_run=True, con=c)
            elif choice == "3":
                current_config = handle_settings_menu(current_config, target_config_path, con=c)
            elif choice in ("4", "q", "exit", "quit"):
                c.print("\n[cyan]Exiting t2-kpxc-sync. Goodbye![/cyan]")
                break
            else:
                c.print(f"[bold red]Invalid choice: '{choice}'. Please select 1, 2, 3, or 4.[/bold red]")
        except KeyboardInterrupt:
            c.print("\n\n[cyan]Session interrupted by user. Exiting t2-kpxc-sync. Goodbye![/cyan]")
            break
        except EOFError:
            break
