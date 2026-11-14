"""Configuration management for KeePassXC to Token2 synchronization."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore


@dataclass
class KeePassXCConfig:
    database_path: str = ""
    keyfile_path: str = ""
    yubikey_slot: str = ""
    cli_binary: str = "keepassxc-cli"
    excluded_groups: list[str] = field(default_factory=lambda: ["Recycle Bin", "Archive"])
    backend: str = "auto"


@dataclass
class Token2Config:
    cli_binary: str = "token2-otp-cli"
    button_required: bool = False


@dataclass
class AppConfig:
    keepassxc: KeePassXCConfig = field(default_factory=KeePassXCConfig)
    token2: Token2Config = field(default_factory=Token2Config)


def get_default_config_path() -> Path:
    """Returns platform-specific default path to config.toml."""
    if sys.platform == "win32":
        app_data = os.environ.get("APPDATA")
        base = Path(app_data) if app_data else Path.home() / "AppData" / "Roaming"
        return base / "t2-kpxc-sync" / "config.toml"
    else:
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg_config) if xdg_config else Path.home() / ".config"
        return base / "t2-kpxc-sync" / "config.toml"


def load_config(path: Optional[str | Path] = None) -> AppConfig:
    """Loads AppConfig from TOML file, returning defaults if not found."""
    target_path = Path(path) if path else get_default_config_path()
    if not target_path.exists():
        return AppConfig()

    try:
        content = target_path.read_text(encoding="utf-8")
        data = tomllib.loads(content)
    except Exception:
        return AppConfig()

    kpxc_data = data.get("keepassxc", {})
    t2_data = data.get("token2", {})

    kpxc_cfg = KeePassXCConfig(
        database_path=str(kpxc_data.get("database_path", "")),
        keyfile_path=str(kpxc_data.get("keyfile_path", "")),
        yubikey_slot=str(kpxc_data.get("yubikey_slot", "")),
        cli_binary=str(kpxc_data.get("cli_binary", "keepassxc-cli")),
        excluded_groups=list(kpxc_data.get("excluded_groups", ["Recycle Bin", "Archive"])),
        backend=str(kpxc_data.get("backend", "auto")),
    )

    t2_cfg = Token2Config(
        cli_binary=str(t2_data.get("cli_binary", "token2-otp-cli")),
        button_required=bool(t2_data.get("button_required", False)),
    )

    return AppConfig(keepassxc=kpxc_cfg, token2=t2_cfg)


def _toml_str(val: str) -> str:
    """Escapes string as a valid TOML basic string literal using JSON escaping rules."""
    return json.dumps(str(val), ensure_ascii=False).replace("\x7f", r"\u007f")


def save_config(config: AppConfig, path: Optional[str | Path] = None) -> None:
    """Saves AppConfig to TOML file atomically with proper TOML string escaping."""
    target_path = Path(path) if path else get_default_config_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    excluded_formatted = ", ".join(_toml_str(g) for g in config.keepassxc.excluded_groups)

    lines = [
        "# KeePassXC to Token2 PIN+ R3.3 TOTP Synchronization Configuration",
        "",
        "[keepassxc]",
        f"database_path = {_toml_str(config.keepassxc.database_path)}",
        f"keyfile_path = {_toml_str(config.keepassxc.keyfile_path)}",
        f"yubikey_slot = {_toml_str(config.keepassxc.yubikey_slot)}",
        f"cli_binary = {_toml_str(config.keepassxc.cli_binary)}",
        f"backend = {_toml_str(config.keepassxc.backend)}",
        f"excluded_groups = [{excluded_formatted}]",
        "",
        "[token2]",
        f"cli_binary = {_toml_str(config.token2.cli_binary)}",
        f"button_required = {'true' if config.token2.button_required else 'false'}",
        "",
    ]
    content = "\n".join(lines)

    temp_path = target_path.with_suffix(".tmp")
    try:
        temp_path.write_text(content, encoding="utf-8")
        os.replace(temp_path, target_path)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
