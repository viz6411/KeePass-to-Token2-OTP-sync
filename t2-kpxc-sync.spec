# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification for t2-kpxc-sync standalone executable."""

import os
from PyInstaller.utils.hooks import (
    collect_all,
    collect_data_files,
    collect_dynamic_libs,
    collect_submodules,
)

block_cipher = None

# Base hidden imports
hiddenimports = [
    # Core CLI & TUI
    "rich",
    "rich.table",
    "rich.panel",
    "rich.console",
    "rich.prompt",
    "tomli",
    "tomllib",
    # Hardware & Crypto
    "hid",
    "cryptography",
    "argon2",
    "argon2.low_level",
    "pykeepass",
    "construct",
    "lxml",
    "lxml.etree",
    "lxml._elementpath",
    # Internal project modules
    "t2_kpxc_sync",
    "t2_kpxc_sync.cli",
    "t2_kpxc_sync.config",
    "t2_kpxc_sync.diff",
    "t2_kpxc_sync.file_picker",
    "t2_kpxc_sync.kpxc",
    "t2_kpxc_sync.models",
    "t2_kpxc_sync.security",
    "t2_kpxc_sync.tui",
    "t2_kpxc_sync.token2",
    "t2_kpxc_sync.token2.adapter",
    "t2_kpxc_sync.token2.client",
    "t2_kpxc_sync.token2.crypto",
    "t2_kpxc_sync.token2.exceptions",
    "t2_kpxc_sync.token2.protocol",
    "t2_kpxc_sync.token2.transport",
]

datas = []
binaries = []

# Collect packages with standard hooks
standard_pkgs = [
    "cryptography",
    "lxml",
    "pykeepass",
    "construct",
    "argon2",
    "rich",
]

for pkg in standard_pkgs:
    try:
        p_datas, p_binaries, p_hidden = collect_all(pkg)
        datas += p_datas
        binaries += p_binaries
        hiddenimports += p_hidden
    except Exception:
        pass

# Cryptodome (used by pykeepass for AES/ChaCha20): collect without SelfTest bloat
datas += collect_data_files("Cryptodome", excludes=["**/SelfTest/**"])
hiddenimports += collect_submodules("Cryptodome", filter=lambda name: "SelfTest" not in name)
binaries += collect_dynamic_libs("Cryptodome", search_patterns=["*.dll", "*.dylib", "*.so", "*.pyd"])

# Optional hardware libraries if present in environment
for opt_pkg in ["smartcard", "fido2"]:
    try:
        p_datas, p_binaries, p_hidden = collect_all(opt_pkg)
        datas += p_datas
        binaries += p_binaries
        hiddenimports += p_hidden
    except Exception:
        pass

a = Analysis(
    ["src/t2_kpxc_sync/__main__.py"],
    pathex=["src"],
    binaries=binaries,
    datas=datas,
    hiddenimports=list(set(hiddenimports)),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "matplotlib",
        "numpy",
        "scipy",
        "IPython",
        "PIL",
        "test",
        "unittest",
        "tkinter",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher,
)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="t2-kpxc-sync",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
