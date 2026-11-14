#!/usr/bin/env python3
"""Deterministic distribution packager for t2-kpxc-sync.

Packages standalone PyInstaller binaries, smart launchers, configuration templates,
and documentation into portable archives (ZIP for Windows, tar.gz for Linux).
"""

from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import platform
import re
import sys
import tarfile
import time
from typing import List, Optional, Sequence
import zipfile


class PackagingError(Exception):
    """Raised when distribution packaging fails."""


class DistItem:
    """Represents a file to be included in the distribution archive."""

    def __init__(
        self,
        src_path: Path,
        rel_dest: str,
        is_executable: bool = False,
        line_ending: Optional[str] = None,
        required: bool = True,
    ):
        self.src_path = src_path
        self.rel_dest = rel_dest
        self.is_executable = is_executable
        self.line_ending = line_ending
        self.required = required


def get_version(root_dir: Path) -> str:
    """Extracts project version from __init__.py or pyproject.toml."""
    init_file = root_dir / "src" / "t2_kpxc_sync" / "__init__.py"
    if init_file.is_file():
        match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init_file.read_text(encoding="utf-8"))
        if match:
            return match.group(1).lstrip("v")

    pyproject = root_dir / "pyproject.toml"
    if pyproject.is_file():
        match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', pyproject.read_text(encoding="utf-8"))
        if match:
            return match.group(1).lstrip("v")

    return "0.2.0"


def normalize_line_endings(data: bytes, target_ending: str) -> bytes:
    """Normalizes text data line endings to either '\\n' or '\\r\\n'."""
    text = data.decode("utf-8")
    lines = text.splitlines()
    sep = "\r\n" if target_ending == "\r\n" else "\n"
    return (sep.join(lines) + sep).encode("utf-8")


def build_manifest(
    platform_name: str,
    root_dir: Path,
    dist_dir: Path,
    version: str,
) -> List[DistItem]:
    """Builds the file inclusion manifest based on target platform."""
    items: List[DistItem] = []

    if platform_name == "windows":
        exe_path = dist_dir / "t2-kpxc-sync.exe"
        items.append(DistItem(exe_path, "t2-kpxc-sync.exe", is_executable=True, required=True))
        items.append(DistItem(root_dir / "Sync-Token2.bat", "Sync-Token2.bat", is_executable=False, line_ending="\r\n", required=True))
        items.append(DistItem(root_dir / "config.example.toml", "config.example.toml", line_ending="\r\n", required=True))
        items.append(DistItem(root_dir / "README.md", "README.md", line_ending="\r\n", required=True))
    else:  # linux or darwin
        bin_path = dist_dir / "t2-kpxc-sync"
        items.append(DistItem(bin_path, "t2-kpxc-sync", is_executable=True, required=True))
        items.append(DistItem(root_dir / "Sync-Token2.sh", "Sync-Token2.sh", is_executable=True, line_ending="\n", required=True))
        if platform_name == "darwin":
            items.append(DistItem(root_dir / "Sync-Token2.command", "Sync-Token2.command", is_executable=True, line_ending="\n", required=False))
        items.append(DistItem(root_dir / "config.example.toml", "config.example.toml", line_ending="\n", required=True))
        items.append(DistItem(root_dir / "README.md", "README.md", line_ending="\n", required=True))

    # Optional release notes
    notes_files = [
        root_dir / f"RELEASE_NOTES_v{version}.md",
        root_dir / "RELEASE_NOTES_v0.2.0.md",
    ]
    for notes_file in notes_files:
        if notes_file.is_file():
            ending = "\r\n" if platform_name == "windows" else "\n"
            items.append(DistItem(notes_file, notes_file.name, line_ending=ending, required=False))
            break

    # Optional Archify architecture viewer
    arch_html = root_dir / "docs" / "architecture.html"
    if arch_html.is_file():
        items.append(DistItem(arch_html, "docs/architecture.html", required=False))

    return items


def create_zip_archive(
    items: List[DistItem],
    out_archive: Path,
    enclosing_folder: Optional[str] = None,
) -> None:
    """Creates a deterministic ZIP archive with explicit Unix permissions."""
    out_archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in items:
            arcname = f"{enclosing_folder}/{item.rel_dest}" if enclosing_folder else item.rel_dest
            arcname = arcname.replace("\\", "/")

            raw_bytes = item.src_path.read_bytes()
            if item.line_ending:
                raw_bytes = normalize_line_endings(raw_bytes, item.line_ending)

            zi = zipfile.ZipInfo(arcname)
            zi.date_time = time.localtime(item.src_path.stat().st_mtime)[:6]
            mode = 0o755 if item.is_executable else 0o644
            zi.external_attr = (mode << 16) | 0x20  # 0x20 = DOS archive attribute
            zf.writestr(zi, raw_bytes)

    # Self-verification
    with zipfile.ZipFile(out_archive, "r") as zf:
        bad_file = zf.testzip()
        if bad_file:
            raise PackagingError(f"Corrupt ZIP file detected: {bad_file}")


def create_tar_archive(
    items: List[DistItem],
    out_archive: Path,
    enclosing_folder: Optional[str] = None,
) -> None:
    """Creates a deterministic tar.gz archive with normalized ownership."""
    out_archive.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out_archive, "w:gz") as tf:
        for item in items:
            arcname = f"{enclosing_folder}/{item.rel_dest}" if enclosing_folder else item.rel_dest
            arcname = arcname.replace("\\", "/")

            raw_bytes = item.src_path.read_bytes()
            if item.line_ending:
                raw_bytes = normalize_line_endings(raw_bytes, item.line_ending)

            ti = tarfile.TarInfo(name=arcname)
            ti.size = len(raw_bytes)
            ti.mtime = int(item.src_path.stat().st_mtime)
            ti.mode = 0o755 if item.is_executable else 0o644
            ti.uid = 0
            ti.gid = 0
            ti.uname = "root"
            ti.gname = "root"
            tf.addfile(ti, io.BytesIO(raw_bytes))


def package_distribution(
    platform_name: str,
    root_dir: Path,
    dist_dir: Path,
    out_dir: Path,
    version: Optional[str] = None,
    arch: str = "x64",
    flat: bool = False,
) -> Path:
    """Coordinates distribution bundle generation."""
    if platform_name == "auto":
        system = platform.system().lower()
        if "windows" in system:
            platform_name = "windows"
        elif "darwin" in system:
            platform_name = "darwin"
        else:
            platform_name = "linux"

    ver = version.lstrip("v") if version else get_version(root_dir)
    manifest = build_manifest(platform_name, root_dir, dist_dir, ver)

    # Validate required source items
    for item in manifest:
        if not item.src_path.is_file():
            if item.required:
                raise FileNotFoundError(
                    f"Required file '{item.src_path}' not found for {platform_name} bundle. "
                    f"If this is the executable, ensure PyInstaller has built it first."
                )

    # Filter present items
    active_items = [i for i in manifest if i.src_path.is_file()]

    bundle_prefix = f"t2-kpxc-sync-v{ver}-{platform_name}-{arch}"
    enclosing_folder = None if flat else bundle_prefix

    if platform_name == "windows":
        archive_name = f"{bundle_prefix}.zip"
        archive_path = out_dir / archive_name
        create_zip_archive(active_items, archive_path, enclosing_folder)
    else:
        archive_name = f"{bundle_prefix}.tar.gz"
        archive_path = out_dir / archive_name
        create_tar_archive(active_items, archive_path, enclosing_folder)

    return archive_path


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point for package_dist.py."""
    parser = argparse.ArgumentParser(
        prog="package_dist.py",
        description="Deterministic distribution packager for t2-kpxc-sync",
    )
    parser.add_argument(
        "--platform",
        "-p",
        choices=["windows", "linux", "darwin", "auto"],
        default="auto",
        help="Target platform (default: auto)",
    )
    parser.add_argument("--version", "-v", help="Release version (e.g. 0.2.0)")
    parser.add_argument("--arch", default="x64", help="Architecture label (default: x64)")
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"), help="Input directory containing PyInstaller binary")
    parser.add_argument("--out-dir", type=Path, default=Path("dist"), help="Output directory for generated archive")
    parser.add_argument("--root-dir", type=Path, default=Path("."), help="Repository root directory")
    parser.add_argument("--flat", action="store_true", help="Do not nest contents inside an enclosing folder")

    args = parser.parse_args(argv)

    try:
        archive_path = package_distribution(
            platform_name=args.platform,
            root_dir=args.root_dir.resolve(),
            dist_dir=args.dist_dir.resolve(),
            out_dir=args.out_dir.resolve(),
            version=args.version,
            arch=args.arch,
            flat=args.flat,
        )
        size_kb = archive_path.stat().st_size / 1024
        print(f"[OK] Successfully packaged distribution archive: {archive_path} ({size_kb:.1f} KB)")
        return 0
    except Exception as exc:
        print(f"[ERROR] Packaging failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
