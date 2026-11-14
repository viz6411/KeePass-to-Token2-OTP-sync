"""Tests for distribution packager scripts/package_dist.py."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import zipfile
import pytest

# Ensure repo root is in sys.path
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from scripts.package_dist import get_version, normalize_line_endings, package_distribution


@pytest.fixture
def mock_repo(tmp_path: Path) -> Path:
    """Sets up a minimal mock repository structure for packaging tests."""
    repo = tmp_path / "repo"
    repo.mkdir()

    # Create src with __init__.py
    pkg = repo / "src" / "t2_kpxc_sync"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text('__version__ = "0.2.0"\n', encoding="utf-8")

    # Create dummy launchers and config
    (repo / "Sync-Token2.bat").write_text("@echo off\r\nREM test bat\r\n", encoding="utf-8")
    (repo / "Sync-Token2.sh").write_text("#!/usr/bin/env bash\necho test\n", encoding="utf-8")
    (repo / "config.example.toml").write_text("[keepassxc]\ncli_binary='test'\n", encoding="utf-8")
    (repo / "README.md").write_text("# Test Readme\n", encoding="utf-8")

    # Create docs/architecture.html
    docs = repo / "docs"
    docs.mkdir()
    (docs / "architecture.html").write_text("<html>Architecture</html>", encoding="utf-8")

    # Create dist with dummy executables
    dist = repo / "dist"
    dist.mkdir()
    (dist / "t2-kpxc-sync.exe").write_bytes(b"MZ_DUMMY_EXE")
    (dist / "t2-kpxc-sync").write_bytes(b"\x7fELF_DUMMY_BIN")

    return repo


def test_get_version(mock_repo: Path):
    assert get_version(mock_repo) == "0.2.0"


def test_normalize_line_endings():
    raw = b"line1\r\nline2\nline3\r\n"
    crlf = normalize_line_endings(raw, "\r\n")
    assert crlf == b"line1\r\nline2\r\nline3\r\n"

    lf = normalize_line_endings(raw, "\n")
    assert lf == b"line1\nline2\nline3\n"


def test_package_distribution_windows_zip(mock_repo: Path):
    out_dir = mock_repo / "out"
    archive = package_distribution(
        platform_name="windows",
        root_dir=mock_repo,
        dist_dir=mock_repo / "dist",
        out_dir=out_dir,
        version="0.2.0",
        arch="x64",
    )

    assert archive.is_file()
    assert archive.name == "t2-kpxc-sync-v0.2.0-windows-x64.zip"

    with zipfile.ZipFile(archive, "r") as zf:
        assert zf.testzip() is None
        names = zf.namelist()
        prefix = "t2-kpxc-sync-v0.2.0-windows-x64"

        assert f"{prefix}/t2-kpxc-sync.exe" in names
        assert f"{prefix}/Sync-Token2.bat" in names
        assert f"{prefix}/config.example.toml" in names
        assert f"{prefix}/README.md" in names
        assert f"{prefix}/docs/architecture.html" in names

        # Verify CRLF in .bat
        bat_content = zf.read(f"{prefix}/Sync-Token2.bat")
        assert b"\r\n" in bat_content
        assert b"\n" not in bat_content.replace(b"\r\n", b"")


def test_package_distribution_linux_tar_gz(mock_repo: Path):
    out_dir = mock_repo / "out"
    archive = package_distribution(
        platform_name="linux",
        root_dir=mock_repo,
        dist_dir=mock_repo / "dist",
        out_dir=out_dir,
        version="0.2.0",
        arch="x64",
    )

    assert archive.is_file()
    assert archive.name == "t2-kpxc-sync-v0.2.0-linux-x64.tar.gz"

    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        member_dict = {m.name: m for m in members}
        prefix = "t2-kpxc-sync-v0.2.0-linux-x64"

        bin_member = member_dict[f"{prefix}/t2-kpxc-sync"]
        assert bin_member.mode == 0o755

        sh_member = member_dict[f"{prefix}/Sync-Token2.sh"]
        assert sh_member.mode == 0o755

        txt_member = member_dict[f"{prefix}/config.example.toml"]
        assert txt_member.mode == 0o644

        # Verify LF only in .sh
        f = tf.extractfile(sh_member)
        assert f is not None
        sh_content = f.read()
        assert b"\r" not in sh_content


def test_package_distribution_missing_binary(mock_repo: Path):
    (mock_repo / "dist" / "t2-kpxc-sync.exe").unlink()
    with pytest.raises(FileNotFoundError, match="t2-kpxc-sync.exe"):
        package_distribution(
            platform_name="windows",
            root_dir=mock_repo,
            dist_dir=mock_repo / "dist",
            out_dir=mock_repo / "out",
        )


def test_existing_repo_launchers_static_compliance():
    root = Path(__file__).resolve().parent.parent

    # Test Linux launcher
    sh_path = root / "Sync-Token2.sh"
    assert sh_path.is_file()
    assert os.access(sh_path, os.X_OK), "Sync-Token2.sh must have +x permission"
    sh_bytes = sh_path.read_bytes()
    assert b"\r" not in sh_bytes, "Sync-Token2.sh must have LF line endings only"

    # Test Windows launcher
    bat_path = root / "Sync-Token2.bat"
    assert bat_path.is_file()
    bat_bytes = bat_path.read_bytes()
    assert b"\r\n" in bat_bytes, "Sync-Token2.bat must have CRLF line endings"
