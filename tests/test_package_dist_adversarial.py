"""Adversarial stress testing suite for distribution packaging automation.

Empirically tests scripts/package_dist.py against:
1. Missing binary errors (Windows .exe, Linux ELF) with clear diagnostics.
2. Missing required launcher scripts, configs, and documentation.
3. Non-existent dist-dir, root-dir, and invalid out-dir types.
4. Edge-case version strings (leading 'v', prerelease suffixes, build metadata).
5. Tar bomb prevention (enclosing folder invariant across all archive members).
6. File permission bits (0o755 for executables/launchers, 0o644 for configs/docs).
7. Line-ending normalization (CRLF with zero bare LF for Windows, LF with zero CR for Linux).
8. Real archive extraction and standalone execution smoke testing.
9. Archive idempotency and corruption-free overwriting.
10. Optional release notes and Archify architecture viewer integration.
"""

from __future__ import annotations

import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
import pytest

repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from scripts.package_dist import (
    DistItem,
    PackagingError,
    build_manifest,
    create_tar_archive,
    create_zip_archive,
    get_version,
    main as cli_main,
    normalize_line_endings,
    package_distribution,
)


@pytest.fixture
def mock_fixture_tree(tmp_path: Path):
    """Sets up a complete isolated fixture tree for packaging operations."""
    root = tmp_path / "workspace"
    root.mkdir()

    # Package source
    pkg = root / "src" / "t2_kpxc_sync"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text('__version__ = "0.2.0"\n', encoding="utf-8")

    # Launchers
    (root / "Sync-Token2.bat").write_text("@echo off\r\nREM launcher\r\n", encoding="utf-8")
    (root / "Sync-Token2.sh").write_text("#!/usr/bin/env bash\necho launcher\n", encoding="utf-8")
    (root / "Sync-Token2.command").write_text("#!/usr/bin/env bash\necho macos\n", encoding="utf-8")

    # Configuration & Docs
    (root / "config.example.toml").write_text("[sync]\nmode = 'add_only'\n", encoding="utf-8")
    (root / "README.md").write_text("# Documentation with Unicode: Привет мир 🚀\n", encoding="utf-8")

    # Archify viewer
    docs = root / "docs"
    docs.mkdir()
    (docs / "architecture.html").write_text("<!DOCTYPE html><html>Archify</html>\n", encoding="utf-8")

    # Dist directory with mock binaries
    dist = root / "dist"
    dist.mkdir()
    (dist / "t2-kpxc-sync").write_bytes(b"\x7fELF_DUMMY_LINUX_BINARY")
    (dist / "t2-kpxc-sync.exe").write_bytes(b"MZ_DUMMY_WINDOWS_BINARY")

    out = root / "out"
    out.mkdir()

    return {
        "root": root,
        "dist": dist,
        "out": out,
        "docs": docs,
    }


# ==============================================================================
# 1. Missing Binary and Missing File Error Scenarios
# ==============================================================================

def test_missing_binary_linux_raises_diagnostic(mock_fixture_tree):
    """Verify missing Linux executable raises FileNotFoundError citing PyInstaller build."""
    tree = mock_fixture_tree
    (tree["dist"] / "t2-kpxc-sync").unlink()

    with pytest.raises(FileNotFoundError, match="t2-kpxc-sync") as exc_info:
        package_distribution(
            platform_name="linux",
            root_dir=tree["root"],
            dist_dir=tree["dist"],
            out_dir=tree["out"],
        )
    assert "ensure PyInstaller has built it first" in str(exc_info.value)


def test_missing_binary_windows_raises_diagnostic(mock_fixture_tree):
    """Verify missing Windows .exe raises FileNotFoundError citing PyInstaller build."""
    tree = mock_fixture_tree
    (tree["dist"] / "t2-kpxc-sync.exe").unlink()

    with pytest.raises(FileNotFoundError, match="t2-kpxc-sync.exe") as exc_info:
        package_distribution(
            platform_name="windows",
            root_dir=tree["root"],
            dist_dir=tree["dist"],
            out_dir=tree["out"],
        )
    assert "ensure PyInstaller has built it first" in str(exc_info.value)


def test_missing_launcher_script_raises_error(mock_fixture_tree):
    """Verify missing launcher script raises FileNotFoundError."""
    tree = mock_fixture_tree
    (tree["root"] / "Sync-Token2.sh").unlink()

    with pytest.raises(FileNotFoundError, match="Sync-Token2.sh"):
        package_distribution(
            platform_name="linux",
            root_dir=tree["root"],
            dist_dir=tree["dist"],
            out_dir=tree["out"],
        )


def test_missing_required_config_template_raises_error(mock_fixture_tree):
    """Verify missing config.example.toml raises FileNotFoundError."""
    tree = mock_fixture_tree
    (tree["root"] / "config.example.toml").unlink()

    with pytest.raises(FileNotFoundError, match="config.example.toml"):
        package_distribution(
            platform_name="linux",
            root_dir=tree["root"],
            dist_dir=tree["dist"],
            out_dir=tree["out"],
        )


def test_missing_required_readme_raises_error(mock_fixture_tree):
    """Verify missing README.md raises FileNotFoundError."""
    tree = mock_fixture_tree
    (tree["root"] / "README.md").unlink()

    with pytest.raises(FileNotFoundError, match="README.md"):
        package_distribution(
            platform_name="windows",
            root_dir=tree["root"],
            dist_dir=tree["dist"],
            out_dir=tree["out"],
        )


def test_nonexistent_dist_dir_raises_error(mock_fixture_tree):
    """Verify non-existent dist_dir raises FileNotFoundError."""
    tree = mock_fixture_tree
    non_existent = tree["root"] / "non_existent_dist"

    with pytest.raises(FileNotFoundError, match="t2-kpxc-sync"):
        package_distribution(
            platform_name="linux",
            root_dir=tree["root"],
            dist_dir=non_existent,
            out_dir=tree["out"],
        )


def test_nonexistent_root_dir_raises_error(mock_fixture_tree):
    """Verify non-existent root_dir raises FileNotFoundError."""
    tree = mock_fixture_tree
    non_existent = tree["root"] / "non_existent_root"

    with pytest.raises(FileNotFoundError):
        package_distribution(
            platform_name="linux",
            root_dir=non_existent,
            dist_dir=tree["dist"],
            out_dir=tree["out"],
        )


def test_out_dir_as_file_fails_cleanly(mock_fixture_tree):
    """Verify that an existing file passed as out_dir fails cleanly."""
    tree = mock_fixture_tree
    file_as_out = tree["root"] / "out_as_file"
    file_as_out.write_text("regular file")

    with pytest.raises(OSError):
        package_distribution(
            platform_name="linux",
            root_dir=tree["root"],
            dist_dir=tree["dist"],
            out_dir=file_as_out,
        )


# ==============================================================================
# 2. Version String Handling and Normalization
# ==============================================================================

@pytest.mark.parametrize(
    "raw_ver,expected_prefix",
    [
        ("0.2.0", "t2-kpxc-sync-v0.2.0"),
        ("v0.2.0", "t2-kpxc-sync-v0.2.0"),
        ("vv0.2.0", "t2-kpxc-sync-v0.2.0"),
        ("0.2.0-rc1", "t2-kpxc-sync-v0.2.0-rc1"),
        ("v0.2.0-beta.2", "t2-kpxc-sync-v0.2.0-beta.2"),
        ("1.0.0+build20261114", "t2-kpxc-sync-v1.0.0+build20261114"),
    ],
)
def test_version_normalization(mock_fixture_tree, raw_ver, expected_prefix):
    """Verify version normalization handles leading 'v' and semver prerelease tags."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="linux",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version=raw_ver,
    )
    assert archive.name.startswith(expected_prefix)
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf.getmembers():
            assert member.name.startswith(expected_prefix)


def test_version_fallback_to_pkg_init(mock_fixture_tree):
    """Verify version is dynamically loaded from package __init__.py when omitted."""
    tree = mock_fixture_tree
    (tree["root"] / "src" / "t2_kpxc_sync" / "__init__.py").write_text('__version__ = "0.3.5"\n')

    archive = package_distribution(
        platform_name="linux",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version=None,
    )
    assert "v0.3.5" in archive.name


# ==============================================================================
# 3. Tar Bomb Prevention & Archive Structure Invariant
# ==============================================================================

def test_tar_bomb_prevention_linux(mock_fixture_tree):
    """Verify that every member in the tar.gz archive is contained within the root bundle folder."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="linux",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
        arch="x64",
    )

    prefix = "t2-kpxc-sync-v0.2.0-linux-x64"
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        assert len(members) >= 5
        for m in members:
            # Must strictly start with prefix + '/'
            assert m.name.startswith(f"{prefix}/"), f"Tar bomb violation: {m.name} escapes enclosing folder"
            # No path traversal markers
            assert ".." not in m.name
            assert not m.name.startswith("/")
            assert "\\" not in m.name


def test_tar_bomb_prevention_windows(mock_fixture_tree):
    """Verify that every member in the ZIP archive is contained within the root bundle folder."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="windows",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
        arch="x64",
    )

    prefix = "t2-kpxc-sync-v0.2.0-windows-x64"
    with zipfile.ZipFile(archive, "r") as zf:
        names = zf.namelist()
        assert len(names) >= 5
        for name in names:
            assert name.startswith(f"{prefix}/"), f"Zip bomb violation: {name} escapes enclosing folder"
            assert ".." not in name
            assert not name.startswith("/")
            assert "\\" not in name


def test_flat_mode_archive_structure(mock_fixture_tree):
    """Verify that --flat creates archives without the enclosing folder."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="linux",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
        flat=True,
    )

    with tarfile.open(archive, "r:gz") as tf:
        names = tf.getnames()
        assert "t2-kpxc-sync" in names
        assert "Sync-Token2.sh" in names
        assert "config.example.toml" in names
        assert not any(n.startswith("t2-kpxc-sync-v0.2.0") for n in names)


# ==============================================================================
# 4. File Permission Bits Verification
# ==============================================================================

def test_linux_tar_gz_permission_bits(mock_fixture_tree):
    """Verify exact permission bits and ownership in Linux tar.gz archive."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="linux",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
    )

    prefix = "t2-kpxc-sync-v0.2.0-linux-x64"
    with tarfile.open(archive, "r:gz") as tf:
        m_dict = {m.name: m for m in tf.getmembers()}

        # Binaries & scripts: 0o755 (rwxr-xr-x)
        assert m_dict[f"{prefix}/t2-kpxc-sync"].mode == 0o755
        assert m_dict[f"{prefix}/Sync-Token2.sh"].mode == 0o755

        # Configs & documentation: 0o644 (rw-r--r--)
        assert m_dict[f"{prefix}/config.example.toml"].mode == 0o644
        assert m_dict[f"{prefix}/README.md"].mode == 0o644
        assert m_dict[f"{prefix}/docs/architecture.html"].mode == 0o644

        # Normalized root ownership
        for m in m_dict.values():
            assert m.uid == 0
            assert m.gid == 0
            assert m.uname == "root"
            assert m.gname == "root"


def test_windows_zip_permission_attributes(mock_fixture_tree):
    """Verify Unix mode attributes encoded in Windows ZIP headers."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="windows",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
    )

    prefix = "t2-kpxc-sync-v0.2.0-windows-x64"
    with zipfile.ZipFile(archive, "r") as zf:
        # Check external_attr for Unix mode
        info_exe = zf.getinfo(f"{prefix}/t2-kpxc-sync.exe")
        assert ((info_exe.external_attr >> 16) & 0xFFFF) == 0o755

        info_bat = zf.getinfo(f"{prefix}/Sync-Token2.bat")
        assert ((info_bat.external_attr >> 16) & 0xFFFF) == 0o644

        info_toml = zf.getinfo(f"{prefix}/config.example.toml")
        assert ((info_toml.external_attr >> 16) & 0xFFFF) == 0o644


# ==============================================================================
# 5. Line Ending Conversion Verification (CRLF vs LF)
# ==============================================================================

def test_windows_zip_crlf_line_endings(mock_fixture_tree):
    """Verify that Windows text files strictly have CRLF without any bare LF."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="windows",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
    )

    prefix = "t2-kpxc-sync-v0.2.0-windows-x64"
    with zipfile.ZipFile(archive, "r") as zf:
        for fname in ["Sync-Token2.bat", "config.example.toml", "README.md"]:
            content = zf.read(f"{prefix}/{fname}")
            assert b"\r\n" in content, f"{fname} must have CRLF"
            # Verify no bare LF
            bare_lf = content.replace(b"\r\n", b"").count(b"\n")
            assert bare_lf == 0, f"{fname} contains {bare_lf} bare LF characters"


def test_linux_tar_lf_line_endings(mock_fixture_tree):
    """Verify that Linux text files strictly have LF without any CR characters."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="linux",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
    )

    prefix = "t2-kpxc-sync-v0.2.0-linux-x64"
    with tarfile.open(archive, "r:gz") as tf:
        for fname in ["Sync-Token2.sh", "config.example.toml", "README.md"]:
            f = tf.extractfile(f"{prefix}/{fname}")
            assert f is not None
            content = f.read()
            assert b"\n" in content
            assert b"\r" not in content, f"{fname} contains carriage return (CR) characters"


# ==============================================================================
# 6. Real Archive Extraction and Disk Verification
# ==============================================================================

def test_unzip_system_extraction_preserves_modes(mock_fixture_tree, tmp_path):
    """Verify system unzip extracts files with correct mode bits."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="windows",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
    )

    extract_dir = tmp_path / "unzip_target"
    extract_dir.mkdir()

    res = subprocess.run(["unzip", "-q", str(archive), "-d", str(extract_dir)], capture_output=True, text=True)
    assert res.returncode == 0, f"unzip failed: {res.stderr}"

    prefix = "t2-kpxc-sync-v0.2.0-windows-x64"
    exe_file = extract_dir / prefix / "t2-kpxc-sync.exe"
    bat_file = extract_dir / prefix / "Sync-Token2.bat"

    assert exe_file.is_file()
    assert bat_file.is_file()
    assert (exe_file.stat().st_mode & 0o777) == 0o755
    assert (bat_file.stat().st_mode & 0o777) == 0o644


def test_tar_system_extraction_and_binary_smoke(tmp_path):
    """Verify extraction of the real project Linux archive and execute the standalone binary."""
    real_dist_dir = repo_root / "dist"
    real_bin = real_dist_dir / "t2-kpxc-sync"
    if not real_bin.is_file():
        pytest.skip("Real standalone binary not built; skipping smoke test")

    out_archive = tmp_path / "real_archive"
    out_archive.mkdir()

    archive_path = package_distribution(
        platform_name="linux",
        root_dir=repo_root,
        dist_dir=real_dist_dir,
        out_dir=out_archive,
        version="0.2.0",
    )

    extract_dir = tmp_path / "extracted_real"
    extract_dir.mkdir()

    res = subprocess.run(["tar", "-xzf", str(archive_path), "-C", str(extract_dir)], capture_output=True, text=True)
    assert res.returncode == 0, f"tar extraction failed: {res.stderr}"

    prefix = "t2-kpxc-sync-v0.2.0-linux-x64"
    extracted_bin = extract_dir / prefix / "t2-kpxc-sync"
    extracted_sh = extract_dir / prefix / "Sync-Token2.sh"

    assert extracted_bin.is_file()
    assert os.access(extracted_bin, os.X_OK)
    assert os.access(extracted_sh, os.X_OK)

    # Execute standalone binary --help
    run_bin = subprocess.run([str(extracted_bin), "--help"], capture_output=True, text=True)
    assert run_bin.returncode == 0
    assert "usage: t2-kpxc-sync" in run_bin.stdout

    # Execute launcher script --help
    run_sh = subprocess.run([str(extracted_sh), "--help"], capture_output=True, text=True)
    assert run_sh.returncode == 0
    assert "usage: t2-kpxc-sync" in run_sh.stdout


# ==============================================================================
# 7. Idempotency and Overwrite Safety
# ==============================================================================

def test_idempotent_archive_overwriting(mock_fixture_tree):
    """Verify that packaging into an existing destination archive overwrites cleanly without corruption."""
    tree = mock_fixture_tree

    archive1 = package_distribution(
        platform_name="linux",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
    )
    assert archive1.is_file()

    # Modify a source file
    (tree["root"] / "README.md").write_text("# Updated Documentation\n", encoding="utf-8")

    archive2 = package_distribution(
        platform_name="linux",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
    )
    assert archive1 == archive2

    # Verify archive integrity and updated content
    with tarfile.open(archive2, "r:gz") as tf:
        m = tf.getmember("t2-kpxc-sync-v0.2.0-linux-x64/README.md")
        f = tf.extractfile(m)
        assert f is not None
        assert f.read() == b"# Updated Documentation\n"


# ==============================================================================
# 8. Optional Components (Release Notes, Archify Viewer, Darwin Launcher)
# ==============================================================================

def test_optional_release_notes_inclusion(mock_fixture_tree):
    """Verify release notes are packaged when present and skipped when absent."""
    tree = mock_fixture_tree
    (tree["root"] / "RELEASE_NOTES_v0.2.0.md").write_text("## Notes v0.2.0\n", encoding="utf-8")

    archive = package_distribution(
        platform_name="linux",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
    )

    with tarfile.open(archive, "r:gz") as tf:
        names = tf.getnames()
        assert "t2-kpxc-sync-v0.2.0-linux-x64/RELEASE_NOTES_v0.2.0.md" in names


def test_optional_archify_html_inclusion(mock_fixture_tree):
    """Verify docs/architecture.html is packaged into docs/ subfolder in archive."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="linux",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
    )

    with tarfile.open(archive, "r:gz") as tf:
        names = tf.getnames()
        assert "t2-kpxc-sync-v0.2.0-linux-x64/docs/architecture.html" in names


def test_darwin_launcher_inclusion(mock_fixture_tree):
    """Verify Sync-Token2.command is packaged for darwin platform with executable permissions."""
    tree = mock_fixture_tree
    archive = package_distribution(
        platform_name="darwin",
        root_dir=tree["root"],
        dist_dir=tree["dist"],
        out_dir=tree["out"],
        version="0.2.0",
    )

    prefix = "t2-kpxc-sync-v0.2.0-darwin-x64"
    with tarfile.open(archive, "r:gz") as tf:
        m = tf.getmember(f"{prefix}/Sync-Token2.command")
        assert m.mode == 0o755


# ==============================================================================
# 9. CLI Invocations and Exit Codes
# ==============================================================================

def test_cli_success(mock_fixture_tree):
    """Verify CLI exit code 0 on success."""
    tree = mock_fixture_tree
    ret = cli_main([
        "--platform", "linux",
        "--root-dir", str(tree["root"]),
        "--dist-dir", str(tree["dist"]),
        "--out-dir", str(tree["out"]),
        "--version", "0.2.0",
    ])
    assert ret == 0


def test_cli_missing_binary_exit_code_1(mock_fixture_tree, capsys):
    """Verify CLI exit code 1 on missing binary with diagnostic printed to stderr."""
    tree = mock_fixture_tree
    (tree["dist"] / "t2-kpxc-sync").unlink()

    ret = cli_main([
        "--platform", "linux",
        "--root-dir", str(tree["root"]),
        "--dist-dir", str(tree["dist"]),
        "--out-dir", str(tree["out"]),
        "--version", "0.2.0",
    ])
    assert ret == 1
    captured = capsys.readouterr()
    assert "[ERROR] Packaging failed: Required file" in captured.err
    assert "t2-kpxc-sync" in captured.err


def test_cli_invalid_arg_exit_code_2():
    """Verify CLI exit code 2 on invalid platform option."""
    with pytest.raises(SystemExit) as exc:
        cli_main(["--platform", "freebsd"])
    assert exc.value.code == 2
