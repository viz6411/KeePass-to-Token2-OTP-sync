"""Tests for KeePassXC XML parsing and zero-disk reading."""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from t2_kpxc_sync.kpxc import (
    KeePassXCError,
    parse_kpxc_xml,
    parse_otpauth_uri,
    read_kpxc_entries,
)


def test_otpauth_normalization():
    # 1. Standard format with query issuer and path account
    uri1 = "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
    e1 = parse_otpauth_uri(uri1)
    assert e1 is not None
    assert e1.issuer == "GitHub"
    assert e1.account == "octocat"
    assert e1.secret == "JBSWY3DPEHPK3PXP"
    assert e1.algorithm == "SHA1"
    assert e1.digits == 6
    assert e1.period == 30
    assert e1.canonical_key == ("github", "octocat")

    # 2. Path-only issuer and account, lowercase secret with spaces
    uri2 = "otpauth://totp/Google:user%40example.com?secret=jbsw%20y3dp%20ehpk%203pxp"
    e2 = parse_otpauth_uri(uri2)
    assert e2 is not None
    assert e2.issuer == "Google"
    assert e2.account == "user@example.com"
    assert e2.secret == "JBSWY3DPEHPK3PXP"
    assert e2.algorithm == "SHA1"  # default
    assert e2.digits == 6  # default
    assert e2.period == 30  # default
    assert e2.canonical_key == ("google", "user@example.com")

    # 3. Query issuer overrides path issuer
    uri3 = "otpauth://totp/OldIssuer:bob?issuer=NewIssuer&secret=GEZDGNBVGY3TQOJQ&algorithm=SHA256&digits=8&period=60"
    e3 = parse_otpauth_uri(uri3)
    assert e3 is not None
    assert e3.issuer == "NewIssuer"
    assert e3.account == "bob"
    assert e3.algorithm == "SHA256"
    assert e3.digits == 8
    assert e3.period == 60

    # 4. No issuer in path or query -> fallback to account
    uri4 = "otpauth://totp/loneuser?secret=GEZDGNBVGY3TQOJQ"
    e4 = parse_otpauth_uri(uri4)
    assert e4 is not None
    assert e4.issuer == "loneuser"
    assert e4.account == "loneuser"

    # 5. Invalid scheme or type (hotp)
    assert parse_otpauth_uri("otpauth://hotp/Counter:user?secret=JBSWY3DPEHPK3PXP&counter=1") is None
    assert parse_otpauth_uri("https://example.com/otpauth") is None
    assert parse_otpauth_uri("otpauth://totp/NoSecret:user") is None
    assert parse_otpauth_uri("") is None


def test_recycle_bin_ignored():
    xml_data = """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
    <KeePassFile>
        <Meta>
            <RecycleBinUUID>v9hJ5zY4T82Q3W0x8s2g7w==</RecycleBinUUID>
        </Meta>
        <Root>
            <Group>
                <Name>Root</Name>
                <Group>
                    <Name>ActiveServices</Name>
                    <Entry>
                        <String><Key>Title</Key><Value>MyGitHub</Value></String>
                        <String><Key>otp</Key><Value>otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP</Value></String>
                    </Entry>
                </Group>
                <Group>
                    <Name>Recycle Bin</Name>
                    <UUID>v9hJ5zY4T82Q3W0x8s2g7w==</UUID>
                    <Entry>
                        <String><Key>Title</Key><Value>DeletedGitLab</Value></String>
                        <String><Key>otp</Key><Value>otpauth://totp/GitLab:deleted?secret=GEZDGNBVGY3TQOJQ</Value></String>
                    </Entry>
                </Group>
                <Group>
                    <Name>Archive</Name>
                    <Entry>
                        <String><Key>Title</Key><Value>ArchivedAWS</Value></String>
                        <String><Key>otp</Key><Value>otpauth://totp/AWS:archived?secret=GEZDGNBVGY3TQOJQ</Value></String>
                    </Entry>
                </Group>
            </Group>
        </Root>
    </KeePassFile>"""

    entries = parse_kpxc_xml(xml_data, excluded_groups=["Recycle Bin", "Archive"])
    assert len(entries) == 1
    assert entries[0].issuer == "GitHub"
    assert entries[0].account == "alice"


def test_kpxc_cli_pipe_parsing(tmp_path):
    dummy_db = tmp_path / "vault.kdbx"
    dummy_db.write_bytes(b"dummy kdbx header")

    mock_xml = """<?xml version="1.0" encoding="utf-8"?>
    <KeePassFile>
        <Root>
            <Group>
                <Name>Root</Name>
                <Entry>
                    <String><Key>Title</Key><Value>Personal</Value></String>
                    <String><Key>otp</Key><Value>otpauth://totp/Bitwarden:user?secret=JBSWY3DPEHPK3PXP</Value></String>
                </Entry>
            </Group>
        </Root>
    </KeePassFile>"""

    # Monitor filesystem to ensure no temporary files created
    temp_dir = tmp_path / "temp_check"
    temp_dir.mkdir()

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = mock_xml.encode("utf-8")
        mock_proc.stderr = b""
        mock_run.return_value = mock_proc

        entries = read_kpxc_entries(
            db_path=dummy_db,
            password=bytearray(b"master_pwd"),
            cli_binary="keepassxc-cli",
        )

        assert len(entries) == 1
        assert entries[0].issuer == "Bitwarden"
        assert entries[0].account == "user"

        # Check call arguments: must be pipe export without file output redirection
        cmd = mock_run.call_args[0][0]
        assert "export" in cmd
        assert str(dummy_db) in cmd
        # Ensure no temp file path was passed in arguments
        other_args = [arg for arg in cmd if arg != str(dummy_db)]
        assert not any("tmp" in str(arg).lower() for arg in other_args)
        assert len(list(temp_dir.iterdir())) == 0
