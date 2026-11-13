"""Tests for Token2 CLI adapter and profile operations."""

import json
from unittest.mock import MagicMock, patch
import pytest

from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.token2 import (
    Token2CLIAdapter,
    Token2Error,
    Token2PINError,
    build_delete_command,
    build_get_all_command,
    build_write_command,
    parse_entries_json,
)


def test_parse_entries_json():
    # 1. Parsing standard JSON list
    sample_list = [
        {
            "slot": 1,
            "issuer": "GitHub",
            "account": "octocat",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
            "current_otp": "123456",
        },
        {
            "slot": "2",
            "issuer": "Google",
            "name": "user@gmail.com",
            "algorithm": "SHA256",
            "digits": "8",
            "period": "60",
            "otp": "98765432",
        },
    ]
    profiles = parse_entries_json(json.dumps(sample_list))
    assert len(profiles) == 2
    assert profiles[0].slot == 1
    assert profiles[0].issuer == "GitHub"
    assert profiles[0].account == "octocat"
    assert profiles[0].algorithm == "SHA1"
    assert profiles[0].digits == 6
    assert profiles[0].period == 30
    assert profiles[0].current_otp == "123456"

    assert profiles[1].slot == 2
    assert profiles[1].issuer == "Google"
    assert profiles[1].account == "user@gmail.com"
    assert profiles[1].algorithm == "SHA256"
    assert profiles[1].digits == 8
    assert profiles[1].period == 60
    assert profiles[1].current_otp == "98765432"

    # 2. Parsing nested dict format {"entries": [...]}
    nested_data = {"entries": sample_list}
    profiles_nested = parse_entries_json(json.dumps(nested_data))
    assert len(profiles_nested) == 2

    # 3. Parsing with bytes input
    profiles_bytes = parse_entries_json(json.dumps(sample_list).encode("utf-8"))
    assert len(profiles_bytes) == 2


def test_pin_immediate_abort():
    # Token2 PIN protection: must fail immediately without retries to prevent bricking the hardware token
    call_count = 0

    def mock_run_fail(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = b""
        mock_proc.stderr = b"Error: Wrong PIN provided. 2 attempts remaining."
        return mock_proc

    with patch("subprocess.run", side_effect=mock_run_fail):
        with pytest.raises(Token2PINError) as exc_info:
            with Token2CLIAdapter(cli_binary="token2-otp-cli", pin="000000") as adapter:
                adapter.get_all()

        assert "Wrong PIN" in str(exc_info.value)
        # Verify execution stopped immediately on first attempt — NO retry loop
        assert call_count == 1


def test_write_delete_commands():
    # 1. Write entry command formatting
    cmd_write = build_write_command(
        cli_binary="token2-otp-cli",
        slot=5,
        issuer="Cloudflare",
        account="admin@cf.com",
        secret="JBSWY3DPEHPK3PXP",
        algorithm="SHA256",
        digits=8,
        period=60,
    )
    assert cmd_write == [
        "token2-otp-cli",
        "write_entry",
        "--slot",
        "5",
        "--issuer",
        "Cloudflare",
        "--account",
        "admin@cf.com",
        "--secret",
        "JBSWY3DPEHPK3PXP",
        "--algorithm",
        "SHA256",
        "--digits",
        "8",
        "--period",
        "60",
    ]

    # 2. Delete entry command formatting
    cmd_delete = build_delete_command(cli_binary="token2-otp-cli", slot=12)
    assert cmd_delete == ["token2-otp-cli", "delete_entry", "--slot", "12"]

    # 3. Get all command formatting
    cmd_get_all = build_get_all_command(cli_binary="token2-otp-cli")
    assert cmd_get_all == ["token2-otp-cli", "get_all", "--json"]
