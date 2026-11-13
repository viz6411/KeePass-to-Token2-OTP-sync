"""Tests for memory security and buffer scrubbing."""

from unittest.mock import MagicMock, patch
from t2_kpxc_sync.security import SecureBuffer, scrub_bytes
from t2_kpxc_sync.kpxc import read_kpxc_entries
from t2_kpxc_sync.token2 import Token2CLIAdapter, build_write_command, build_delete_command, build_get_all_command


def test_buffer_zeroing():
    data = bytearray(b"super_secret_master_password_123")
    assert any(b != 0 for b in data)
    scrub_bytes(data)
    assert all(b == 0 for b in data)


def test_secure_buffer_context_manager():
    secret_bytes = b"my_token2_pin"
    buf_ref = None
    with SecureBuffer(secret_bytes) as buf:
        buf_ref = buf
        assert bytes(buf) == secret_bytes

    # Should be zeroed after exit
    assert all(b == 0 for b in buf_ref)


def test_argv_leak_prevention(tmp_path):
    # 1. Verify KeePassXC password is never exposed in process arguments
    dummy_db = tmp_path / "test.kdbx"
    dummy_db.write_bytes(b"dummy kdbx header")
    secret_password = b"TopSecretMasterPassword999!"

    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"""<KeePassFile><Root><Group><Name>Root</Name></Group></Root></KeePassFile>"""
        mock_proc.stderr = b""
        mock_run.return_value = mock_proc

        read_kpxc_entries(
            db_path=dummy_db,
            password=secret_password,
            cli_binary="keepassxc-cli",
        )

        assert mock_run.called
        call_args, call_kwargs = mock_run.call_args
        cmd_args = call_args[0]
        # Command arguments must not contain the secret password
        for arg in cmd_args:
            assert "TopSecretMasterPassword999!" not in arg
        # Secret must be passed via stdin/input
        assert b"TopSecretMasterPassword999!" in call_kwargs.get("input", b"")

    # 2. Verify Token2 PIN is never exposed in process arguments
    secret_pin = b"849201"
    with patch("subprocess.run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = b"[]"
        mock_proc.stderr = b""
        mock_run.return_value = mock_proc

        with Token2CLIAdapter(cli_binary="token2-otp-cli", pin=secret_pin) as adapter:
            adapter.get_all()

        assert mock_run.called
        call_args, call_kwargs = mock_run.call_args
        cmd_args = call_args[0]
        # Command arguments must not contain the PIN
        for arg in cmd_args:
            assert "849201" not in arg
        # PIN must be passed via stdin/input
        assert b"849201" in call_kwargs.get("input", b"")

    # 3. CLI builder functions must not take PIN in argv
    write_cmd = build_write_command("token2-otp-cli", 1, "Issuer", "Account", "JBSWY3DPEHPK3PXP")
    assert all("--pin" not in arg for arg in write_cmd)
    delete_cmd = build_delete_command("token2-otp-cli", 1)
    assert all("--pin" not in arg for arg in delete_cmd)
    get_all_cmd = build_get_all_command("token2-otp-cli")
    assert all("--pin" not in arg for arg in get_all_cmd)
