"""Adversarial exploratory chaos testing battery for KeePassXC and Token2 sync."""

from unittest.mock import MagicMock, patch
import pytest

from t2_kpxc_sync.cli import apply_sync
from t2_kpxc_sync.diff import DiffResult, calculate_totp, compute_diff
from t2_kpxc_sync.kpxc import KeePassXCError, parse_kpxc_xml, parse_otpauth_uri, read_kpxc_entries
from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.token2 import Token2CLIAdapter, Token2Error, Token2PINError, parse_entries_json


def test_corrupted_xml_handling():
    # 1. Truncated XML
    with pytest.raises(KeePassXCError) as exc_info:
        parse_kpxc_xml("<KeePassFile><Root><Group><Name>")
    assert "Failed to parse KeePass XML" in str(exc_info.value)

    # 2. Corrupted binary noise
    with pytest.raises(KeePassXCError):
        parse_kpxc_xml(b"\x00\xff\xfe\x12\x34\x56\x78\x9a\xbc\xde")

    # 3. Empty string
    with pytest.raises(KeePassXCError):
        parse_kpxc_xml("")


def test_malformed_json_handling():
    # 1. Truncated JSON
    with pytest.raises(Token2Error) as exc_info:
        parse_entries_json('[{"slot": 1, "issuer": "Git')
    assert "Failed to parse Token2 JSON" in str(exc_info.value)

    # 2. Unexpected root type (int, string, bool)
    with pytest.raises(Token2Error):
        parse_entries_json("12345")

    with pytest.raises(Token2Error):
        parse_entries_json('"just a string"')

    # 3. List with malformed items (None, numbers, missing slot)
    profiles = parse_entries_json('[null, 42, {}, {"slot": "invalid_int"}, {"slot": 1, "issuer": "OK"}]')
    assert len(profiles) == 1
    assert profiles[0].slot == 1
    assert profiles[0].issuer == "OK"


def test_boundary_and_malformed_inputs():
    # 1. 10,000 character strings
    huge_issuer = "A" * 10000
    huge_account = "B" * 10000
    uri_huge = f"otpauth://totp/{huge_issuer}:{huge_account}?secret=JBSWY3DPEHPK3PXP"
    entry_huge = parse_otpauth_uri(uri_huge)
    assert entry_huge is not None
    assert len(entry_huge.issuer) == 10000
    assert len(entry_huge.account) == 10000

    # 2. Unicode, Cyrillic, Chinese, and Emojis in labels
    emoji_uri = "otpauth://totp/%F0%9F%94%91%20%D0%AF%D0%BD%D0%B4%D0%B5%D0%BA%D1%81:%D0%B8%D0%B2%D0%B0%D0%BD%40%D1%8F%D0%BD%D0%B4%D0%B5%D0%BA%D1%81.%D1%80%D1%84?secret=JBSWY3DPEHPK3PXP&issuer=%F0%9F%94%92%20%E9%98%BF%E9%87%8C%E4%BA%91"
    entry_emoji = parse_otpauth_uri(emoji_uri)
    assert entry_emoji is not None
    assert "🔑" in entry_emoji.account or "🔒" in entry_emoji.issuer
    assert "Яндекс" in entry_emoji.account or "阿里云" in entry_emoji.issuer

    # 3. Injection vectors (<script>, SQL ' OR '1'='1', null bytes)
    inj_uri = "otpauth://totp/<script>alert(1)</script>:' OR '1'='1'?secret=JBSWY3DPEHPK3PXP"
    entry_inj = parse_otpauth_uri(inj_uri)
    assert entry_inj is not None
    assert "<script>" in entry_inj.issuer
    assert "' OR '1'='1'" in entry_inj.account

    # 4. Whitespace and boundary numeric values
    boundary_uri = "otpauth://totp/Test:User?secret=JBSWY3DPEHPK3PXP&digits=not_a_number&period=-5"
    entry_b = parse_otpauth_uri(boundary_uri)
    assert entry_b is not None
    assert entry_b.digits == 6  # fallback default
    assert entry_b.period == -5


def test_usb_disconnect_simulation():
    # Simulate hardware USB disconnect during multi-entry write batch
    entries = [
        TOTPEntry(issuer=f"Site{i}", account="user", secret="JBSWY3DPEHPK3PXP")
        for i in range(5)
    ]
    diff = DiffResult(to_add=entries, final_slot_count=5)

    mock_adapter = MagicMock(spec=Token2CLIAdapter)
    written_slots = []

    def mock_write(slot, entry):
        if slot == 3:
            # Simulate USB unplug/communication failure on slot 3
            raise Token2Error("Device disconnected: USB HID write failed: I/O Error")
        written_slots.append(slot)

    mock_adapter.write_entry.side_effect = mock_write

    with pytest.raises(Token2Error) as exc_info:
        apply_sync(mock_adapter, diff, [], mode="add_only")

    assert "Device disconnected" in str(exc_info.value)
    # Verify exactly 2 writes succeeded before disconnect
    assert written_slots == [1, 2]


def test_immediate_abort_on_auth_failure():
    # Chaos test: Multiple rapid calls or failed authentication must abort immediately without trying to guess PIN
    mock_proc = MagicMock()
    mock_proc.returncode = 2
    mock_proc.stdout = b""
    mock_proc.stderr = b"Authentication error: Invalid device PIN"

    with patch("subprocess.run", return_value=mock_proc) as mock_run:
        adapter = Token2CLIAdapter(pin="wrong_pin")
        with pytest.raises(Token2PINError):
            adapter.get_all()

        # Must execute only once and abort
        assert mock_run.call_count == 1
