"""Comprehensive unit and mock-hardware tests for Token2 native USB-HID protocol (Milestone 2).

Tests:
1. MockHIDTransport framing, chunk fragmentation (>61 bytes in send/recv), and 0xC0 polling.
2. NIST P-256 ECDH + AES-256-CBC (IV-1) crypto engine round-trip and error validation.
3. APDU serialization and parsing (WRITE_SEED, DELETE, ENUM_CODES, pagination, bricking guard).
4. Token2DirectClient complete lifecycle operations.
5. Error handling (memory full, button timeout, device not found, safety guards).
6. Token2Adapter unified facade with synthetic slot translation and memory scrubbing.
"""

import pytest

from t2_kpxc_sync.models import TOTPEntry
from t2_kpxc_sync.token2 import (
    CMD_SET_DEVICE_TYPE,
    IV_1,
    SW_BUTTON_TIMEOUT,
    SW_OK,
    MockHIDTransport,
    Token2Adapter,
    Token2ButtonTimeoutError,
    Token2DirectClient,
    Token2MemoryFullError,
    Token2ProtocolError,
    Token2TimeoutError,
    build_apdu,
    build_get_ecdh_pubkey_apdu,
    build_get_info_apdu,
    build_write_seed_apdu,
    decrypt_payload_ecdh,
    encrypt_payload_ecdh,
    generate_ecdh_keypair,
    parse_enum_response,
    parse_status_word,
    public_key_from_raw_bytes,
    serialize_delete_payload,
    serialize_write_seed_payload,
    validate_apdu_safety,
)

# ============================================================================
# 1. Cryptographic Engine Tests (NIST P-256 ECDH + AES-256-CBC with IV-1)
# ============================================================================

def test_ecdh_aes_round_trip():
    """Tests P-256 key generation, ECDH derivation, and AES-256-CBC IV-1 round-trip."""
    token_priv, token_pub_raw = generate_ecdh_keypair()
    assert len(token_pub_raw) == 64

    payload = b"TopSecretSeedDataForToken2HardwareProvisioning12345"
    encrypted_block = encrypt_payload_ecdh(token_pub_raw, payload, IV_1)

    # Structure: 64 bytes host public key + at least 16 bytes ciphertext
    assert len(encrypted_block) >= 80
    assert encrypted_block[:64] != token_pub_raw

    # Decrypt with token's private key
    decrypted = decrypt_payload_ecdh(token_priv, encrypted_block, IV_1)
    assert decrypted == payload


def test_crypto_invalid_inputs():
    """Tests edge cases and error handling in crypto primitives."""
    token_priv, _ = generate_ecdh_keypair()

    # Public key must be exactly 64 bytes
    with pytest.raises(ValueError, match="Expected 64 bytes"):
        public_key_from_raw_bytes(b"too_short")

    # Encrypted block too short
    with pytest.raises(ValueError, match="Encrypted block too short"):
        decrypt_payload_ecdh(token_priv, b"short_data")

    # Corrupted ciphertext fails PKCS#7 unpadding or AES block
    _, token_pub_raw = generate_ecdh_keypair()
    valid_enc = encrypt_payload_ecdh(token_pub_raw, b"SamplePayload1234")
    # Corrupt ciphertext to non-block boundary (guaranteed ValueError from AES-CBC)
    corrupted_enc = valid_enc[:-1]
    with pytest.raises(ValueError):
        decrypt_payload_ecdh(token_priv, corrupted_enc)


# ============================================================================
# 2. Protocol Serialization & APDU Framing Tests
# ============================================================================

def test_apdu_bricking_guard():
    """Validates that SET_DEVICE_TYPE is strictly blocked to protect hardware keys."""
    # Attempting to validate or build an APDU containing CMD_SET_DEVICE_TYPE must fail
    with pytest.raises(Token2ProtocolError, match="CMD_SET_DEVICE_TYPE"):
        validate_apdu_safety(CMD_SET_DEVICE_TYPE)

    with pytest.raises(Token2ProtocolError, match="CMD_SET_DEVICE_TYPE"):
        build_apdu(CMD_SET_DEVICE_TYPE, b"\x01\x02\x03")


def test_serialize_write_and_delete_payloads():
    """Tests payload packing for write_seed and delete operations."""
    raw_seed = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10"

    # 1. Write payload: SHA1, 30s timestep, 6 digits, no button
    write_payload = serialize_write_seed_payload(
        app_name="GitHub",
        account_name="octocat",
        raw_seed=raw_seed,
        algorithm="SHA1",
        timestep=30,
        code_length=6,
        btn_flag=0,
    )
    assert write_payload[0] == 0x01  # TOTP
    assert write_payload[1] == 0xC1  # SHA1
    assert write_payload[2:4] == (30).to_bytes(2, "big")
    assert write_payload[4] == 6     # digits
    assert write_payload[5] == 0     # no touch button
    assert write_payload[6] == len(b"GitHub")
    assert write_payload[7:13] == b"GitHub"

    # 2. Delete payload: zeroed parameters, seed length = 0
    delete_payload = serialize_delete_payload("GitHub", "octocat")
    assert delete_payload[:6] == b"\x00\x00\x00\x00\x00\x00"
    assert delete_payload[-1] == 0  # seed_len = 0

    # 3. Input length constraints
    with pytest.raises(ValueError, match="Issuer/app name too long"):
        serialize_write_seed_payload("A" * 65, "account", raw_seed)

    with pytest.raises(ValueError, match="Account name too long"):
        serialize_write_seed_payload("app", "B" * 65, raw_seed)

    with pytest.raises(ValueError, match="Raw seed too long"):
        serialize_write_seed_payload("app", "account", b"X" * 65)


def test_parse_enum_response_with_and_without_otp():
    """Tests streaming deserialization of packed profiles with continuation bits."""
    # Build a simulated packed ENUM_CODES response
    # Entry 1: TOTP, SHA1, 30s, 6 digits, btn_flag=0 (includes 6-digit OTP '123456')
    app1 = b"AWS"
    acct1 = b"alice"
    otp1 = b"654321"
    entry1 = (
        bytes([0xC1])
        + (30).to_bytes(2, "big")
        + bytes([6, 0, len(app1)])
        + app1
        + bytes([len(acct1)])
        + acct1
        + bytes([len(otp1)])
        + otp1
    )

    # Entry 2: TOTP, SHA256, 60s, 8 digits, btn_flag=1 (button required, NO OTP in stream)
    app2 = b"GitLab"
    acct2 = b"bob"
    entry2 = (
        bytes([0x01, 0xC2])
        + (60).to_bytes(2, "big")
        + bytes([8, 1, len(app2)])
        + app2
        + bytes([len(acct2)])
        + acct2
    )

    # First byte: continuation flag 0x80 | type 0x01 (TOTP)
    first_byte = 0x80 | 0x01
    full_stream = bytes([first_byte]) + entry1 + entry2

    entries, has_more = parse_enum_response(full_stream)
    assert has_more is True
    assert len(entries) == 2

    assert entries[0]["app_name"] == "AWS"
    assert entries[0]["account_name"] == "alice"
    assert entries[0]["algorithm"] == "SHA1"
    assert entries[0]["timestep"] == 30
    assert entries[0]["digits"] == 6
    assert entries[0]["btn_flag"] == 0
    assert entries[0]["otp_code"] == "654321"

    assert entries[1]["app_name"] == "GitLab"
    assert entries[1]["account_name"] == "bob"
    assert entries[1]["algorithm"] == "SHA256"
    assert entries[1]["timestep"] == 60
    assert entries[1]["digits"] == 8
    assert entries[1]["btn_flag"] == 1
    assert entries[1]["otp_code"] is None


# ============================================================================
# 3. Mock Transport Framing, Fragmentation & Polling Tests
# ============================================================================

def test_mock_transport_framing_and_fragmentation():
    """Tests 65-byte Feature Report framing and multi-packet fragmentation in both directions."""
    mock = MockHIDTransport(serial="T2F2-TEST-UNIT")
    mock.open()

    # 1. Device Info (CMD_GET_INFO)
    resp = mock.send_apdu(build_get_info_apdu())
    data, sw = parse_status_word(resp)
    assert sw == SW_OK
    assert data[0] == 0xD1
    serial_len = data[1]
    assert data[2 : 2 + serial_len].decode("ascii") == "T2F2-TEST-UNIT"

    # 2. Get ECDH Public Key (CMD_GET_ECDH_PUBKEY)
    # Returns 64 bytes public key + 2 bytes status word = 66 bytes total.
    # Because 66 > 61 bytes, this verifies multi-packet fragmentation on the response path!
    resp_pub = mock.send_apdu(build_get_ecdh_pubkey_apdu())
    pub_data, sw_pub = parse_status_word(resp_pub)
    assert sw_pub == SW_OK
    assert len(pub_data) == 64

    # 3. Multi-packet outgoing APDU (> 61 bytes)
    # Provision an entry with a long issuer name, which exceeds single-frame 61 bytes
    long_issuer = "CorporateSingleSignOnGatewayForInfrastructure"
    seed = b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0\xB0\xC0\xD0\xE0\xF0\x00"
    payload = serialize_write_seed_payload(long_issuer, "admin", seed)
    encrypted_block = encrypt_payload_ecdh(pub_data, payload)
    # Encrypted block length is 64 + 80 = 144 bytes. APDU is 7 + 144 = 151 bytes!
    # Requires 3 frames on the USB bus (61 + 61 + 29).
    apdu_write = build_write_seed_apdu(encrypted_block)
    assert len(apdu_write) > 140

    resp_write = mock.send_apdu(apdu_write)
    _, sw_write = parse_status_word(resp_write)
    assert sw_write == SW_OK
    assert (long_issuer, "admin") in mock.entries

    mock.close()


def test_mock_transport_polling_flag_0xC0():
    """Tests 0xC0 polling flag handling when device reports in-progress."""
    mock = MockHIDTransport()
    mock.open()

    # Set mock device to report busy / in-progress for 3 polling cycles
    mock.poll_delay_countdown = 3
    polled_counts = []

    def on_poll(count: int):
        polled_counts.append(count)

    resp = mock.send_apdu(build_get_info_apdu(), on_polling_callback=on_poll)
    _, sw = parse_status_word(resp)
    assert sw == SW_OK
    # Must have polled at least 3 times before receiving the real response
    assert len(polled_counts) >= 3

    mock.close()


def test_mock_transport_timeout_simulation():
    """Tests timeout handling when device never finishes polling."""
    mock = MockHIDTransport()
    mock.open()

    # Device set to poll indefinitely
    mock.poll_delay_countdown = 99999

    with pytest.raises(Token2TimeoutError, match="Timed out after"):
        mock.send_apdu(build_get_info_apdu(), timeout=0.15)

    mock.close()


# ============================================================================
# 4. Token2DirectClient Complete Lifecycle Tests
# ============================================================================

def test_direct_client_lifecycle():
    """Tests complete Token2DirectClient lifecycle (get_info, write, list, read_otp, delete, erase)."""
    mock = MockHIDTransport(serial="T2F2-TEST-CLIENT")
    client = Token2DirectClient(transport=mock)

    with client:
        # 1. Device Info
        info = client.get_info()
        assert info == "T2F2-TEST-CLIENT"

        # 2. Empty list initially
        entries = client.list_entries()
        assert len(entries) == 0

        # 3. Write entries (provisioning)
        # Entry 1: Standard RFC 4226 Base32 seed
        client.write_entry(
            issuer="GitHub",
            account="octocat",
            secret="JBSWY3DPEHPK3PXP",  # "Hello!" in Base32
            algorithm="SHA1",
            digits=6,
            period=30,
        )

        # Entry 2: SHA256, 8 digits, 60s
        client.write_entry(
            issuer="Cloudflare",
            account="admin@cf.com",
            secret="MZXW6YTBOI======",
            algorithm="SHA256",
            digits=8,
            period=60,
        )

        # 4. List entries and verify properties
        profiles = client.list_entries()
        assert len(profiles) == 2
        assert profiles[0].slot == 1
        assert profiles[0].issuer == "GitHub"
        assert profiles[0].account == "octocat"
        assert profiles[0].algorithm == "SHA1"
        assert profiles[0].digits == 6
        assert profiles[0].period == 30
        assert profiles[0].current_otp is not None
        assert len(profiles[0].current_otp) == 6

        assert profiles[1].slot == 2
        assert profiles[1].issuer == "Cloudflare"
        assert profiles[1].account == "admin@cf.com"
        assert profiles[1].algorithm == "SHA256"
        assert profiles[1].digits == 8
        assert profiles[1].period == 60
        assert profiles[1].current_otp is not None
        assert len(profiles[1].current_otp) == 8

        # 5. Read single OTP code
        otp_single = client.read_otp("GitHub", "octocat")
        assert otp_single is not None
        assert len(otp_single) == 6
        assert otp_single == profiles[0].current_otp

        # 6. Overwrite existing entry in place
        client.write_entry(
            issuer="GitHub",
            account="octocat",
            secret="KRSXG5CTMVRXEZLU",  # New secret
            algorithm="SHA1",
            digits=6,
            period=30,
        )
        updated_profiles = client.list_entries()
        # Count remains 2 (overwritten, not duplicated)
        assert len(updated_profiles) == 2

        # 7. Delete one entry
        client.delete_entry("GitHub", "octocat")
        remaining = client.list_entries()
        assert len(remaining) == 1
        assert remaining[0].issuer == "Cloudflare"

        # 8. Erase all
        client.erase_all()
        assert len(client.list_entries()) == 0


def test_direct_client_pagination():
    """Tests multi-page enumeration through CMD_ENUM_CODES_CONTINUE."""
    # Set page size to 2 entries per page
    mock = MockHIDTransport(page_size=2)
    client = Token2DirectClient(transport=mock)

    with client:
        # Write 5 entries across 3 pages
        for i in range(1, 6):
            client.write_entry(
                issuer=f"Service_{i}",
                account=f"user_{i}@example.com",
                secret="JBSWY3DPEHPK3PXP",
                digits=6,
                period=30,
            )

        # Enumerate all: client should fetch page 1 (2), page 2 (2), page 3 (1)
        profiles = client.list_entries()
        assert len(profiles) == 5
        assert [p.slot for p in profiles] == [1, 2, 3, 4, 5]
        assert [p.issuer for p in profiles] == [
            "Service_1",
            "Service_2",
            "Service_3",
            "Service_4",
            "Service_5",
        ]


def test_direct_client_error_conditions():
    """Tests error handling for memory full, button timeout, and invalid secrets."""
    mock = MockHIDTransport(max_entries=2)
    client = Token2DirectClient(transport=mock)

    with client:
        # 1. Fill mock storage
        client.write_entry("App1", "User1", "JBSWY3DPEHPK3PXP")
        client.write_entry("App2", "User2", "JBSWY3DPEHPK3PXP")

        # 2. Exceeding capacity triggers Token2MemoryFullError (0x6A84)
        with pytest.raises(Token2MemoryFullError, match="memory is full"):
            client.write_entry("App3", "User3", "JBSWY3DPEHPK3PXP")

        # 3. Simulate button press timeout (0x6FF9)
        mock.force_status_word = SW_BUTTON_TIMEOUT
        with pytest.raises(Token2ButtonTimeoutError, match="confirmation timed out"):
            client.write_entry("App4", "User4", "JBSWY3DPEHPK3PXP")
        mock.force_status_word = None

        # 4. Invalid base32 secret raises ValueError
        with pytest.raises(ValueError, match="Invalid Base32 secret"):
            client.write_entry("App5", "User5", "NotABase32Secret!@#$%^")


# ============================================================================
# 5. Token2Adapter Unified Facade Tests
# ============================================================================

def test_unified_adapter_with_direct_backend():
    """Tests Token2Adapter using direct USB-HID mock backend with slot translation."""
    mock = MockHIDTransport()
    adapter = Token2Adapter(backend="direct", transport=mock)

    with adapter:
        # 1. Write TOTPEntry via slot interface
        entry1 = TOTPEntry(
            issuer="GitHub",
            account="octocat",
            secret="JBSWY3DPEHPK3PXP",
            algorithm="SHA1",
            digits=6,
            period=30,
        )
        adapter.write_entry(slot=1, entry=entry1)

        entry2 = TOTPEntry(
            issuer="AWS",
            account="root",
            secret="MZXW6YTBOI======",
            algorithm="SHA256",
            digits=8,
            period=60,
        )
        adapter.write_entry(slot=2, entry=entry2)

        # 2. Get all profiles
        profiles = adapter.get_all()
        assert len(profiles) == 2
        assert profiles[0].slot == 1
        assert profiles[0].issuer == "GitHub"
        assert profiles[1].slot == 2
        assert profiles[1].issuer == "AWS"

        # 3. Delete entry by slot
        adapter.delete_entry(slot=1)
        remaining = adapter.get_all()
        assert len(remaining) == 1
        assert remaining[0].issuer == "AWS"


def test_unified_adapter_pin_memory_scrubbing():
    """Tests that sensitive PIN memory buffer is properly scrubbed upon adapter closure."""
    pin_raw = b"Secret123456"
    adapter = Token2Adapter(backend="direct", pin=pin_raw, transport=MockHIDTransport())

    assert adapter._pin_buf is not None
    assert bytes(adapter._pin_buf) == pin_raw

    adapter.close()
    assert adapter._pin_buf is None


def test_hid_transport_device_not_found():
    """Tests that HIDTransport raises Token2DeviceNotFoundError when device not found."""
    from unittest.mock import patch

    from t2_kpxc_sync.token2 import HIDTransport, Token2DeviceNotFoundError

    with patch("hid.enumerate", return_value=[]):
        transport = HIDTransport(vendor_id=0x1234, product_id=0x5678)
        with pytest.raises(Token2DeviceNotFoundError, match="No Token2 device found"):
            transport.open()


def test_hid_transport_mocked_calls():
    """Tests HIDTransport.send_feature_report and get_feature_report against hid device mock."""
    from unittest.mock import MagicMock, patch

    from t2_kpxc_sync.token2 import HIDTransport

    mock_dev = MagicMock()
    mock_dev.send_feature_report.return_value = 65
    mock_dev.get_feature_report.return_value = [0x00, 0x21, 0x00, 0x02, 0x90, 0x00] + [0] * 59

    with (
        patch("hid.enumerate", return_value=[{"vendor_id": 0x349E, "product_id": 0x0022, "path": b"/dev/hidraw1"}]),
        patch("hid.device", return_value=mock_dev),
    ):
        transport = HIDTransport()
        transport.open()
        assert transport._dev is not None

        # Test send
        report = bytes([0x00, 0x21, 0x00, 0x00]) + bytes(61)
        transport.send_feature_report(report)
        mock_dev.send_feature_report.assert_called_once_with(list(report))

        # Test get
        res = transport.get_feature_report(0x00, 65)
        assert len(res) == 65
        assert res[1] == 0x21

        transport.close()
        mock_dev.close.assert_called_once()
        assert transport._dev is None


def test_adapter_auto_mode_fallback():
    """Tests that Token2Adapter(backend='auto') falls back to CLI when USB device is not found."""
    from unittest.mock import patch

    from t2_kpxc_sync.token2 import Token2Adapter

    with patch("hid.enumerate", return_value=[]):
        adapter = Token2Adapter(backend="auto", cli_binary="token2-otp-cli")
        adapter.open()
        assert adapter._cli_adapter is not None
        assert adapter._direct_client is None
        adapter.close()


def test_protocol_status_word_edge_cases():
    """Tests APDU parsing on short or malformed responses."""
    with pytest.raises(Token2ProtocolError, match="Response too short"):
        parse_status_word(b"\x90")

    data, sw = parse_status_word(b"\x01\x02\x03\x90\x00")
    assert data == b"\x01\x02\x03"
    assert sw == 0x9000

    entries, has_more = parse_enum_response(b"")
    assert entries == []
    assert has_more is False


def test_mock_transport_unsupported_apdu():
    """Tests that MockHIDTransport responds with 0x6D00 for unknown APDU."""
    mock = MockHIDTransport()
    mock.open()
    resp = mock.send_apdu(bytes.fromhex("80FF0000"))
    _, sw = parse_status_word(resp)
    assert sw == 0x6D00
    mock.close()

