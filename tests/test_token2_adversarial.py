"""Empirical adversarial test suite for Milestone 2 Token2 USB-HID driver.

Stress-tests:
1. Transport framing & MockHIDTransport chaos:
   - Truncated feature reports, corrupted magic, invalid report IDs
   - Packet length exceeding 61 bytes, payload overflow
   - Unexpected frame flags, missing end chunks, timeout on infinite 0xC0
   - Packets shorter than 4 bytes, status word edge cases
2. Cryptographic engine stress:
   - Public keys not on SECP256R1, corrupted coordinates, invalid byte lengths
   - Coordinates exceeding prime field p
   - Truncated ciphertexts, non-16-byte block sizes
   - Corrupted IVs, malformed PKCS#7 padding
3. High-level client & adapter chaos:
   - Duplicate entries & in-place update semantics
   - 64-byte boundary vs 65+ byte rejection for issuer and account
   - Unicode UTF-8 handling (Cyrillic, Japanese, German, emojis)
   - Multi-byte length calculation (33 Cyrillic chars = 66 bytes > 64)
   - Empty secrets and Base32 padding tolerance
   - 300 slot capacity boundary and overflow handling
   - Safe deletion of non-existent slots and empty erase
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from t2_kpxc_sync.models import TOTPEntry
from t2_kpxc_sync.token2 import (
    IV_1,
    BaseTransport,
    MockHIDTransport,
    Token2Adapter,
    Token2DirectClient,
    Token2MemoryFullError,
    Token2ProtocolError,
    Token2TimeoutError,
    build_write_seed_apdu,
    decrypt_payload_ecdh,
    encrypt_payload_ecdh,
    generate_ecdh_keypair,
    parse_enum_response,
    parse_status_word,
    public_key_from_raw_bytes,
)
from t2_kpxc_sync.token2.transport import (
    FEATURE_REPORT_ID,
    FEATURE_REPORT_MAGIC,
    FLAG_LAST_FRAME,
    FLAG_POLLING_IN_PROGRESS,
)

# ============================================================================
# Category 1: Transport Framing & Protocol Chaos
# ============================================================================

class ChaoticFeatureReportTransport(BaseTransport):
    """Custom mock transport injecting arbitrary raw feature reports for testing send_apdu."""

    def __init__(self, canned_reports: list[bytes]) -> None:
        super().__init__()
        self.canned_reports = list(canned_reports)
        self.sent_reports: list[bytes] = []

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def send_feature_report(self, report: bytes) -> None:
        self.sent_reports.append(bytes(report))

    def get_feature_report(self, report_id: int, length: int) -> bytes:
        if not self.canned_reports:
            # Default empty frame
            flags_seq = (FLAG_LAST_FRAME & 0xF0) | 0
            return bytes([FEATURE_REPORT_ID, FEATURE_REPORT_MAGIC, flags_seq, 0]) + bytes(61)
        return self.canned_reports.pop(0)


def test_framing_truncated_feature_reports():
    """Empirically verifies that reports shorter than 3 bytes are rejected with Token2ProtocolError."""
    # 0 bytes
    t0 = ChaoticFeatureReportTransport([b""])
    with pytest.raises(Token2ProtocolError, match="Feature report response too short"):
        t0.send_apdu(b"\x80\x33\x00\x00")

    # 1 byte
    t1 = ChaoticFeatureReportTransport([b"\x21"])
    with pytest.raises(Token2ProtocolError, match="Feature report response too short"):
        t1.send_apdu(b"\x80\x33\x00\x00")

    # 2 bytes
    t2 = ChaoticFeatureReportTransport([b"\x21\x00"])
    with pytest.raises(Token2ProtocolError, match="Feature report response too short"):
        t2.send_apdu(b"\x80\x33\x00\x00")


def test_framing_corrupted_magic_bytes():
    """Empirically verifies that unexpected magic bytes are rejected."""
    bad_magics = [0x00, 0x11, 0x33, 0xFF]
    for bm in bad_magics:
        report = bytes([FEATURE_REPORT_ID, bm, 0x00, 0x02, 0x90, 0x00]) + bytes(59)
        t = ChaoticFeatureReportTransport([report])
        with pytest.raises(Token2ProtocolError, match="Invalid feature report magic"):
            t.send_apdu(b"\x80\x33\x00\x00")


def test_framing_claimed_chunk_len_overflow():
    """Empirically verifies that chunk_len exceeding actual report size is rejected."""
    # Sliced report is 64 bytes (after removing Report ID 0x00).
    # Header is 3 bytes (magic, flags_seq, chunk_len), so max valid chunk is 61 bytes.
    # Claim chunk_len = 62 -> 3 + 62 = 65 > 64 -> payload overflow!
    report_62 = bytes([FEATURE_REPORT_ID, FEATURE_REPORT_MAGIC, 0x00, 62]) + bytes(61)
    t = ChaoticFeatureReportTransport([report_62])
    with pytest.raises(Token2ProtocolError, match="Report payload overflow"):
        t.send_apdu(b"\x80\x33\x00\x00")

    # Claim chunk_len = 255
    report_255 = bytes([FEATURE_REPORT_ID, FEATURE_REPORT_MAGIC, 0x00, 255]) + bytes(61)
    t2 = ChaoticFeatureReportTransport([report_255])
    with pytest.raises(Token2ProtocolError, match="Report payload overflow"):
        t2.send_apdu(b"\x80\x33\x00\x00")


def test_framing_unexpected_frame_flags():
    """Empirically verifies that unassigned frame flags are rejected."""
    # Valid flags are 0x00 (LAST), 0x20 (MORE), 0xC0 (POLLING).
    # Test flags 0x10, 0x40, 0x80
    for bad_flag in [0x10, 0x40, 0x80]:
        report = bytes([FEATURE_REPORT_ID, FEATURE_REPORT_MAGIC, bad_flag, 0x02, 0x90, 0x00]) + bytes(59)
        t = ChaoticFeatureReportTransport([report])
        with pytest.raises(Token2ProtocolError, match="Unexpected frame flag"):
            t.send_apdu(b"\x80\x33\x00\x00")


def test_framing_infinite_polling_timeout():
    """Empirically verifies that continuous 0xC0 polling aborts with Token2TimeoutError."""
    # Transport that continuously emits 0xC0 (POLLING_IN_PROGRESS)
    poll_report = bytes([FEATURE_REPORT_ID, FEATURE_REPORT_MAGIC, FLAG_POLLING_IN_PROGRESS, 0]) + bytes(61)
    t = ChaoticFeatureReportTransport([poll_report] * 100)

    with pytest.raises(Token2TimeoutError, match="Timed out after"):
        t.send_apdu(b"\x80\x33\x00\x00", timeout=0.1)


def test_mock_transport_invalid_report_id_and_length():
    """Empirically verifies MockHIDTransport.send_feature_report error handling on malformed reports."""
    mock = MockHIDTransport()
    mock.open()

    # Must be exactly 65 bytes
    with pytest.raises(Token2ProtocolError, match="Mock report size must be 65 bytes"):
        mock.send_feature_report(bytes(64))

    with pytest.raises(Token2ProtocolError, match="Mock report size must be 65 bytes"):
        mock.send_feature_report(bytes(66))

    # Must have Report ID 0x00
    with pytest.raises(Token2ProtocolError, match="Invalid report ID"):
        mock.send_feature_report(b"\x01" + bytes(64))

    # Must have magic 0x21
    with pytest.raises(Token2ProtocolError, match="Invalid magic"):
        mock.send_feature_report(b"\x00\x99" + bytes(63))

    mock.close()


def test_mock_transport_unsupported_short_apdu():
    """Empirically verifies handling of APDUs shorter than 4 bytes."""
    mock = MockHIDTransport()
    mock.open()

    # Send 1-byte APDU
    resp = mock.send_apdu(b"\x80")
    data, sw = parse_status_word(resp)
    assert sw == 0x6700  # Wrong length
    assert data == b""

    # Send 3-byte APDU
    resp3 = mock.send_apdu(b"\x80\x01\x02")
    _, sw3 = parse_status_word(resp3)
    assert sw3 == 0x6700

    mock.close()


def test_protocol_parse_enum_response_truncated_streams():
    """Empirically verifies that stream deserialization of truncated data halts gracefully without crashing."""
    # Truncated right after first byte
    entries, has_more = parse_enum_response(b"\x80")
    assert entries == []
    assert has_more is True

    # Truncated in the middle of timestep (1 byte of timestep instead of 2)
    truncated_stream = bytes([0x01, 0xC1, 0x00])  # type, algo, only 1B of timestep
    entries, has_more = parse_enum_response(truncated_stream)
    assert entries == []
    assert has_more is False

    # Truncated in the middle of app_name
    stream_trunc_app = bytes([0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x0A]) + b"Short"  # claimed len 10, only 5 provided
    entries, has_more = parse_enum_response(stream_trunc_app)
    assert entries == []

    # Truncated in the middle of account_name
    stream_trunc_acct = (
        bytes([0x01, 0xC1, 0x00, 0x1E, 0x06, 0x00, 0x03])
        + b"App"
        + bytes([0x0A])
        + b"Acct"  # claimed len 10, only 4 provided
    )
    entries, has_more = parse_enum_response(stream_trunc_acct)
    assert entries == []


# ============================================================================
# Category 2: Cryptographic Engine Stress
# ============================================================================

def test_crypto_invalid_public_key_points_not_on_curve():
    """Empirically verifies that points not on SECP256R1 curve raise ValueError."""
    # Point (1, 1): Not on SECP256R1
    invalid_point_1 = (1).to_bytes(32, "big") + (1).to_bytes(32, "big")
    with pytest.raises(ValueError):
        public_key_from_raw_bytes(invalid_point_1)

    # Point all 0x00 (point at infinity representation is rejected)
    zero_point = bytes(64)
    with pytest.raises(ValueError):
        public_key_from_raw_bytes(zero_point)

    # Point all 0xFF
    ff_point = bytes([0xFF] * 64)
    with pytest.raises(ValueError):
        public_key_from_raw_bytes(ff_point)


def test_crypto_coordinates_exceeding_p256_prime_field():
    """Empirically verifies that coordinates >= p raise ValueError."""
    # P-256 prime field modulus p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    p256_p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    x_too_large = (p256_p + 1).to_bytes(32, "big")
    y_coord = (1).to_bytes(32, "big")

    with pytest.raises(ValueError):
        public_key_from_raw_bytes(x_too_large + y_coord)


def test_crypto_public_key_length_variations():
    """Empirically verifies that raw public keys not exactly 64 bytes raise ValueError."""
    for bad_len in [0, 1, 32, 63, 65, 128]:
        with pytest.raises(ValueError, match="Expected 64 bytes"):
            public_key_from_raw_bytes(bytes(bad_len))


def test_crypto_truncated_and_non_block_ciphertexts():
    """Empirically verifies decryption rejection on truncated or non-block-aligned ciphertexts."""
    token_priv, token_pub_raw = generate_ecdh_keypair()
    valid_enc = encrypt_payload_ecdh(token_pub_raw, b"HelloWorld123456")

    # 1. Truncated block (< 80 bytes)
    for length in [0, 64, 79]:
        with pytest.raises(ValueError, match="Encrypted block too short"):
            decrypt_payload_ecdh(token_priv, valid_enc[:length])

    # 2. Ciphertext length not a multiple of 16 bytes (AES block size)
    # Valid is 64 + 32 = 96 bytes. Slicing to 85 bytes leaves 21 bytes of ciphertext (not multiple of 16).
    with pytest.raises(ValueError):
        decrypt_payload_ecdh(token_priv, valid_enc[:85])


def test_crypto_corrupted_iv_handling():
    """Empirically verifies behavior when IV is corrupted or wrong length."""
    token_priv, token_pub_raw = generate_ecdh_keypair()
    valid_enc = encrypt_payload_ecdh(token_pub_raw, b"ValidPayloadSecretData")

    # IV too short (8 bytes instead of 16)
    with pytest.raises(ValueError):
        decrypt_payload_ecdh(token_priv, valid_enc, iv=bytes(8))

    # IV too long (32 bytes instead of 16)
    with pytest.raises(ValueError):
        decrypt_payload_ecdh(token_priv, valid_enc, iv=bytes(32))

    # Single-block payload with wrong IV: block 1 is the padding block, so wrong IV scrambles padding
    single_block_enc = encrypt_payload_ecdh(token_pub_raw, b"1234567890")
    wrong_iv = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    with pytest.raises(ValueError, match="Invalid padding bytes"):
        decrypt_payload_ecdh(token_priv, single_block_enc, iv=wrong_iv)

    # Multi-block payload with wrong IV: block 1 is scrambled while block 2 padding remains intact
    multi_dec = decrypt_payload_ecdh(token_priv, valid_enc, iv=wrong_iv)
    assert multi_dec[:16] != b"ValidPayloadSecr"
    assert multi_dec[16:] == b"etData"


def test_crypto_malformed_pkcs7_padding():
    """Empirically verifies that ciphertexts with invalid PKCS#7 padding fail cleanly."""
    token_priv, token_pub_raw = generate_ecdh_keypair()

    # Manually encrypt a block with bad padding using valid ECDH session key
    host_priv, host_pub_raw = generate_ecdh_keypair()
    from t2_kpxc_sync.token2.crypto import derive_session_key

    session_key = derive_session_key(host_priv, public_key_from_raw_bytes(token_pub_raw))

    # 1. Padding byte 0x00 (illegal in PKCS#7)
    bad_padded_1 = b"123456789012345\x00"
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(IV_1))
    enc = cipher.encryptor()
    ct_bad_1 = host_pub_raw + enc.update(bad_padded_1) + enc.finalize()
    with pytest.raises(ValueError):
        decrypt_payload_ecdh(token_priv, ct_bad_1)

    # 2. Padding byte 0x11 (17 > 16)
    bad_padded_2 = b"123456789012345\x11"
    enc = cipher.encryptor()
    ct_bad_2 = host_pub_raw + enc.update(bad_padded_2) + enc.finalize()
    with pytest.raises(ValueError):
        decrypt_payload_ecdh(token_priv, ct_bad_2)

    # 3. Inconsistent pad bytes (e.g. \x01\x02)
    bad_padded_3 = b"12345678901234\x01\x02"
    enc = cipher.encryptor()
    ct_bad_3 = host_pub_raw + enc.update(bad_padded_3) + enc.finalize()
    with pytest.raises(ValueError):
        decrypt_payload_ecdh(token_priv, ct_bad_3)


# ============================================================================
# Category 3: Client & Adapter Chaos (Limits, Boundaries, Unicode, Overflows)
# ============================================================================

def test_client_duplicate_account_overwrite():
    """Empirically verifies that writing the same (issuer, account) updates in-place without duplicating."""
    mock = MockHIDTransport()
    client = Token2DirectClient(transport=mock)

    with client:
        # Write initial entry
        client.write_entry(
            issuer="GitHub",
            account="octocat",
            secret="JBSWY3DPEHPK3PXP",
            algorithm="SHA1",
            digits=6,
            period=30,
        )
        profiles = client.list_entries()
        assert len(profiles) == 1
        assert profiles[0].algorithm == "SHA1"

        # Overwrite with different parameters
        client.write_entry(
            issuer="GitHub",
            account="octocat",
            secret="MZXW6YTBOI======",
            algorithm="SHA256",
            digits=8,
            period=60,
        )
        profiles = client.list_entries()
        assert len(profiles) == 1
        assert profiles[0].algorithm == "SHA256"
        assert profiles[0].digits == 8
        assert profiles[0].period == 60


def test_client_name_size_boundaries():
    """Empirically verifies exact 64-byte boundary and rejection at 65+ bytes for names."""
    mock = MockHIDTransport()
    client = Token2DirectClient(transport=mock)

    with client:
        # Exactly 64 ASCII bytes for issuer and account
        name_64 = "A" * 64
        client.write_entry(
            issuer=name_64,
            account=name_64,
            secret="JBSWY3DPEHPK3PXP",
        )
        profiles = client.list_entries()
        assert len(profiles) == 1
        assert profiles[0].issuer == name_64
        assert profiles[0].account == name_64

        # 65 bytes for issuer -> rejected
        with pytest.raises(ValueError, match="Issuer/app name too long"):
            client.write_entry(
                issuer="A" * 65,
                account="user",
                secret="JBSWY3DPEHPK3PXP",
            )

        # 65 bytes for account -> rejected
        with pytest.raises(ValueError, match="Account name too long"):
            client.write_entry(
                issuer="app",
                account="B" * 65,
                secret="JBSWY3DPEHPK3PXP",
            )


def test_client_unicode_multibyte_handling():
    """Empirically verifies Cyrillic, Japanese, German, and Emoji handling."""
    mock = MockHIDTransport()
    client = Token2DirectClient(transport=mock)

    with client:
        # 1. Russian / Cyrillic
        client.write_entry(
            issuer="Сбербанк",
            account="иван@почта.рф",
            secret="JBSWY3DPEHPK3PXP",
        )

        # 2. Japanese
        client.write_entry(
            issuer="楽天銀行",
            account="タナカ_タロウ",
            secret="JBSWY3DPEHPK3PXP",
        )

        # 3. German umlauts
        client.write_entry(
            issuer="Deutsche Bank Köln",
            account="müller@firma.de",
            secret="JBSWY3DPEHPK3PXP",
        )

        # 4. Emojis
        client.write_entry(
            issuer="🛡️ SecureVault 🔑",
            account="🚀 admin@space.io 🌌",
            secret="JBSWY3DPEHPK3PXP",
        )

        profiles = client.list_entries()
        assert len(profiles) == 4
        issuers = [p.issuer for p in profiles]
        accounts = [p.account for p in profiles]

        assert "Сбербанк" in issuers
        assert "иван@почта.рф" in accounts
        assert "楽天銀行" in issuers
        assert "タナカ_タロウ" in accounts
        assert "Deutsche Bank Köln" in issuers
        assert "🛡️ SecureVault 🔑" in issuers

        # 5. Multi-byte UTF-8 length checking:
        # 33 Cyrillic characters = 66 UTF-8 bytes (> 64 bytes).
        # Must raise ValueError based on byte length, not char length!
        cyrillic_33_chars = "А" * 33
        assert len(cyrillic_33_chars) == 33
        assert len(cyrillic_33_chars.encode("utf-8")) == 66

        with pytest.raises(ValueError, match="Issuer/app name too long"):
            client.write_entry(
                issuer=cyrillic_33_chars,
                account="test",
                secret="JBSWY3DPEHPK3PXP",
            )


def test_client_base32_secrets_variations():
    """Empirically verifies secret formatting (unpadded Base32, spaces, lowercase)."""
    mock = MockHIDTransport()
    client = Token2DirectClient(transport=mock)

    with client:
        # Unpadded base32
        client.write_entry("App1", "User1", "JBSWY3DPEHPK3PXP")

        # Lowercase base32
        client.write_entry("App2", "User2", "jbswy3dpehpk3pxp")

        # Secret with spaces
        client.write_entry("App3", "User3", "JBSW Y3DP EHPK 3PXP")

        profiles = client.list_entries()
        assert len(profiles) == 3

        # Invalid base32 characters raise ValueError
        with pytest.raises(ValueError, match="Invalid Base32 secret"):
            client.write_entry("AppBad", "UserBad", "189!InvalidBase32===")


def test_client_slot_capacity_up_to_300_entries():
    """Empirically verifies storage capacity limit of 300 entries and overflow rejection."""
    mock = MockHIDTransport(max_entries=300, page_size=50)
    client = Token2DirectClient(transport=mock)

    with client:
        # Provision 300 entries
        for i in range(1, 301):
            mock.entries[(f"App_{i}", f"User_{i}")] = {
                "type": "TOTP",
                "algorithm": "SHA1",
                "timestep": 30,
                "digits": 6,
                "btn_flag": 0,
                "app_name": f"App_{i}",
                "account_name": f"User_{i}",
                "seed": b"Secret1234567890",
            }

        profiles = client.list_entries()
        assert len(profiles) == 300
        assert profiles[0].slot == 1
        assert profiles[-1].slot == 300

        # Attempting to add 301st new entry must raise Token2MemoryFullError
        with pytest.raises(Token2MemoryFullError, match="memory is full"):
            client.write_entry("App_301", "User_301", "JBSWY3DPEHPK3PXP")

        # Updating an existing entry among the 300 must succeed!
        client.write_entry("App_1", "User_1", "MZXW6YTBOI======", digits=8)
        updated = client.list_entries()
        assert len(updated) == 300
        assert updated[0].digits == 8

        # Deleting 1 entry frees up a slot
        client.delete_entry("App_1", "User_1")
        assert len(client.list_entries()) == 299

        # Now adding a new entry succeeds
        client.write_entry("App_New", "User_New", "JBSWY3DPEHPK3PXP")
        assert len(client.list_entries()) == 300


def test_adapter_facade_non_existent_slot_delete():
    """Empirically verifies that deleting an unmapped slot in Token2Adapter is handled gracefully."""
    mock = MockHIDTransport()
    adapter = Token2Adapter(backend="direct", transport=mock)

    with adapter:
        # Delete slot 999 on empty token: must not crash
        adapter.delete_entry(slot=999)
        assert len(adapter.get_all()) == 0

        # Add slot 1
        entry = TOTPEntry(issuer="Test", account="User", secret="JBSWY3DPEHPK3PXP")
        adapter.write_entry(slot=1, entry=entry)
        assert len(adapter.get_all()) == 1

        # Delete unmapped slot 5: does not affect slot 1
        adapter.delete_entry(slot=5)
        assert len(adapter.get_all()) == 1

        # Delete slot 1: succeeds
        adapter.delete_entry(slot=1)
        assert len(adapter.get_all()) == 0


# ============================================================================
# Category 4: Empirical Bug Re-producers & Defect Verification
# ============================================================================

def test_bug_read_otp_returns_correct_account_code():
    """Demonstrates that read_otp returns wrong account OTP and returns OTP for non-existent accounts."""
    mock = MockHIDTransport()
    client = Token2DirectClient(transport=mock)
    with client:
        client.write_entry("AWS", "admin", "JBSWY3DPEHPK3PXP")
        client.write_entry("GitHub", "octocat", "MZXW6YTBOI======")

        profiles = client.list_entries()
        aws_otp = next(p.current_otp for p in profiles if p.issuer == "AWS")
        gh_otp = next(p.current_otp for p in profiles if p.issuer == "GitHub")
        assert aws_otp != gh_otp

        # Querying GitHub must return GitHub's OTP, not AWS's OTP
        read_gh = client.read_otp("GitHub", "octocat")
        assert read_gh == gh_otp

        # Querying non-existent entry must return None, not AWS's OTP
        assert client.read_otp("NoSuchApp", "NoSuchUser") is None


def test_bug_mock_write_seed_index_error_on_malformed_payload():
    """Demonstrates that malformed write plaintext causes unhandled IndexError instead of clean SW error."""
    mock = MockHIDTransport()
    mock.open()
    # Payload claiming app_len=10 but total plaintext is truncated
    bad_payload = bytes([1, 0xC1, 0, 30, 6, 0, 10]) + b"1234567890"
    enc = encrypt_payload_ecdh(mock.public_key_raw, bad_payload)
    apdu = build_write_seed_apdu(enc)

    # Must cleanly return SW_WRONG_DATA (0x6A80) or SW_WRONG_LENGTH (0x6700), never crash with IndexError
    resp = mock.send_apdu(apdu)
    _, sw = parse_status_word(resp)
    assert sw in (0x6A80, 0x6700, 0x6982)
    mock.close()


def test_bug_mock_read_one_index_error_on_truncated_apdu():
    """Demonstrates that truncated READ_ONE APDU causes unhandled IndexError instead of clean SW error."""
    mock = MockHIDTransport()
    # READ_ONE APDU claiming app_len=50 but truncated at offset 17
    bad_apdu = bytes([0x80, 0xC5, 0x05, 0x00, 0x00, 0x00, 0x0A, 0x01]) + bytes(8) + bytes([50])
    resp = mock._handle_read_one(bad_apdu)
    _, sw = parse_status_word(resp)
    assert sw in (0x6700, 0x6A80)


def test_bug_write_entry_empty_secret_rejection():
    """Demonstrates that write_entry with empty secret silently deletes entry instead of raising ValueError."""
    mock = MockHIDTransport()
    client = Token2DirectClient(transport=mock)
    with client:
        client.write_entry("GitHub", "octocat", "JBSWY3DPEHPK3PXP")
        assert len(client.list_entries()) == 1

        # Writing with empty secret must raise ValueError, NOT silently delete the entry
        with pytest.raises(ValueError, match="[Ss]ecret"):
            client.write_entry("GitHub", "octocat", secret="")

        # Entry must still be present
        assert len(client.list_entries()) == 1


def test_bug_mock_send_feature_report_rejects_chunk_len_overflow():
    """Demonstrates that MockHIDTransport accepts reports with chunk_len > 61 without raising Token2ProtocolError."""
    mock = MockHIDTransport()
    mock.open()
    # Report claiming chunk_len = 100 in 65-byte report
    bad_report = bytes([FEATURE_REPORT_ID, FEATURE_REPORT_MAGIC, 0x00, 100]) + bytes(61)
    with pytest.raises(Token2ProtocolError, match="overflow|exceed"):
        mock.send_feature_report(bad_report)
    mock.close()

