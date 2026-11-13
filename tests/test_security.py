"""Tests for memory security and buffer scrubbing."""

from t2_kpxc_sync.security import SecureBuffer, scrub_bytes


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
