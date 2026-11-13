"""Tests for the diff engine and TOTP verification."""

import pytest
from t2_kpxc_sync.diff import calculate_totp, compute_diff
from t2_kpxc_sync.models import TOTPEntry, Token2Profile


def test_calculate_totp_rfc_test_vectors():
    # RFC 6238 test secret (12345678901234567890 in base32 -> GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ)
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    # Unix timestamp 59: counter = 1 -> RFC 6238 code 287082
    code = calculate_totp(secret, timestamp=59, digits=6, period=30, algorithm="SHA1")
    assert code == "287082"


def test_diff_categories():
    t0 = 1000000
    secret1 = "JBSWY3DPEHPK3PXP"
    secret2 = "GEZDGNBVGY3TQOJQ"

    otp1 = calculate_totp(secret1, t0)
    wrong_otp = "000000"

    kpxc = [
        TOTPEntry(issuer="GitHub", account="alice", secret=secret1),
        TOTPEntry(issuer="Google", account="alice", secret=secret2),
        TOTPEntry(issuer="AWS", account="root", secret="JBSWY3DPEHPK3PXP", algorithm="SHA512"),  # incompatible
    ]

    tokens = [
        # Up to date
        Token2Profile(slot=1, issuer="GitHub", account="alice", current_otp=otp1),
        # Rotated key (wrong OTP)
        Token2Profile(slot=2, issuer="Google", account="alice", current_otp=wrong_otp),
        # Obsolete on token
        Token2Profile(slot=3, issuer="Legacy", account="old", current_otp="123456"),
    ]

    result = compute_diff(kpxc, tokens, current_time=t0)

    # AWS has SHA512 -> skipped
    assert len(result.skipped) == 1
    assert result.skipped[0].issuer == "AWS"

    # Google key rotated -> to_update
    assert len(result.to_update) == 1
    assert result.to_update[0][0].issuer == "Google"

    # Legacy is missing in KeePassXC -> to_delete
    assert len(result.to_delete) == 1
    assert result.to_delete[0].issuer == "Legacy"


def test_capacity_limit_300():
    kpxc = [
        TOTPEntry(issuer=f"Site{i}", account="user", secret="JBSWY3DPEHPK3PXP")
        for i in range(301)
    ]
    tokens = []
    result = compute_diff(kpxc, tokens)
    assert result.final_slot_count == 301
    assert result.is_capacity_exceeded is True


def test_totp_code_verification():
    t_fixed = 1700000000
    secret_kpxc = "JBSWY3DPEHPK3PXP"
    current_code = calculate_totp(secret_kpxc, timestamp=t_fixed)

    # When token returns matching code, no update needed
    kpxc = [TOTPEntry(issuer="Service", account="user1", secret=secret_kpxc)]
    token_matching = [Token2Profile(slot=1, issuer="Service", account="user1", current_otp=current_code)]
    res1 = compute_diff(kpxc, token_matching, current_time=t_fixed)
    assert len(res1.to_update) == 0
    assert len(res1.to_add) == 0

    # When secret on KeePassXC was rotated, OTP codes differ -> detected as to_update
    token_rotated = [Token2Profile(slot=1, issuer="Service", account="user1", current_otp="999888")]
    res2 = compute_diff(kpxc, token_rotated, current_time=t_fixed)
    assert len(res2.to_update) == 1
    assert res2.to_update[0][0].issuer == "Service"
    assert res2.to_update[0][1].slot == 1


def test_duplicate_entries_detection():
    kpxc = [
        TOTPEntry(issuer="GitHub", account="alice", secret="JBSWY3DPEHPK3PXP"),
        TOTPEntry(issuer="github", account="Alice ", secret="JBSWY3DPEHPK3PXP"),
    ]
    result = compute_diff(kpxc, [])
    assert len(result.duplicates) == 1
    assert result.duplicates[0] == ("github", "alice")
