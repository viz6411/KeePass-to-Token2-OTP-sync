"""Tier 4: Real-World Application Scenarios.

Tests complete, end-to-end user journeys:
1. Fresh provisioning from clean state to full synchronization.
2. Quarterly corporate credential rotation & differential synchronization.
3. Idempotent re-sync verification (zero operations when synchronized).
4. Migrated legacy vault reconciliation (KeePass 2.x + KeePassXC + Recycle Bin).
5. Standalone CLI binary smoke invocation in detached subprocess.
6. Multilingual enterprise synchronization across global service accounts.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pyotp
import pytest

from t2_kpxc_sync.cli import apply_sync, main
from t2_kpxc_sync.diff import compute_diff
from t2_kpxc_sync.kpxc import read_kdbx_direct
from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.token2 import Token2Adapter, Token2DirectClient
from tests.e2e.conftest import SimulatedToken2HIDDevice
from tests.e2e.fixtures.kdbx_factory import KDBXFactory
from tests.e2e.harness import run_cli_subprocess, run_interactive_session, strip_ansi


def test_t4_scenario_fresh_onboarding_to_full_sync(
    tmp_path: Path,
    mock_token2_hid: SimulatedToken2HIDDevice,
):
    """User Journey: Fresh key provisioning of 10 accounts from KeePass vault."""
    vault = tmp_path / "fresh_vault.kdbx"
    kp = KDBXFactory.create_vault(vault, password="MasterPassword123!")

    accounts = [
        ("GitHub", "dev1", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30),
        ("AWS", "admin", "GEZDGNBVGY3TQOJQ", "SHA256", 8, 60),
        ("GitLab", "secops", "MFRGGZDFMZTWQ2LK", "SHA1", 6, 30),
        ("Google", "user@gmail.com", "KVKFKRCPNZQUYMLX", "SHA1", 6, 30),
        ("Cloudflare", "infra", "OVYGYZDFMFRGGZDF", "SHA1", 6, 30),
        ("DigitalOcean", "deploy", "JBSWY3DPEHPK3PXP", "SHA1", 6, 30),
        ("Atlassian", "pm", "GEZDGNBVGY3TQOJQ", "SHA256", 6, 30),
        ("Slack", "worker", "MFRGGZDFMZTWQ2LK", "SHA1", 6, 30),
        ("Bitbucket", "repo", "KVKFKRCPNZQUYMLX", "SHA1", 6, 30),
        ("Salesforce", "sales", "OVYGYZDFMFRGGZDF", "SHA1", 6, 30),
    ]

    for title, user, secret, algo, digits, period in accounts:
        KDBXFactory.add_otpauth_entry(
            kp,
            title=title,
            username=user,
            secret=secret,
            algorithm=algo,
            digits=digits,
            period=period,
            save=False,
        )
    kp.save()

    # Step 1: User runs non-interactive batch sync
    with run_interactive_session(["MasterPassword123!", ""]) as (si, so, se):
        exit_code = main(["--db", str(vault), "--mode", "add_only", "-y"])
        assert exit_code == 0
        out = strip_ansi(so.getvalue())
        assert "Successfully performed 10 operations" in out

    # Step 2: Verify all 10 accounts exist on Token2 with valid live TOTPs
    with Token2Adapter(backend="direct") as adapter:
        profiles = adapter.get_all()
        assert len(profiles) == 10

        for title, user, secret, algo, digits, period in accounts:
            p = next(x for x in profiles if x.issuer == title and x.account == user)
            assert p.digits == digits
            assert p.period == period

            # Calculate mathematical TOTP with PyOTP and verify live code matches
            digest = hashlib.sha256 if algo == "SHA256" else hashlib.sha1
            expected_otp = pyotp.TOTP(secret, digits=digits, interval=period, digest=digest).now()
            assert p.current_otp == expected_otp


def test_t4_scenario_quarterly_secret_rotation(
    tmp_path: Path,
    mock_token2_hid: SimulatedToken2HIDDevice,
):
    """User Journey: Quarterly rotation where 2 secrets change, 1 is deleted, 1 is added."""
    # Step 1: Pre-populate token with 4 initial accounts
    with Token2Adapter(backend="direct") as adapter:
        adapter.write_entry(1, TOTPEntry(issuer="ServiceA", account="u1", secret="JBSWY3DPEHPK3PXP"))  # Keep
        adapter.write_entry(2, TOTPEntry(issuer="ServiceB", account="u2", secret="JBSWY3DPEHPK3PXP"))  # Rotate
        adapter.write_entry(3, TOTPEntry(issuer="ServiceC", account="u3", secret="JBSWY3DPEHPK3PXP"))  # Rotate
        adapter.write_entry(4, TOTPEntry(issuer="ObsoleteService", account="u4", secret="JBSWY3DPEHPK3PXP"))  # Delete

    # Step 2: Create vault reflecting new state:
    # ServiceA (unchanged), ServiceB (new secret), ServiceC (new secret), NewService (added)
    vault = tmp_path / "rotation.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")
    KDBXFactory.add_otpauth_entry(kp, title="ServiceA", username="u1", secret="JBSWY3DPEHPK3PXP", save=False)
    KDBXFactory.add_otpauth_entry(kp, title="ServiceB", username="u2", secret="GEZDGNBVGY3TQOJQ", save=False)
    KDBXFactory.add_otpauth_entry(kp, title="ServiceC", username="u3", secret="MFRGGZDFMZTWQ2LK", save=False)
    KDBXFactory.add_otpauth_entry(kp, title="NewService", username="u5", secret="KVKFKRCPNZQUYMLX", save=False)
    kp.save()

    # Step 3: Run full synchronization
    with run_interactive_session(["pwd", ""]) as (si, so, se):
        exit_code = main(["--db", str(vault), "--mode", "full_sync", "-y"])
        assert exit_code == 0
        out = strip_ansi(so.getvalue())
        assert "Successfully performed 4 operations" in out

    # Step 4: Verify end state
    with Token2Adapter(backend="direct") as adapter:
        profiles = adapter.get_all()
        assert len(profiles) == 4
        issuers = {p.issuer for p in profiles}
        assert issuers == {"ServiceA", "ServiceB", "ServiceC", "NewService"}
        assert "ObsoleteService" not in issuers


def test_t4_scenario_idempotent_re_sync(
    tmp_path: Path,
    mock_token2_hid: SimulatedToken2HIDDevice,
):
    """User Journey: Re-running sync immediately when token is already in sync."""
    vault = tmp_path / "idempotent.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")
    KDBXFactory.add_otpauth_entry(kp, title="SyncSvc1", username="u1", secret="JBSWY3DPEHPK3PXP", save=False)
    KDBXFactory.add_otpauth_entry(kp, title="SyncSvc2", username="u2", secret="GEZDGNBVGY3TQOJQ", save=False)
    kp.save()

    # Run 1: Initial sync
    with run_interactive_session(["pwd", ""]) as (si, so, se):
        exit1 = main(["--db", str(vault), "--mode", "add_only", "-y"])
        assert exit1 == 0

    # Run 2: Immediate re-sync
    with run_interactive_session(["pwd", ""]) as (si, so, se):
        exit2 = main(["--db", str(vault), "--mode", "full_sync", "-y"])
        assert exit2 == 0
        out = strip_ansi(so.getvalue())
        assert "Token2 is already up to date with KeePassXC. Nothing to do." in out


def test_t4_scenario_migrated_legacy_vault(
    tmp_path: Path,
    mock_token2_hid: SimulatedToken2HIDDevice,
):
    """User Journey: Database with legacy KeePass 2.x and modern KeePassXC entries."""
    vault = tmp_path / "legacy_migration.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")

    # 1. Modern KeePassXC entry (otpauth://)
    KDBXFactory.add_otpauth_entry(kp, title="ModernXC", username="user1", secret="JBSWY3DPEHPK3PXP", save=False)

    # 2. Legacy KeePass 2.x entry (TimeOtp-*)
    KDBXFactory.add_timeotp_entry(kp, title="LegacyTray", username="user2", secret="GEZDGNBVGY3TQOJQ", save=False)

    # 3. Deleted entry in Recycle Bin
    g_bin = kp.add_group(kp.root_group, "Recycle Bin")
    KDBXFactory.add_otpauth_entry(kp, group=g_bin, title="DeletedService", username="user3", save=False)

    # 4. Standard non-OTP login
    KDBXFactory.add_standard_entry(kp, title="RegularLogin", username="user4", save=False)
    kp.save()

    # Sync to token
    with run_interactive_session(["pwd", ""]) as (si, so, se):
        exit_code = main(["--db", str(vault), "--mode", "add_only", "-y"])
        assert exit_code == 0

    with Token2Adapter(backend="direct") as adapter:
        profiles = adapter.get_all()
        assert len(profiles) == 2
        issuers = {p.issuer for p in profiles}
        assert issuers == {"ModernXC", "LegacyTray"}
        assert "DeletedService" not in issuers
        assert "RegularLogin" not in issuers


def test_t4_scenario_standalone_binary_smoke():
    """User Journey: Standalone CLI invocation in detached subprocess."""
    res_help = run_cli_subprocess(["--help"])
    assert res_help.exit_code == 0
    assert "t2-kpxc-sync" in res_help.clean_text

    # Without --db, exits 1 with error message
    res_nodb = run_cli_subprocess([])
    assert res_nodb.exit_code == 1
    assert "Error: No KeePassXC database specified" in res_nodb.clean_text


def test_t4_scenario_multilingual_enterprise_sync(
    tmp_path: Path,
    mock_token2_hid: SimulatedToken2HIDDevice,
):
    """User Journey: International accounts with Cyrillic, Chinese, and European characters."""
    vault = tmp_path / "global.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")

    KDBXFactory.add_otpauth_entry(kp, title="Яндекс 360", username="admin@ядекс.рф", secret="JBSWY3DPEHPK3PXP", save=False)
    KDBXFactory.add_otpauth_entry(kp, title="微信公众号", username="admin_cn", secret="GEZDGNBVGY3TQOJQ", save=False)
    KDBXFactory.add_otpauth_entry(kp, title="Société Générale", username="jean@banque.fr", secret="MFRGGZDFMZTWQ2LK", save=False)
    kp.save()

    with run_interactive_session(["pwd", ""]) as (si, so, se):
        exit_code = main(["--db", str(vault), "--mode", "add_only", "-y"])
        assert exit_code == 0

    with Token2Adapter(backend="direct") as adapter:
        profiles = adapter.get_all()
        assert len(profiles) == 3
        issuers = {p.issuer for p in profiles}
        assert "Яндекс 360" in issuers
        assert "微信公众号" in issuers
        assert "Société Générale" in issuers
