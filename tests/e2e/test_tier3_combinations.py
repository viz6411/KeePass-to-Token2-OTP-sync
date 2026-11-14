"""Tier 3: Cross-Feature Combinations.

Tests interactions across subsystems:
- Multi-schema KDBX direct reading + Token2 cryptographic provisioning
- Direct KDBX + Dry-run simulation + Simulated Token2 NVRAM immutability
- Hybrid KeePassXC backend routing facade (auto/direct/cli with YubiKey)
- Secret normalization (spaces, lowercase, padding) + PyOTP code generation
- Capacity limit threshold guard across Diff Engine + Token2 hardware
- CLI argument overrides on config settings
"""

from __future__ import annotations

import base64
from pathlib import Path
from unittest.mock import MagicMock, patch

import pyotp
import pytest

from t2_kpxc_sync.cli import apply_sync, main
from t2_kpxc_sync.diff import TOKEN2_MAX_CAPACITY, compute_diff
from t2_kpxc_sync.kpxc import KeePassXCError, read_kdbx_direct, read_kpxc_entries
from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.token2 import Token2Adapter, Token2DirectClient, Token2Error
from tests.e2e.conftest import SimulatedToken2HIDDevice
from tests.e2e.fixtures.kdbx_factory import KDBXFactory
from tests.e2e.harness import run_cli_subprocess, run_interactive_session, strip_ansi


def test_t3_cross_multischema_kdbx_to_token2_sync(
    tmp_path: Path,
    mock_token2_hid: SimulatedToken2HIDDevice,
):
    """Verifies that both otpauth:// and TimeOtp-* entries are read and provisioned via ECDH."""
    vault = tmp_path / "multischema.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")

    # Entry 1: Standard otpauth:// URI
    KDBXFactory.add_otpauth_entry(
        kp,
        title="StandardService",
        username="alice",
        secret="JBSWY3DPEHPK3PXP",
        algorithm="SHA1",
        digits=6,
        period=30,
        save=False,
    )

    # Entry 2: Custom TimeOtp-* properties
    KDBXFactory.add_timeotp_entry(
        kp,
        title="CustomService",
        username="bob",
        secret="GEZDGNBVGY3TQOJQ",
        algorithm="HMAC-SHA-256",
        digits=8,
        period=60,
        save=False,
    )
    kp.save()

    # Read directly in RAM
    kpxc_entries = read_kdbx_direct(vault, password="pwd")
    assert len(kpxc_entries) == 2

    # Provision to simulated hardware token via direct adapter
    with Token2Adapter(backend="direct") as adapter:
        for idx, entry in enumerate(kpxc_entries, start=1):
            adapter.write_entry(idx, entry)

        # Inspect Token2 stored profiles
        profiles = adapter.get_all()
        assert len(profiles) == 2

        p_std = next(p for p in profiles if p.issuer == "StandardService")
        assert p_std.account == "alice"
        assert p_std.digits == 6
        assert p_std.period == 30

        p_cust = next(p for p in profiles if p.issuer == "CustomService")
        assert p_cust.account == "bob"
        assert p_cust.algorithm == "SHA256"
        assert p_cust.digits == 8
        assert p_cust.period == 60


def test_t3_cross_direct_kdbx_dry_run_simulation(
    tmp_path: Path,
    mock_token2_hid: SimulatedToken2HIDDevice,
):
    """Verifies direct KDBX + Dry-run execution displays diff table with zero NVRAM writes."""
    vault = tmp_path / "dryrun_sim.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")
    KDBXFactory.add_otpauth_entry(kp, title="AlphaService", username="u1", save=False)
    KDBXFactory.add_otpauth_entry(kp, title="BetaService", username="u2", save=False)
    kp.save()

    # Pre-populate token with AlphaService (matching) and GammaService (to delete)
    with Token2Adapter(backend="direct") as adapter:
        adapter.write_entry(1, TOTPEntry(issuer="AlphaService", account="u1", secret="JBSWY3DPEHPK3PXP"))
        adapter.write_entry(2, TOTPEntry(issuer="GammaService", account="u3", secret="MFRGGZDFMZTWQ2LK"))

    initial_keys = set(mock_token2_hid.entries.keys())
    assert len(initial_keys) == 2

    with run_interactive_session(["pwd", ""]) as (si, so, se):
        exit_code = main(["--db", str(vault), "--dry-run"])
        assert exit_code == 0
        out = strip_ansi(so.getvalue())
        assert "TOTP Synchronization Plan" in out
        assert "BetaService" in out
        assert "GammaService" in out
        assert "Dry-run requested: no changes written to Token2" in out

    # Device NVRAM must remain completely unchanged
    assert set(mock_token2_hid.entries.keys()) == initial_keys


def test_t3_cross_hybrid_routing_facade(tmp_path: Path):
    """Verifies read_kpxc_entries routing across auto, direct, and cli backends."""
    vault = tmp_path / "facade.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")
    KDBXFactory.add_otpauth_entry(kp, title="FacadeSvc")

    # 1. backend="direct": executes direct reader
    res_direct = read_kpxc_entries(vault, password="pwd", backend="direct")
    assert len(res_direct) == 1
    assert res_direct[0].issuer == "FacadeSvc"

    # 2. backend="direct" with yubikey_slot: raises KeePassXCError
    with pytest.raises(KeePassXCError, match="Direct pykeepass backend does not support YubiKey"):
        read_kpxc_entries(vault, password="pwd", yubikey_slot=1, backend="direct")

    # 3. backend="auto" without yubikey: routes to direct reader
    res_auto = read_kpxc_entries(vault, password="pwd", yubikey_slot=None, backend="auto")
    assert len(res_auto) == 1
    assert res_auto[0].issuer == "FacadeSvc"

    # 4. backend="auto" with yubikey: routes to CLI reader
    with patch("t2_kpxc_sync.kpxc.read_kpxc_entries_cli") as mock_cli:
        mock_cli.return_value = []
        read_kpxc_entries(vault, password="pwd", yubikey_slot=1, backend="auto")
        mock_cli.assert_called_once()

    # 5. backend="cli": routes to CLI reader
    with patch("t2_kpxc_sync.kpxc.read_kpxc_entries_cli") as mock_cli:
        mock_cli.return_value = []
        read_kpxc_entries(vault, password="pwd", backend="cli")
        mock_cli.assert_called_once()


def test_t3_cross_secret_normalization_and_pyotp_validation(tmp_path: Path):
    """Verifies secret normalization (spaces, lowercase, padding) matches PyOTP computation."""
    vault = tmp_path / "secrets.kdbx"
    kp = KDBXFactory.create_vault(vault, password="pwd")

    # Lowercase with spaces
    KDBXFactory.add_otpauth_entry(
        kp,
        title="MessyService",
        username="user",
        secret="jbsw y3dp ehpk 3pxp",
        save=False,
    )
    # Unpadded base32 secret
    KDBXFactory.add_timeotp_entry(
        kp,
        title="UnpaddedService",
        username="user2",
        secret="GEZDGNBVGY3TQOJQ",
        save=False,
    )
    kp.save()

    entries = read_kdbx_direct(vault, password="pwd")
    assert len(entries) == 2

    for entry in entries:
        # Verify valid Base32 secret by generating live TOTP with PyOTP
        totp = pyotp.TOTP(entry.secret, digits=entry.digits, interval=entry.period)
        code = totp.now()
        assert len(code) == entry.digits
        assert code.isdigit()


def test_t3_cross_capacity_threshold_boundary():
    """Verifies 305 entries against 300-slot token triggers diff guard and aborts."""
    kpxc_entries = [
        TOTPEntry(issuer=f"Corp_{i}", account=f"usr_{i}", secret="JBSWY3DPEHPK3PXP")
        for i in range(305)
    ]
    existing_token = [
        Token2Profile(slot=1, issuer="Existing", account="root")
    ]

    diff = compute_diff(kpxc_entries, existing_token)
    assert diff.is_capacity_exceeded is True
    assert diff.final_slot_count == 305

    mock_adapter = MagicMock()
    with pytest.raises(Token2Error, match="exceeds hardware limit 300"):
        apply_sync(mock_adapter, diff, existing_token, mode="add_only")
    mock_adapter.write_entry.assert_not_called()


def test_t3_cross_cli_override_config(
    tmp_path: Path,
    mock_token2_hid: SimulatedToken2HIDDevice,
):
    """Verifies that --db flag on CLI overrides database_path in config.toml."""
    vault_config = tmp_path / "vault_config.kdbx"
    kp1 = KDBXFactory.create_vault(vault_config, password="pwd1")
    KDBXFactory.add_otpauth_entry(kp1, title="ConfigVaultEntry")

    vault_override = tmp_path / "vault_override.kdbx"
    kp2 = KDBXFactory.create_vault(vault_override, password="pwd2")
    KDBXFactory.add_otpauth_entry(kp2, title="OverrideVaultEntry")

    conf_file = tmp_path / "config.toml"
    conf_file.write_text(f"""[keepassxc]
database_path = "{vault_config}"
""")

    with run_interactive_session(["pwd2", ""]) as (si, so, se):
        exit_code = main(["--config", str(conf_file), "--db", str(vault_override), "--dry-run"])
        assert exit_code == 0
        out = strip_ansi(so.getvalue())
        assert "OverrideVaultEntry" in out
        assert "ConfigVaultEntry" not in out
