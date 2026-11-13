"""Tests for CLI interaction and sync mode execution."""

from unittest.mock import MagicMock, patch
import pytest

from t2_kpxc_sync.cli import apply_sync, find_free_slots
from t2_kpxc_sync.diff import DiffResult
from t2_kpxc_sync.models import TOTPEntry, Token2Profile
from t2_kpxc_sync.token2 import Token2CLIAdapter, Token2Error


def test_find_free_slots():
    occupied = [1, 2, 5]
    free = find_free_slots(occupied, max_capacity=6)
    assert free == [3, 4, 6]


def test_sync_modes():
    # Setup test diff
    entry_add = TOTPEntry(issuer="NewService", account="user", secret="JBSWY3DPEHPK3PXP")
    entry_upd = TOTPEntry(issuer="UpdService", account="user", secret="GEZDGNBVGY3TQOJQ")
    prof_upd = Token2Profile(slot=2, issuer="UpdService", account="user")
    prof_del = Token2Profile(slot=3, issuer="OldService", account="user")

    diff = DiffResult(
        to_add=[entry_add],
        to_update=[(entry_upd, prof_upd)],
        to_delete=[prof_del],
        final_slot_count=2,
    )
    existing_profiles = [prof_upd, prof_del]

    # 1. Mode: Add Only -> only adds, does not delete or update
    mock_adapter = MagicMock(spec=Token2CLIAdapter)
    ops = apply_sync(mock_adapter, diff, existing_profiles, mode="add_only")
    assert ops == 1
    mock_adapter.write_entry.assert_called_once_with(1, entry_add)
    mock_adapter.delete_entry.assert_not_called()

    # 2. Mode: Add & Update -> adds and updates, does not delete obsolete
    mock_adapter.reset_mock()
    ops = apply_sync(mock_adapter, diff, existing_profiles, mode="add_update")
    assert ops == 2
    # Update deletes old slot then writes updated
    mock_adapter.delete_entry.assert_called_once_with(2)
    assert mock_adapter.write_entry.call_count == 2

    # 3. Mode: Full Sync with confirmation -> adds, updates, and deletes obsolete
    mock_adapter.reset_mock()
    ops = apply_sync(mock_adapter, diff, existing_profiles, mode="full_sync", confirm_delete=False)
    assert ops == 3
    # Deleted prof_del (slot 3) and old prof_upd (slot 2)
    assert mock_adapter.delete_entry.call_count == 2
    assert mock_adapter.write_entry.call_count == 2

    # 4. Mode: Cancel -> 0 operations
    mock_adapter.reset_mock()
    ops = apply_sync(mock_adapter, diff, existing_profiles, mode="cancel")
    assert ops == 0
    mock_adapter.write_entry.assert_not_called()
    mock_adapter.delete_entry.assert_not_called()


def test_capacity_exceeded_guard():
    diff = DiffResult(
        to_add=[TOTPEntry(issuer="S", account="a", secret="S")] * 301,
        final_slot_count=301,
        is_capacity_exceeded=True,
    )
    mock_adapter = MagicMock(spec=Token2CLIAdapter)
    with pytest.raises(Token2Error) as exc_info:
        apply_sync(mock_adapter, diff, [], mode="add_only")
    assert "exceeds hardware limit 300" in str(exc_info.value)
