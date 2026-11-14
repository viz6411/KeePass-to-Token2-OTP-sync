#!/usr/bin/env bash
# Stage 8 Evidence-Based Manual Pre-Release Stand Runner
# Runs verification for all 36 items in docs/PRE_RELEASE_CHECKLIST.md
# Outputs machine evidence verbatim into docs/testing/manual-20261114-results.txt

set -u

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

OUT_DIR="docs/testing"
mkdir -p "$OUT_DIR"
RESULTS_FILE="$OUT_DIR/manual-20261114-results.txt"
rm -f "$RESULTS_FILE"

export PYTHONPATH=src
PYTHON_BIN="/usr/bin/python3"
NODE_BIN="/home/viz/.local/bin/node"
ARCHIFY_BIN="/home/viz/.gemini/config/skills/archify/bin/archify.mjs"

PASS_COUNT=0
FAIL_COUNT=0
TOTAL_COUNT=0

log() {
    echo "$@" | tee -a "$RESULTS_FILE"
}

run_check() {
    local item_id="$1"
    local title="$2"
    shift 2
    local cmd=("$@")

    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    log "================================================================================"
    log "[$TOTAL_COUNT/36] $item_id: $title"
    log "Command: ${cmd[*]}"
    log "--------------------------------------------------------------------------------"

    # Execute command, stream output to stdout and append verbatim to RESULTS_FILE
    "${cmd[@]}" >> "$RESULTS_FILE" 2>&1
    local status=$?

    if [ $status -eq 0 ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        log "Result: PASS (Exit code 0)"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        log "Result: FAIL (Exit code $status)"
    fi
    log ""
}

log "=== PRE-RELEASE VERIFICATION EVIDENCE LOG ==="
log "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
log "Environment: $(uname -s -r -v -m) | Python: $($PYTHON_BIN --version 2>&1)"
log "Git Revision: $(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
log "Working Directory: $PROJECT_ROOT"
log ""

# Category 1: Безопасность и Zero-Disk-Footprint
run_check "SEC-01" "Zero-Disk-Footprint Invariant" bash scripts/manual/verify_zero_disk.sh
run_check "SEC-02" "Buffer Scrubbing and Zeroing" $PYTHON_BIN -m pytest -v tests/test_security.py::test_buffer_zeroing
run_check "SEC-03" "sys.argv Leak Prevention" $PYTHON_BIN -m pytest -v tests/test_security.py::test_argv_leak_prevention
run_check "SEC-04" "Memory Hygiene and GC Cleanup" $PYTHON_BIN -m pytest -v tests/e2e/test_tier1_features.py::test_t1_kdbx_memory_scrubbing tests/test_tui_stress.py::test_memory_hygiene_normal_sync

# Category 2: Интеграция с KeePassXC
run_check "KPXC-01" "Autonomous Direct KDBX Reading" $PYTHON_BIN -m pytest -v tests/test_kpxc_direct.py::test_direct_read_kdbx40_default tests/e2e/test_tier1_features.py::test_t1_kdbx_standard_otpauth_uri
run_check "KPXC-02" "RFC 6238 otpauth URI Normalization" $PYTHON_BIN -m pytest -v tests/test_kpxc.py::test_otpauth_normalization
run_check "KPXC-03" "KeeOtp / TrayTOTP TimeOtp Custom Properties" $PYTHON_BIN -m pytest -v tests/test_kpxc_direct.py::test_direct_read_custom_properties_traytotp tests/e2e/test_tier1_features.py::test_t1_kdbx_timeotp_custom_properties
run_check "KPXC-04" "Composite Password and Keyfile Auth" $PYTHON_BIN -m pytest -v tests/e2e/test_tier1_features.py::test_t1_kdbx_composite_password_and_keyfile
run_check "KPXC-05" "Recycle Bin and Excluded Groups Filtering" $PYTHON_BIN -m pytest -v tests/test_kpxc.py::test_recycle_bin_ignored
run_check "KPXC-06" "Hybrid KeePassXC Routing and YubiKey Fallback" $PYTHON_BIN -m pytest -v tests/test_kpxc_direct.py::test_hybrid_routing_auto_with_yubikey tests/e2e/test_tier3_combinations.py::test_t3_cross_hybrid_routing_facade

# Category 3: Интеграция с Token2 PIN+
run_check "T2-01" "USB-HID Transport and 65-byte Framing" $PYTHON_BIN -m pytest -v tests/test_token2_protocol.py::test_mock_transport_framing_and_fragmentation tests/test_token2_protocol.py::test_hid_transport_mocked_calls
run_check "T2-02" "NIST P-256 ECDH + AES-256-CBC IV-1 Seed Provisioning" $PYTHON_BIN -m pytest -v tests/test_token2_protocol.py::test_ecdh_aes_round_trip
run_check "T2-03" "APDU Commands Execution" $PYTHON_BIN -m pytest -v tests/e2e/test_tier1_features.py::test_t1_token2_write_seed tests/test_token2_protocol.py::test_direct_client_lifecycle
run_check "T2-04" "Live TOTP Codes and Profile Enumeration" $PYTHON_BIN -m pytest -v tests/test_token2_protocol.py::test_parse_enum_response_with_and_without_otp
run_check "T2-05" "Immediate Abort on Invalid PIN" $PYTHON_BIN -m pytest -v tests/test_token2.py::test_pin_immediate_abort
run_check "T2-06" "CLI Fallback when Native HID Driver is Missing" $PYTHON_BIN -m pytest -v tests/test_token2_protocol.py::test_adapter_auto_mode_fallback

# Category 4: Движок сверки (Diff Engine)
run_check "DIFF-01" "Diff 4-Way Category Classification" $PYTHON_BIN -m pytest -v tests/test_diff.py::test_diff_categories
run_check "DIFF-02" "Hardware Capacity Limit (300 Slots)" $PYTHON_BIN -m pytest -v tests/test_diff.py::test_capacity_limit_300
run_check "DIFF-03" "Live TOTP Seed Discrepancy Rotation Detection" $PYTHON_BIN -m pytest -v tests/test_diff.py::test_totp_code_verification
run_check "DIFF-04" "Duplicate (issuer, account) Detection" $PYTHON_BIN -m pytest -v tests/test_diff.py::test_duplicate_entries_detection

# Category 5: Интерактивный TUI и Onboarding Wizard
run_check "TUI-01" "Onboarding Wizard Configuration Generation" $PYTHON_BIN -m pytest -v tests/test_tui.py::test_wizard_manual_full_flow tests/test_tui.py::test_wizard_browse_flow
run_check "TUI-02" "Main Menu Routing and Sync Modes" $PYTHON_BIN -m pytest -v tests/test_tui.py::test_main_menu_dry_run tests/e2e/test_tier1_features.py::test_t1_tui_interactive_menu_options
run_check "TUI-03" "Settings Editor Mutation and Persistence" $PYTHON_BIN -m pytest -v tests/test_tui.py::test_settings_editor_edit_all_fields tests/test_tui_stress.py::test_settings_editor_complete_mutation_cycle
run_check "TUI-04" "Native OS File Picker and Headless CLI Fallback" $PYTHON_BIN -m pytest -v tests/test_file_picker.py tests/test_file_picker_config_stress.py
run_check "TUI-05" "Graceful Exit on Interrupt (Ctrl+C / EOF)" $PYTHON_BIN -m pytest -v tests/test_tui.py::test_main_menu_keyboard_interrupt_handled tests/test_tui_stress.py::test_main_menu_keyboard_interrupt_graceful_exit

# Category 6: Автономная сборка и дистрибуция
run_check "PKG-01" "Standalone Executable Execution (--help)" ./dist/t2-kpxc-sync --help
run_check "PKG-02" "Smart Launchers Execution (--help)" ./Sync-Token2.sh --help
run_check "PKG-03" "Distribution Archive Packaging and Integrity" $PYTHON_BIN scripts/package_dist.py --version 0.2.0

# Category 7: CI/CD автоматизация и Архитектура
run_check "CI-01" "GitHub Actions Workflow Syntax Validation" $PYTHON_BIN -c "import yaml; d = yaml.safe_load(open('.github/workflows/release.yml')); assert 'jobs' in d; print('release.yml jobs:', list(d['jobs'].keys()))"
run_check "ARCH-01" "Archify Architecture Map Showcase Validation" $NODE_BIN $ARCHIFY_BIN deliver architecture docs/architecture.json docs/architecture.html --quality showcase

# Category 8: Хаос-тестирование и устойчивость
run_check "CHAOS-01" "Corrupted XML Handling" $PYTHON_BIN -m pytest -v tests/test_chaos.py::test_corrupted_xml_handling
run_check "CHAOS-02" "Malformed Token Response Handling" $PYTHON_BIN -m pytest -v tests/test_chaos.py::test_malformed_json_handling
run_check "CHAOS-03" "Boundary and Malformed Inputs" $PYTHON_BIN -m pytest -v tests/test_chaos.py::test_boundary_and_malformed_inputs
run_check "CHAOS-04" "USB Disconnect Simulation and Recovery" $PYTHON_BIN -m pytest -v tests/test_chaos.py::test_usb_disconnect_simulation
run_check "CHAOS-05" "Token Lockout Prevention on Invalid PIN" $PYTHON_BIN -m pytest -v tests/test_chaos.py::test_immediate_abort_on_auth_failure
run_check "CHAOS-06" "TUI Spam and Double-Submit Resilience" $PYTHON_BIN -m pytest -v tests/test_tui_stress.py::test_main_menu_invalid_choices_and_clean_exit

log "================================================================================"
log "SUMMARY: Total checks: $TOTAL_COUNT | Passed: $PASS_COUNT | Failed: $FAIL_COUNT"
log "================================================================================"

if [ $FAIL_COUNT -eq 0 ]; then
    log "STATUS: SUCCESS - All 36 checklist items verified with zero errors."
    exit 0
else
    log "STATUS: FAILURE - $FAIL_COUNT checks failed. Inspect log above."
    exit 1
fi
