# E2E Test Suite Infrastructure & Architecture (v0.2.0)

## 1. Overview
The end-to-end (E2E) test suite provides exhaustive, opaque-box integration verification for the **KeePass to Token2 OTP Sync** application across all core features:
1. **Direct KDBX Parsing**: Memory-safe parsing of KDBX 3.1, 4.0, and 4.1 databases using `pykeepass` with support for AES-256, ChaCha20, Twofish ciphers, Argon2id/AES KDFs, composite credentials (password + binary keyfiles), and dual OTP schemas (`otpauth://` URIs and `TimeOtp-*` custom string attributes).
2. **Embedded Token2 Hardware Protocol**: In-process cryptographic emulation of Token2 PIN+ / Link USB-HID security keys executing NIST P-256 ECDH ephemeral key exchange, SHA-256 session key derivation, AES-256-CBC encryption (constant IV-1), 65-byte USB feature report framing (Report ID `0x21`), and ISO 7816-4 APDU command sequencing (`GET_INFO`, `ENUM_ACCOUNTS`, `WRITE_SEED`, `DELETE_ENTRY`, `SYNC_TIME`).
3. **Headless TUI Interaction**: Automated interactive terminal session driving rich onboarding wizards, differential preview tables, sync confirmation prompts, and configuration persistence without opening `/dev/tty` or deadlocking automated CI runners.
4. **CLI & Subprocess Invocation**: Non-interactive command-line execution (`--help`, `--dry-run`, `--mode`, `--config`, `--yes`) via detached subprocess sessions with strict execution timeouts.

---

## 2. Four-Tier Coverage Model

| Tier | Category | File | Count | Focus Areas |
|------|----------|------|-------|-------------|
| **Tier 1** | Feature Coverage | `tests/e2e/test_tier1_features.py` | 26 | Isolated happy-path verification across direct KDBX reading, Token2 USB-HID operations, TUI interactive menu flows, and CLI command flags. |
| **Tier 2** | Boundary & Chaos | `tests/e2e/test_tier2_boundaries.py` | 23 | Stress and fault-injection: empty vaults, unicode/emojis, 150+ bulk entries, corrupted headers/payloads, Token2 capacity limits (300 slots), USB disconnect mid-transfer, PIN authentication failures, prompt EOF, and narrow terminals (40 cols). |
| **Tier 3** | Cross-Feature Combinations | `tests/e2e/test_tier3_combinations.py` | 6 | Multi-subsystem interactions: multi-schema KDBX + Token2 ECDH provisioning, dry-run zero-write simulation, TUI wizard onboarding -> CLI sync execution, headless file picker fallback, and capacity overflow diff guards. |
| **Tier 4** | Real-World Application Scenarios | `tests/e2e/test_tier4_scenarios.py` | 6 | End-to-end user journeys: clean onboarding to full sync, quarterly credential rotation, sub-50ms idempotent re-sync, mixed legacy KDBX migration, and CLI binary smoke testing. |
| **Total** | | | **61** | **Exceeds required $\ge 50$ test minimum.** |

---

## 3. Test Infrastructure Components

### 3.1. Dynamic KDBX Factory (`tests/e2e/fixtures/kdbx_factory.py`)
- Programmatically constructs valid, self-contained KDBX 4.0 databases in temporary directories.
- Fast execution via single-round Argon2id KDF configuration for dynamic test generation.
- Supports bulk entry generation (`save=False` optimization) enabling generation of 150+ entries in <0.3s.
- Encapsulates cipher selection (`AES-256`, `ChaCha20`, `Twofish`), keyfile generation (32-byte cryptographic random binary), and corruption injection (header magic overwrites, payload truncations).

### 3.2. Embedded KDBX 3.1 Base64 Fixture (`tests/e2e/fixtures/kdbx3_sample.py`)
- Self-contained 5,166-byte (6,888 base64 characters) valid KDBX 3.1 database with legacy AES-KDF.
- Pre-seeded with 16 accounts (including valid TOTP secrets).
- Unlocks with password `test3pass` with zero external network or filesystem dependencies.

### 3.3. Pure-Python Token2 USB-HID Simulator (`tests/e2e/conftest.py`)
- `SimulatedToken2HIDDevice` emulates Token2 PIN+ / Link hardware directly in memory:
  * **NIST P-256 ECDH**: Generates ephemeral P-256 curve points, calculates shared secrets with caller's public key, derives SHA-256 symmetric encryption key.
  * **AES-256-CBC**: Decrypts seed payloads using the standard Token2 constant IV (`\x00...\x00\x01`) and validates PKCS#7 padding.
  * **ISO 7816-4 APDU Dispatcher**: Handles `GET_INFO` (returns serial `T2-SIM-001` and firmware `v2.4`), `ENUM_ACCOUNTS` (pagination and live TOTP computation), `WRITE_SEED` (account provisioning / deletion / wipe), and `SYNC_TIME`.
  * **Capacity Guard**: Simulates maximum hardware limit (300 entries), raising status word `0x6A84` when capacity is exhausted.
  * **Touch-Button & Disconnect**: Emulates `0xC0` touch polling loops, PIN authentication verification, and simulated physical USB unplugging.
- `mock_token2_hid` pytest fixture routes both `hidapi` (`sys.modules["hid"]`) and the application's CLI adapter to the simulated hardware.

### 3.4. Headless Interactive TTY Harness (`tests/e2e/harness.py`)
- `PseudoTTY`: Custom `io.StringIO` wrapper returning `isatty() == True` and emulating arbitrary terminal dimensions (`lines`, `columns`).
- `run_interactive_session`: Intercepts `rich.console.Console.input` and `getpass.getpass` to inject sequential scripted keystrokes and mock terminal inputs, completely avoiding `/dev/tty` deadlocks in automated runners.
- `strip_ansi`: Strips VT100 / ANSI escape sequences from rendered console output to facilitate clean text assertion.
- `run_cli_subprocess`: Spawns detached subprocess sessions with a strict 5.0s timeout to verify command-line argument parsing and exit codes.

---

## 4. Execution & Verification

### Run End-to-End Test Suite
```bash
PYTHONPATH=src python3 -m pytest tests/e2e/ -v
```

### Run Full Test Suite (Unit, Protocol, Adversarial, and E2E)
```bash
PYTHONPATH=src python3 -m pytest
```

---

## 5. Quality Invariants
1. **Opaque-Box Testing**: Tests interact exclusively through public APIs, TUI interfaces, and CLI commands. No internal business logic, diff algorithms, or cryptographic functions are mocked.
2. **Zero Physical Dependencies**: All tests run deterministically in headless CI environments without requiring physical Token2 dongles, smartcards, or GUI display servers.
3. **Execution Speed & Determinism**: All 61 E2E tests execute in under 20 seconds. Memory scrubbing is verified on every path, and temporary files are strictly cleaned up.
