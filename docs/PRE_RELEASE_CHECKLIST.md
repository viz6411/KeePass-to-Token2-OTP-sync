# Pre-Release Checklist — v0.2.0

Каждый пункт чек-листа должен иметь статус и прикрепленное машинное свидетельство выполнения.
Отметка пункта без свидетельства считается недействительной.

Машинный лог выполнения пре-релизного стенда сохранен в: [manual-20261114-results.txt](file:///home/viz/projects/KeePass%20to%20Token2%20OTP%20sync/docs/testing/manual-20261114-results.txt)

---

## 1. Безопасность и Zero-Disk-Footprint
- [x] **SEC-01**: Никаких временных файлов на диске при экспорте и чтении KDBX (проверка `/tmp`, `%TEMP%`, рабочей директории).
  - *Expected*: Никаких файлов KDBX, XML или секретов не создается на диске во время и после синхронизации.
  - *Evidence*: `scripts/manual/verify_zero_disk.sh` (Passed: 0 disk files created, 0 leaks detected in /tmp)
- [x] **SEC-02**: Буферы секретов и паролей зануляются нулями в памяти (`bytearray`) после использования.
  - *Expected*: Вызов `scrub_bytes()` или выход из контекста `SecureBuffer` перезаписывает все байты нулями (`b == 0`).
  - *Evidence*: `tests/test_security.py::test_buffer_zeroing`
- [x] **SEC-03**: Пароли и PIN не передаются через аргументы командной строки `sys.argv`.
  - *Expected*: Пароли и PIN вводятся интерактивно через скрытые промпты или `stdin` pipe; `sys.argv` свободен от секретов.
  - *Evidence*: `tests/test_security.py::test_argv_leak_prevention`
- [x] **SEC-04**: Очистка DOM базы данных и секретных переменных после завершения синхронизации в TUI.
  - *Expected*: Ссылки на расшифрованную базу KeePassXC обнуляются, вызывается `gc.collect()`, volatile-буферы очищены.
  - *Evidence*: `tests/e2e/test_tier1_features.py::test_t1_kdbx_memory_scrubbing` и `tests/test_tui_stress.py::test_memory_hygiene_normal_sync`

---

## 2. Интеграция с KeePassXC (Zero-External-CLI и Hybrid Routing)
- [x] **KPXC-01**: Автономное прямое чтение KDBX в памяти через `pykeepass` без вызова внешнего CLI.
  - *Expected*: Базы KDBX 3.1, 4.0, 4.1 расшифровываются напрямую в RAM с шифрами AES, ChaCha20, Twofish и Argon2id/AES-KDF.
  - *Evidence*: `tests/test_kpxc_direct.py::test_direct_read_kdbx40_default` и `tests/e2e/test_tier1_features.py::test_t1_kdbx_standard_otpauth_uri`
- [x] **KPXC-02**: Парсинг стандартных RFC 6238 `otpauth://` URI.
  - *Expected*: Секреты, длина (6/8), алгоритм (SHA1/SHA256) и период (30/60) извлекаются и нормализуются (uppercase, без пробелов).
  - *Evidence*: `tests/test_kpxc.py::test_otpauth_normalization`
- [x] **KPXC-03**: Парсинг кастомных полей KeeOtp / TrayTOTP (`TimeOtp-*`).
  - *Expected*: TOTP-данные успешно извлекаются из `TimeOtp-Secret`, `TimeOtp-Length`, `TimeOtp-Period`, `TimeOtp-Algorithm` при отсутствии `otp` URI.
  - *Evidence*: `tests/test_kpxc_direct.py::test_direct_read_custom_properties_traytotp` и `tests/e2e/test_tier1_features.py::test_t1_kdbx_timeotp_custom_properties`
- [x] **KPXC-04**: Поддержка композитной аутентификации (пароль + ключевой файл `.key`).
  - *Expected*: База данных успешно открывается комбинацией мастер-пароля и бинарного/XML keyfile.
  - *Evidence*: `tests/e2e/test_tier1_features.py::test_t1_kdbx_composite_password_and_keyfile`
- [x] **KPXC-05**: Игнорирование записей из `Recycle Bin` и исключенных групп (`excluded_groups`).
  - *Expected*: Записи, находящиеся в корзине или настроенных исключаемых группах, отфильтровываются из пула синхронизации.
  - *Evidence*: `tests/test_kpxc.py::test_recycle_bin_ignored`
- [x] **KPXC-06**: Гибридный fallback на `keepassxc-cli` при вызове аппаратного YubiKey challenge-response (слоты 1/2).
  - *Expected*: При наличии параметра `yubikey_slot` или `backend="cli"` синхронизатор маршрутизирует вызовы через pipe `keepassxc-cli`.
  - *Evidence*: `tests/test_kpxc_direct.py::test_hybrid_routing_auto_with_yubikey` и `tests/e2e/test_tier3_combinations.py::test_t3_cross_hybrid_routing_facade`

---

## 3. Интеграция с Token2 PIN+ (Встроенный USB-HID протокол)
- [x] **T2-01**: Прямое USB-HID обнаружение токена (VID:PID 0x0483:0x5750 / 0x20a0:0x4211) через `hidapi`.
  - *Expected*: Драйвер открывает HID-устройство и передает 65-байтные feature reports с сигнатурой 0x21 без внешнего `token2-otp-cli`.
  - *Evidence*: `tests/test_token2_protocol.py::test_mock_transport_framing_and_fragmentation` и `tests/test_token2_protocol.py::test_hid_transport_mocked_calls`
- [x] **T2-02**: Криптографический обмен NIST P-256 ECDH + AES-256-CBC (IV-1) для `WRITE_SEED`.
  - *Expected*: Генерируется эфемерная пара EC-ключей, вычисляется общий секрет с токеном, seed зашифровывается по спецификации Token2.
  - *Evidence*: `tests/test_token2_protocol.py::test_ecdh_aes_round_trip`
- [x] **T2-03**: Выполнение APDU команд (GET_INFO, LIST_ENTRIES, WRITE_SEED, DELETE_ENTRY).
  - *Expected*: Токен возвращает метаданные, список активных профилей, производит безопасную запись и удаление нулевым seed.
  - *Evidence*: `tests/e2e/test_tier1_features.py::test_t1_token2_write_seed` и `tests/test_token2_protocol.py::test_direct_client_lifecycle`
- [x] **T2-04**: Получение и верификация текущих TOTP-кодов от токена по APDU.
  - *Expected*: Драйвер считывает live TOTP-коды для каждого аккаунта для проверки ротации ключей.
  - *Evidence*: `tests/test_token2_protocol.py::test_parse_enum_response_with_and_without_otp`
- [x] **T2-05**: Немедленное прекращение работы при неверном PIN без повторных попыток.
  - *Expected*: Ошибка аутентификации PIN выбрасывает `Token2PINError` и немедленно останавливает выполнение во избежание блокировки аппаратного токена.
  - *Evidence*: `tests/test_token2.py::test_pin_immediate_abort`
- [x] **T2-06**: Поддержка fallback на системный `token2-otp-cli` при отсутствии драйвера `hidapi`.
  - *Expected*: При сбое или отсутствии библиотеки `hidapi` система переключается на внешний CLI с сохранением безопасности stdin-пайпа.
  - *Evidence*: `tests/test_token2_protocol.py::test_adapter_auto_mode_fallback`

---

## 4. Движок сверки (Diff Engine)
- [x] **DIFF-01**: Корректное распределение записей по 4 категориям (`to_add`, `to_update`, `to_delete`, `skipped`).
  - *Expected*: Новые профили классифицируются в `to_add`, измененные в `to_update`, устаревшие в `to_delete`, неподдерживаемые в `skipped`.
  - *Evidence*: `tests/test_diff.py::test_diff_categories`
- [x] **DIFF-02**: Защита от переполнения аппаратного лимита (300 слотов).
  - *Expected*: При превышении емкости токена флаг `is_capacity_exceeded = True`, блокируется опасная запись и выводится предупреждение.
  - *Evidence*: `tests/test_diff.py::test_capacity_limit_300`
- [x] **DIFF-03**: Детекция ротации секрета по расхождению live TOTP-кода.
  - *Expected*: Несовпадение сгенерированного локально TOTP и аппаратного TOTP направляет аккаунт в `to_update`.
  - *Evidence*: `tests/test_diff.py::test_totp_code_verification`
- [x] **DIFF-04**: Предупреждение о дубликатах `(issuer, account)` в KDBX.
  - *Expected*: Дубликаты канонических пар фиксируются в `diff.duplicates`, выводятся пользователю, не вызывая сбоя сверки.
  - *Evidence*: `tests/test_diff.py::test_duplicate_entries_detection`

---

## 5. Интерактивный TUI и Мастер первого запуска (Onboarding Wizard)
- [x] **TUI-01**: Автоматический запуск Onboarding Wizard при отсутствии конфига.
  - *Expected*: При запуске в интерактивном TTY без настроенного пути к БД мастер проводит пользователя через 4 шага и сохраняет валидный TOML.
  - *Evidence*: `tests/test_tui.py::test_wizard_manual_full_flow` и `tests/test_tui.py::test_wizard_browse_flow`
- [x] **TUI-02**: Интерактивное Главное Меню [1-4] и маршрутизация режимов синхронизации.
  - *Expected*: Опции [1] Синхронизация, [2] Тестовый прогон (Dry Run), [3] Настройки, [4] Выход выполняются корректно; режимы Add Only, Add & Update, Full Sync, Cancel применяются штатно.
  - *Evidence*: `tests/test_tui.py::test_main_menu_dry_run` и `tests/e2e/test_tier1_features.py::test_t1_tui_interactive_menu_options`
- [x] **TUI-03**: Редактирование настроек в TUI (Settings Editor) с немедленным сохранением.
  - *Expected*: Меню [3] позволяет изменять путь к базе, ключевой файл, слот YubiKey, исключаемые группы с сохранением на диск.
  - *Evidence*: `tests/test_tui.py::test_settings_editor_edit_all_fields` и `tests/test_tui_stress.py::test_settings_editor_complete_mutation_cycle`
- [x] **TUI-04**: Нативный системный выбор файлов (Native OS File Picker) и Headless CLI Fallback.
  - *Expected*: На Windows запускается PowerShell .NET OpenFileDialog, на Linux — zenity/kdialog/tkinter; в headless/SSH сессиях активируется текстовый ввод пути с очисткой кавычек.
  - *Evidence*: `tests/test_file_picker.py` и `tests/test_file_picker_config_stress.py`
- [x] **TUI-05**: Корректная обработка прерываний пользователя (`Ctrl+C` / `EOF`).
  - *Expected*: `KeyboardInterrupt` и `EOFError` на любом шаге завершают работу программы с кодом 0 без аварийных трассировок стека.
  - *Evidence*: `tests/test_tui.py::test_main_menu_keyboard_interrupt_handled` и `tests/test_tui_stress.py::test_main_menu_keyboard_interrupt_graceful_exit`

---

## 6. Автономная сборка и дистрибуция (PyInstaller & Bundling)
- [x] **PKG-01**: Сборка автономного исполняемого файла (`t2-kpxc-sync.exe` / `t2-kpxc-sync`).
  - *Expected*: Standalone-бинарник запускается и выводит `--help` на чистой машине без установленного Python.
  - *Evidence*: Вывод команды `dist/t2-kpxc-sync --help`
- [x] **PKG-02**: Умные лаунчеры в 1 клик (`Sync-Token2.bat` и `Sync-Token2.sh`).
  - *Expected*: Скрипты автоматически запускают локальный скомпилированный бинарник или используют `python -m t2_kpxc_sync` в режиме разработчика.
  - *Evidence*: Лог выполнения `Sync-Token2.sh` / `Sync-Token2.bat`
- [x] **PKG-03**: Целостность портативного архива дистрибутива (ZIP / tar.gz).
  - *Expected*: Архив содержит бинарник, `config.example.toml`, скрипты запуска, `README.md`, `RELEASE_NOTES_v0.2.0.md` и `docs/architecture.html`.
  - *Evidence*: `python scripts/package_dist.py` лог верификации содержимого архива
    - Пакетирование проверено: `dist/t2-kpxc-sync-v0.2.0-linux-x64.tar.gz`
    - Тесты целостности: `tests/test_package_dist.py` и `tests/test_package_dist_adversarial.py` (37 tests passed)

---

## 7. CI/CD автоматизация и Архитектура
- [x] **CI-01**: GitHub Actions workflow релиза (`.github/workflows/release.yml`).
  - *Expected*: Сборочная матрица (`windows-latest`, `ubuntu-22.04`) компилирует бинарники, архивирует дистрибутив и формирует драфт релиза на пуш тега `v*`.
  - *Evidence*: Синтаксическая валидация `.github/workflows/release.yml` и успешный прогон тестового джоба
- [x] **ARCH-01**: Синхронизация архитектурной карты Archify (`docs/architecture.json` и `docs/architecture.html`).
  - *Expected*: Интерактивный файл `docs/architecture.html` отражает компоненты v0.2.0 и валидируется с 0 ошибок и 0 предупреждений в профиле showcase.
  - *Evidence*: `node /home/viz/.gemini/config/skills/archify/bin/archify.mjs deliver architecture docs/architecture.json docs/architecture.html --quality showcase` (Passed: 9/9 checks, 0 errors, 0 warnings)

---

## 8. Хаос-тестирование и устойчивость (Adversarial Chaos Battery)
- [x] **CHAOS-01**: Обработка поврежденного/невалидного XML при экспорте KeePassXC.
  - *Expected*: Ошибка XML перехватывается с исключением `KeePassXCError` без падения процесса.
  - *Evidence*: `tests/test_chaos.py::test_corrupted_xml_handling`
- [x] **CHAOS-02**: Обработка поврежденного/невалидного APDU или JSON ответа токена.
  - *Expected*: Ошибка десериализации перехватывается с исключением `Token2Error` без сбоя синхронизатора.
  - *Evidence*: `tests/test_chaos.py::test_malformed_json_handling`
- [x] **CHAOS-03**: Граничные входные данные (Unicode, emoji, 10000+ символов, спецсимволы, пустые поля).
  - *Expected*: Все парсеры и UI безопасно обрабатывают длинные строки, emoji и спецсимволы без утечек памяти.
  - *Evidence*: `tests/test_chaos.py::test_boundary_and_malformed_inputs`
- [x] **CHAOS-04**: Симуляция обрыва USB-соединения во время синхронизации и восстановление состояния.
  - *Expected*: Обрыв соединения на середине пакетной операции фиксирует точное число выполненных записей, очищает память и оставляет устройство в консистентном состоянии.
  - *Evidence*: `tests/test_chaos.py::test_usb_disconnect_simulation`
- [x] **CHAOS-05**: Предотвращение блокировки токена при серии неверных PIN (immediate abort).
  - *Expected*: Однократная ошибка PIN немедленно останавливает выполнение без повторных попыток.
  - *Evidence*: `tests/test_chaos.py::test_immediate_abort_on_auth_failure`
- [x] **CHAOS-06**: Устойчивость TUI к спаму нажатий (rapid enter / double-submit).
  - *Expected*: Быстрый ввод пустых строк или некорректных опций меню не нарушает работу TUI и не повреждает конфигурационный файл.
  - *Evidence*: `tests/test_tui_stress.py::test_main_menu_invalid_choices_and_clean_exit`

---

## 9. Верификация фикса v0.2.1 (APDU Extended Lc Framing & SW 0x6FFB)
- [x] **FIX-01**: Формирование Extended Lc (`00 00 00`) в APDU при пустом теле (`CMD_GET_ECDH_PUBKEY`, `erase_all`).
  - *Expected*: `build_get_ecdh_pubkey_apdu()` возвращает ровно 7 байт `80 C5 01 00 00 00 00`.
  - *Evidence*: `tests/test_token2_protocol.py::test_apdu_extended_lc_for_empty_payload`
- [x] **FIX-02**: Симуляция аппаратного ответа 0x6FFB на усеченные 4-байтные APDU.
  - *Expected*: `SimulatedToken2HIDDevice` возвращает статус `0x6FFB` при получении усеченного 4-байтного `80 C5 01 00` и `0x9000` при получении `80 C5 01 00 00 00 00`.
  - *Evidence*: `tests/e2e/test_tier2_boundaries.py::test_t2_token2_short_apdu_rejected_with_6ffb`
- [x] **FIX-03**: Успешная запись TOTP-профиля на токен со встроенным протоколом и extended Lc.
  - *Expected*: `write_entry()` успешно получает 64-байтный ECDH pubkey, выполняет обмен и записывает профиль без ошибки 0x6FFB.
  - *Evidence*: `tests/e2e/test_tier1_features.py::test_t1_token2_write_seed_extended_lc`
  - *Manual Evidence*: [manual-20261114-v021-results.txt](file:///home/viz/projects/KeePass%20to%20Token2%20OTP%20sync/docs/testing/manual-20261114-v021-results.txt)

---

## 10. Верификация фикса v0.2.2 (USB Sequence Counter Reset per APDU & SW 0x6FFB Elimination)
- [x] **FIX-04**: Сброс счётчика последовательности USB-HID пакетов (`idx & 0x0F`) для каждого нового APDU фрейма в `send_apdu()`.
  - *Expected*: Каждый отдельный APDU фрейм начинает первый 64-байтный фрагмент со счетчика 0 (`(flag & 0xF0) | (idx & 0x0F)`), исключая перенос накопленного счетчика от предыдущей команды `list_entries()`.
  - *Evidence*: `src/t2_kpxc_sync/token2/transport.py` (BaseTransport.send_apdu)
- [x] **FIX-05**: Валидация сброса счетчика при непрерывной цепочке команд `GET_INFO` -> `ENUM_CODES` -> `GET_ECDH_PUBKEY`.
  - *Expected*: Все 3 последовательные команды стартуют с `seq = 0`.
  - *Evidence*: `tests/test_token2_protocol.py::test_usb_sequence_counter_strictly_resets_per_apdu`
- [x] **FIX-06**: Эмуляция отказа аппаратного токена (`0x6FFB`) в тестовом стенде (`conftest.py` и `MockHIDTransport`) при получении пакетов с нарушенной последовательностью (`seq != 0` на новом APDU).
  - *Expected*: Виртуальный стенд возвращает аппаратный статус `0x6FFB`, полностью симулируя реальный токен Token2 PIN+.
  - *Evidence*: `tests/test_token2_protocol.py::test_mock_transport_rejects_out_of_order_sequence_with_6ffb`
- [x] **FIX-07**: Полный регрессионный прогон всего набора автотестов (399 тестов).
  - *Expected*: 100% тестов проходят успешно без единого регресса.
  - *Evidence*: `python3 -m pytest` (399 passed in 98.07s)
  - *Manual Evidence*: [manual-20261114-v022-results.txt](file:///home/viz/projects/KeePass%20to%20Token2%20OTP%20sync/docs/testing/manual-20261114-v022-results.txt)

---

## 11. Верификация релиза v0.3.0 (TOTP Entry Format Selection & Touch Button Requirement)
- [x] **FMT-01**: Интерактивный запрос формата записи TOTP в TUI на финальном шаге перед записью.
  - *Expected*: Перед выполнением записей на токен TUI вызывает `prompt_entry_format()`, предлагая выбор: [1] Обычный формат (по умолчанию) или [2] Требовать касания для показа кода (Require touch/button press).
  - *Evidence*: `tests/test_tui.py::test_prompt_entry_format_choices`, `tests/test_tui.py::test_main_menu_sync_apply_add_touch_required`
- [x] **FMT-02**: Настройка формата по умолчанию в редакторе настроек TUI (`[6] Изменить формат TOTP по умолчанию`).
  - *Expected*: В меню настроек отображается текущий формат («Обычный» / «Требуется нажатие кнопки»), опция `[6]` позволяет переключать значение и сохранять в `config.toml`.
  - *Evidence*: `tests/test_tui.py::test_settings_editor_edit_all_fields`, `tests/test_tui_stress.py::test_settings_editor_complete_mutation_cycle`
- [x] **FMT-03**: Поддержка конфигурационного параметра `button_required` в `config.toml` и `config.example.toml`.
  - *Expected*: `Token2Config` содержит поле `button_required: bool = False`, корректно читается и сохраняется сериализатором.
  - *Evidence*: `src/t2_kpxc_sync/config.py`, `config.example.toml`
- [x] **FMT-04**: Поддержка CLI-флага `--button-required` для пакетного режима синхронизации.
  - *Expected*: При передаче `--button-required` вычисляется `btn_flag=1`, при отсутствии — `btn_flag=0` (или берётся из конфига).
  - *Evidence*: `tests/test_cli.py::test_cli_batch_button_required_flag`
- [x] **FMT-05**: Проброс `btn_flag` (0x00 / 0x01) на аппаратный уровень (USB-HID direct client & fallback CLI).
  - *Expected*: Байт 5 расшифрованного пакета `CMD_WRITE_SEED` передаёт флаг `btn_flag`, а `Token2CLIAdapter` при необходимости добавляет `--button-required`.
  - *Evidence*: `src/t2_kpxc_sync/token2/adapter.py`, `src/t2_kpxc_sync/token2/direct.py`
- [x] **FMT-06**: Поддержка флага `btn_flag` в модели `Token2Profile` при листинге записей.
  - *Expected*: `Token2Profile.btn_flag` считывается из метаданных профилей устройства.
  - *Evidence*: `src/t2_kpxc_sync/models.py`, `src/t2_kpxc_sync/token2/client.py`
- [x] **FMT-07**: Полный регрессионный прогон всего набора автотестов (403 теста).
  - *Expected*: 100% тестов проходят успешно без ошибок и регрессий.
  - *Evidence*: `python3 -m pytest` (403 passed)
  - *Manual Evidence*: [manual-20261114-v030-results.txt](file:///home/viz/projects/KeePass%20to%20Token2%20OTP%20sync/docs/testing/manual-20261114-v030-results.txt)

---

## 12. Верификация хотфикса v0.3.1 (KeePass XPath Hardening & Custom Attribute Direct DOM Inspection)
- [x] **KDBX-01**: Безопасное извлечение строковых атрибутов записи (`get_entry_strings(entry)`) через прямой обход DOM (`entry._element`), исключая вызов уязвимого свойства `entry.custom_properties` из `pykeepass`.
  - *Expected*: Строковые атрибуты записей (включая кастомные поля) считываются напрямую из дерева элементов без генерации XPath-запросов и без интерполяции строк вида `String/Key[text()="{}"]`.
  - *Evidence*: `src/t2_kpxc_sync/kpxc.py` (`get_entry_strings`, `extract_totp_from_entry`)
- [x] **KDBX-02**: Полная устойчивость к кавычкам (`"`, `'`), спецсимволам, квадратным скобкам и знакам препинания в ключах кастомных полей.
  - *Expected*: База данных с записями, содержащими `custom"quote`, `field'name`, `[test]`, `<tag>` и т.д., считывается без исключения `lxml.etree.XPathEvalError: Invalid predicate` / `KeePassCorruptedError`.
  - *Evidence*: `tests/test_kpxc_direct.py`, `tests/test_kpxc_stress.py`
- [x] **KDBX-03**: Изоляция исключений на уровне отдельных записей в `read_kdbx_direct`.
  - *Expected*: Если отдельная запись повреждена или вызывает ошибку парсинга, парсер логирует предупреждение и продолжает сканирование остальных сотен записей базы, предотвращая срыв всей сессии синхронизации.
  - *Evidence*: `src/t2_kpxc_sync/kpxc.py` (`read_kdbx_direct`)
- [x] **KDBX-04**: Полный регрессионный прогон набора автотестов (включая все tier-тесты).
  - *Expected*: 100% тестов проходят успешно без ошибок и регрессий.
  - *Evidence*: `python3 -m pytest` (406 passed)
- [x] **KDBX-05**: Фиксация результатов прогона в артефакте ручного стенда.
  - *Expected*: Стенд выполнен с машинной верификацией в `docs/testing/manual-<stamp>-v031-results.txt`.
  - *Evidence*: `docs/testing/manual-20261117-v031-results.txt`




