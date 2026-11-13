# Pre-Release Checklist — v0.1.0

Каждый пункт чек-листа должен иметь статус и прикрепленное машинное свидетельство выполнения.
Отметка пункта без свидетельства считается недействительной.

Машинный лог выполнения пре-релизного стенда сохранен в: [manual-20261113-results.txt](file:///home/viz/projects/KeePass%20to%20Token2%20OTP%20sync/docs/testing/manual-20261113-results.txt)

## 1. Безопасность и Zero-Disk-Footprint
- [x] **SEC-01**: Никаких временных файлов на диске при экспорте KDBX (проверка `/tmp`, `%TEMP%`, рабочей директории).
  - *Expected*: Никаких файлов KDBX или расшифрованных XML не создается на диске во время и после экспорта.
  - *Evidence*: `scripts/manual/verify_zero_disk.sh` (Passed: 0 disk files created, 0 leaks detected in /tmp)
- [x] **SEC-02**: Буферы секретов и паролей зануляются нулями в памяти (`bytearray`) после использования.
  - *Expected*: Вызов `scrub_bytes()` или выход из `SecureBuffer` перезаписывает все байты нулями (`b == 0`).
  - *Evidence*: тест `tests/test_security.py::test_buffer_zeroing` (Passed in 0.01s)
- [x] **SEC-03**: Пароли и PIN не передаются через аргументы командной строки `sys.argv`.
  - *Expected*: Пароли и PIN передаются исключительно через потоки `stdin` (pipe), аргументы командной строки не содержат секретов.
  - *Evidence*: тест `tests/test_security.py::test_argv_leak_prevention` (Passed in 0.01s)

## 2. Интеграция с KeePassXC
- [x] **KPXC-01**: Корректное чтение базы через pipe `keepassxc-cli` без сохранения на диск.
  - *Expected*: Вывод `keepassxc-cli export` перехватывается в оперативной памяти и преобразуется в валидный список `TOTPEntry`.
  - *Evidence*: `tests/test_kpxc.py::test_kpxc_cli_pipe_parsing` (Passed in 0.01s)
- [x] **KPXC-02**: Игнорирование записей из `Recycle Bin` и исключенных групп.
  - *Expected*: Записи, находящиеся в корзине (`Recycle Bin`) или группах из списка `excluded_groups`, не попадают в итоговую выборку.
  - *Evidence*: `tests/test_kpxc.py::test_recycle_bin_ignored` (Passed in 0.01s)
- [x] **KPXC-03**: Валидация и нормализация `otpauth://` URI (`issuer`, `account`, алгоритм, период, длина).
  - *Expected*: Параметры URL декодируются, секрет очищается от пробелов и переводится в uppercase, fallback на путь при отсутствии query issuer.
  - *Evidence*: `tests/test_kpxc.py::test_otpauth_normalization` (Passed in 0.01s)

## 3. Интеграция с Token2 PIN+
- [x] **T2-01**: Парсинг вывода `get_all --json` токена.
  - *Expected*: JSON-массив или объект с профилями токена парсится в список объектов `Token2Profile` с корректными типами.
  - *Evidence*: `tests/test_token2.py::test_parse_entries_json` (Passed in 0.01s)
- [x] **T2-02**: Прекращение работы при неверном PIN без повторных попыток.
  - *Expected*: При ошибке PIN выбрасывается `Token2PINError` и процесс немедленно прерывается без автоматических ретраев.
  - *Evidence*: `tests/test_token2.py::test_pin_immediate_abort` (Passed in 0.01s)
- [x] **T2-03**: Формирование команд `write_entry` и `delete_entry`.
  - *Expected*: Аргументы CLI для записи и удаления формируются строго по контракту CLI без передачи PIN в аргументах.
  - *Evidence*: `tests/test_token2.py::test_write_delete_commands` (Passed in 0.01s)

## 4. Движок сверки (Diff Engine)
- [x] **DIFF-01**: Распределение записей по категориям `to_add`, `to_update`, `to_delete`, `skipped`.
  - *Expected*: Новые ключи попадают в `to_add`, несовпадающие в `to_update`, отсутствующие в `to_delete`, неподдерживаемые (например SHA512) в `skipped`.
  - *Evidence*: `tests/test_diff.py::test_diff_categories` (Passed in 0.01s)
- [x] **DIFF-02**: Валидация лимита 300 слотов токена.
  - *Expected*: Если итоговое количество записей > 300, устанавливается флаг `is_capacity_exceeded = True`.
  - *Evidence*: `tests/test_diff.py::test_capacity_limit_300` (Passed in 0.01s)
- [x] **DIFF-03**: Определение ротации ключа по несовпадению текущего TOTP-кода.
  - *Expected*: При несовпадении сгенерированного локально TOTP и полученного от токена запись классифицируется как `to_update`.
  - *Evidence*: `tests/test_diff.py::test_totp_code_verification` (Passed in 0.01s)

## 5. Консольный интерфейс и сценарии
- [x] **CLI-01**: Корректная обработка режимов Add Only, Add & Update, Full Sync, Cancel.
  - *Expected*: Режим Add Only выполняет только запись новых, Add & Update обновляет и добавляет, Full Sync удаляет устаревшие с подтверждением, Cancel не производит записей.
  - *Evidence*: `tests/test_cli.py::test_sync_modes` (Passed in 0.01s)
- [x] **CLI-02**: Защита от дубликатов `(issuer, account)` в KeePassXC.
  - *Expected*: Повторяющиеся канонические ключи `(issuer, account)` фиксируются в `diff.duplicates` и выводят предупреждение пользователю.
  - *Evidence*: `tests/test_diff.py::test_duplicate_entries_detection` (Passed in 0.01s)

## 6. Хаос-тестирование и устойчивость (Adversarial Chaos Battery)
- [x] **CHAOS-01**: Обработка поврежденного/невалидного XML при экспорте KeePassXC.
  - *Expected*: Ошибка XML корректно перехватывается с исключением `KeePassXCError` без падения процесса.
  - *Evidence*: `tests/test_chaos.py::test_corrupted_xml_handling` (Passed in 0.01s)
- [x] **CHAOS-02**: Обработка невалидного/битого JSON от токена.
  - *Expected*: Ошибка разбора JSON перехватывается с исключением `Token2Error` без аварийного завершения.
  - *Evidence*: `tests/test_chaos.py::test_malformed_json_handling` (Passed in 0.01s)
- [x] **CHAOS-03**: Граничные входные данные (Unicode, emoji, 10000+ символов, спецсимволы, пустые поля).
  - *Expected*: Модели и парсеры безопасно обрабатывают длинные строки, спецсимволы и пустые значения без утечек памяти.
  - *Evidence*: `tests/test_chaos.py::test_boundary_and_malformed_inputs` (Passed in 0.01s)
- [x] **CHAOS-04**: Симуляция обрыва USB-соединения во время синхронизации и восстановление состояния.
  - *Expected*: Прерывание процесса на середине пакетной операции фиксирует точное число выполненных операций, очищает память и оставляет систему готовой к повторной идемпотентной синхронизации.
  - *Evidence*: `tests/test_chaos.py::test_usb_disconnect_simulation` (Passed in 0.01s)
- [x] **CHAOS-05**: Предотвращение блокировки токена при серии неверных PIN (immediate abort).
  - *Expected*: Никаких автоматических циклов повтора ввода PIN; однократная ошибка PIN сразу останавливает выполнение.
  - *Evidence*: `tests/test_chaos.py::test_immediate_abort_on_auth_failure` (Passed in 0.01s)
