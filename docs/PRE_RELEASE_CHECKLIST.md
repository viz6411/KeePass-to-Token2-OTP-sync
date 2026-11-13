# Pre-Release Checklist — v0.1.0

Каждый пункт чек-листа должен иметь статус и прикрепленное машинное свидетельство выполнения.
Отметка пункта без свидетельства считается недействительной.

## 1. Безопасность и Zero-Disk-Footprint
- [ ] **SEC-01**: Никаких временных файлов на диске при экспорте KDBX (проверка `/tmp`, `%TEMP%`, рабочей директории).
  - *Evidence*: `scripts/manual/verify_zero_disk.sh` лог
- [ ] **SEC-02**: Буферы секретов и паролей зануляются нулями в памяти (`bytearray`) после использования.
  - *Evidence*: тест `tests/test_security.py::test_buffer_zeroing`
- [ ] **SEC-03**: Пароли и PIN не передаются через аргументы командной строки `sys.argv`.
  - *Evidence*: тест `tests/test_security.py::test_argv_leak_prevention`

## 2. Интеграция с KeePassXC
- [ ] **KPXC-01**: Корректное чтение базы через pipe `keepassxc-cli` без сохранения на диск.
  - *Evidence*: `tests/test_kpxc.py::test_kpxc_cli_pipe_parsing`
- [ ] **KPXC-02**: Игнорирование записей из `Recycle Bin` и исключенных групп.
  - *Evidence*: `tests/test_kpxc.py::test_recycle_bin_ignored`
- [ ] **KPXC-03**: Валидация и нормализация `otpauth://` URI (`issuer`, `account`, алгоритм, период, длина).
  - *Evidence*: `tests/test_kpxc.py::test_otpauth_normalization`

## 3. Интеграция с Token2 PIN+
- [ ] **T2-01**: Парсинг вывода `get_all --json` токена.
  - *Evidence*: `tests/test_token2.py::test_parse_entries_json`
- [ ] **T2-02**: Прекращение работы при неверном PIN без повторных попыток.
  - *Evidence*: `tests/test_token2.py::test_pin_immediate_abort`
- [ ] **T2-03**: Формирование команд `write_entry` и `delete_entry`.
  - *Evidence*: `tests/test_token2.py::test_write_delete_commands`

## 4. Движок сверки (Diff Engine)
- [ ] **DIFF-01**: Распределение записей по категориям `to_add`, `to_update`, `to_delete`, `skipped`.
  - *Evidence*: `tests/test_diff.py::test_diff_categories`
- [ ] **DIFF-02**: Валидация лимита 300 слотов токена.
  - *Evidence*: `tests/test_diff.py::test_capacity_limit_300`
- [ ] **DIFF-03**: Определение ротации ключа по несовпадению текущего TOTP-кода.
  - *Evidence*: `tests/test_diff.py::test_totp_code_verification`

## 5. Консольный интерфейс и сценарии
- [ ] **CLI-01**: Корректная обработка режимов Add Only, Add & Update, Full Sync, Cancel.
  - *Evidence*: `tests/test_cli.py::test_sync_modes`
- [ ] **CLI-02**: Защита от дубликатов `(issuer, account)` в KeePassXC.
  - *Evidence*: `tests/test_diff.py::test_duplicate_entries_detection`
