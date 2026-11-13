# KeePassXC to Token2 PIN+ R3.3 TOTP Sync

Безопасная кроссплатформенная утилита для синхронизации TOTP-профилей из зашифрованной базы данных KeePassXC (`.kdbx`) на аппаратные токены безопасности **Token2 PIN+ R3.3** (до 300 слотов).

---

## Ключевые возможности и безопасность
- **Zero-Disk-Footprint & Read-Only**: База KeePassXC открывается **строго в режиме чтения**. Экспорт выполняется потоком через `keepassxc-cli` в оперативную память (`RAM`). Никаких незашифрованных XML/дампов или временных файлов на диске не создается.
- **Детекция ротации ключей без записи в KDBX**: Для определения обновленных секретов утилита генерирует в памяти текущий TOTP-код для момента времени $T$ и сравнивает его с кодом, возвращаемым аппаратным токеном.
- **Защита памяти**: Пароли базы, PIN-код токена и сырые секреты хранятся в изменяемых буферах `bytearray` и принудительно зануляются (`scrub_bytes`) в блоках `finally`. Пароли не передаются через аргументы процессов (`sys.argv`).
- **Защита аппаратного счетчика PIN**: При ошибке ввода PIN-кода утилита немедленно завершает работу, предотвращая исчерпание попыток и блокировку токена.
- **Запуск в 1 клик**: Готовые скрипты запуска для Windows, Linux и macOS.

---

## Системные требования
1. **Python 3.11+**
2. **KeePassXC**: утилита `keepassxc-cli` (входит в стандартную поставку KeePassXC).
3. **Token2 CLI**: официальная утилита `token2-otp-cli` (или `otp-cli.exe` для Windows) от [Token2 GitHub](https://github.com/token2/token2-otp-cli).
4. **Аппаратный ключ Token2 PIN+ R3.3**, подключенный по USB.

---

## Установка

### Вариант 1: Использование готового архива (Рекомендуется)
1. Скачайте `t2-kpxc-sync-v0.1.0-portable.zip` со страницы [Releases](https://github.com/viz6411/KeePass-to-Token2-OTP-sync/releases).
2. Распакуйте архив в удобную папку.
3. Установите зависимости:
   ```bash
   pip install rich
   ```

### Вариант 2: Установка через Wheel-пакет
```bash
pip install t2_kpxc_sync-0.1.0-py3-none-any.whl
```
После установки в системе доступна консольная команда:
```bash
t2-kpxc-sync
```

### Вариант 3: Установка из исходного кода
```bash
git clone https://github.com/viz6411/KeePass-to-Token2-OTP-sync.git
cd KeePass-to-Token2-OTP-sync
pip install .
```

---

## Настройка (`config.toml`)

При первом запуске утилита ищет файл конфигурации по стандартным путям:
- **Windows**: `%APPDATA%\t2-kpxc-sync\config.toml`
- **Linux**: `~/.config/t2-kpxc-sync/config.toml`
- **macOS**: `~/Library/Application Support/t2-kpxc-sync/config.toml`
- **Текущая директория**: `./config.toml`

Пример конфигурационного файла (`config.example.toml`):
```toml
[keepassxc]
# Путь к вашей базе данных .kdbx
database_path = "C:/Users/Username/Documents/Passwords.kdbx"

# Опционально: путь к ключевому файлу (.key / .keyx)
keyfile_path = ""

# Опционально: слот Challenge-Response YubiKey (например, "2")
yubikey_slot = ""

# Имя или абсолютный путь к бинарнику keepassxc-cli
cli_binary = "keepassxc-cli"

# Исключаемые группы (записи из них игнорируются)
excluded_groups = ["Recycle Bin", "Archive"]

[token2]
# Имя или абсолютный путь к утилите token2-otp-cli
cli_binary = "token2-otp-cli"
```

---

## Инструкция по запуску

### Быстрый запуск в один клик:
- **Windows**: Двойной клик по `Sync-Token2.bat`.
- **Linux**: Запуск скрипта `./Sync-Token2.sh` (для доступа к USB без root добавьте правило udev: `echo 'SUBSYSTEM=="usb", ATTR{idVendor}=="349e", MODE="0660", GROUP="plugdev", TAG+="uaccess"' | sudo tee /etc/udev/rules.d/70-token2.rules && sudo udevadm control --reload`).
- **macOS**: Двойной клик по `Sync-Token2.command`.

### Интерактивный процесс работы:
1. **Аутентификация**:
   * Утилита скрытно запросит мастер-пароль от базы KeePassXC (`Master password:`).
   * Если на токене установлен PIN, будет скрытно запрошен PIN токена (`Token2 PIN:`).
2. **Анализ и сводка**:
   * В консоли отобразится форматированная таблица `rich`:
     * Количество занятых слотов на токене (из 300).
     * Количество новых профилей для добавления (`To Add`).
     * Количество измененных/ротированных профилей (`To Update`).
     * Количество устаревших профилей, отсутствующих в базе (`To Delete`).
     * Пропущенные несовместимые профили (`Skipped`).
3. **Выбор режима синхронизации**:
   * `[1] Add Only` — записать на токен только новые ключи, не трогая существующие.
   * `[2] Add & Update` — записать новые и перезаписать обновленные ключи.
   * `[3] Full Sync` — полная синхронизация (добавление новых, обновление измененных и удаление устаревших профилей с запросом подтверждения `[y/N]`).
   * `[4] Cancel` — выйти без внесения изменений на токен.

---

## Проверка и запуск тестов

Для запуска полного набора из 22 автоматических тестов и проверки инварианта Zero-Disk:
```bash
pip install -e ".[dev]"
pytest
bash scripts/manual/verify_zero_disk.sh
```

---

## Архитектура
Интерактивная карта архитектуры доступна в файле [`docs/architecture.html`](docs/architecture.html) (скомпилирована с помощью Archify).
Регламент разработки и критерии приёмки описаны в [CONTRIBUTING.md](CONTRIBUTING.md).
