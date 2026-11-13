# Регламент разработки и стандарты проекта

## 1. Роли и зоны ответственности агентов
Проект разрабатывается мультиагентной командой в соответствии со стандартом `Operating Standard: Multi-Agent Software Engineering Lifecycle`:
1. **Developer (Implementation Lead)**: отвечает за минимальный чистый рабочий код (Ponytail), устранение дефектов, соблюдение Zero-Disk-Footprint. Запрещены: спекулятивные функции («отсебятина»), написание приёмочных тестов для своего же кода.
2. **Tester (Independent Test Engineer)**: отвечает за независимую стратегию тестирования, `docs/PRE_RELEASE_CHECKLIST.md`, негативные и хаос-тесты, сбор машинных свидетельств. Запрещено: менять прод-код ради прохождения тестов.
3. **Reviewer (Adversarial Production-Readiness Reviewer)**: независимый аудит качества, безопасности, соответствия ТЗ и синхронизации Archify. Запрещено: аппрув без машинных доказательств и актуальной архитектурной карты.

## 2. Conventional Commits (Обязательно)
Формат: `type(scope): description`
Типы: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`, `build`, `perf`, `revert`.
Примеры:
- `feat(kpxc): add pipe-based in-memory kdbx export`
- `fix(token2): handle PIN retry limit protection`
- `test(diff): add live totp comparison test`

## 3. Версионирование и релизный цикл
- Каждый релиз — отдельная **веха (Milestone)** на GitHub.
- На каждую веху создаётся корневая задача с текстом ТЗ.
- Все рабочие задачи вехи привязываются как дочерние (sub-issues) к корневой задаче ТЗ.
- Прогресс отслеживается на GitHub Project Board.
- Завершение релиза: только после 100% прохождения `docs/PRE_RELEASE_CHECKLIST.md` с фиксацией машинных доказательств, создания аннотированного тега (`git tag -a vX.Y.Z -m "..."`) и пуша в origin.

## 4. Принципы Ponytail (Lazy Senior Dev Mode)
1. Строгое следование YAGNI: не писать код, который не запрошен в ТЗ.
2. Использование стандартной библиотеки Python (`urllib.parse`, `subprocess`, `getpass`, `io.BytesIO`) и готового SDK Token2.
3. Исправление первопричин, а не симптомов.
4. Запрет на сохранение секретов на диск: только оперативная память (`bytearray`), принудительное зануление после использования.

## 5. Работа с памятью (Mnemosyne)
- Перед началом работы или при возникновении вопросов о контексте — запрос в постоянную память (`mnemosyne_recall`).
- Все сложные находки, аппаратные особенности токенов и решения платформенных проблем фиксируются в памяти (`mnemosyne_remember`, `importance >= 0.7`).
- **СТРОЖАЙШЕ ЗАПРЕЩЕНО** дампить, читать или логировать авторизационные токены и пароли. Проверка авторизации — только через высокоуровневые CLI (`gh auth status`).

## 6. Синхронизация архитектуры (Archify)
- Источник истины — `docs/architecture.json`.
- При любых изменениях границ компонентов, CLI-адаптеров, потоков данных схема валидируется и компилируется:
  `/home/viz/.local/bin/node /home/viz/.gemini/config/skills/archify/bin/archify.mjs deliver architecture docs/architecture.json docs/architecture.html --quality showcase`
