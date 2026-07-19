# Changelog

## Unreleased

### UI decomposition — stage 8

Protocol and network-service menu presentation is now isolated in `hydra/ui/protocol_menu.py`. Deterministic status rows, selectable options, common navigation entries and runtime-status fallback rendering no longer live inside the monolithic `menus.py` loop. Existing menu entry points and plugin ordering remain unchanged, while the extracted boundary is directly covered by focused tests.

### Runtime reconciliation

`hydra doctor` now reports desired-vs-actual runtime drift and a read-only correction plan. The new `hydra reconcile` command shows the same plan; `hydra reconcile --apply` explicitly applies only safe enable/disable actions and never installs missing components automatically.

`hydra plan` now includes the same reconciliation actions alongside configuration changes and dependency requirements, keeping the complete preflight view side-effect free.

Host boundary completion — production `subprocess.run`/`Popen` calls now pass through the injectable `HostBackend`; nftables, Sing-Box, Caddy/SNI, networking, protocol lifecycle and background service operations use bounded host commands. A regression guard prevents new direct subprocess calls outside the command boundary.

Transactional lifecycle completion — legacy Honeypot, IPBan, Fail2ban, DNSCrypt, Telemt and WARP managers now delegate install/uninstall/enable/disable operations to the orchestrator transaction boundary. Managers no longer mutate plugin runtime directly.

Rollback deduplication — shared state/configuration rollback registration is now provided by `state_transaction`; lifecycle operations keep plugin-specific rollback actions explicit while using one canonical restore ordering.

Plugin contract completion — added typed `PluginCapabilities`, `LifecycleResult` and `HealthResult` models with compatibility adapters for legacy bool/tuple implementations. Registry contract validation now checks every registered plugin without touching the host.

Typed configuration boundary — plugin config and `ConfigFragment` now use recursive JSON types, strict nested validation, serialization helpers and a defensive legacy-dict adapter. Invalid Python-only values are rejected before state persistence or runtime configuration.

Persisted/runtime separation — added immutable `RuntimeSnapshot` and `RuntimePluginState` models. Status, doctor and reconciliation consume live runtime facts without adding runtime snapshots to persisted `state.json`.

State storage hardening — schema migrations now run through an ordered vN→vN+1 registry, future schemas fail closed, backup replacement is atomic, directory entries are fsynced after state replacement, and double corruption preserves a quarantine copy.

### Runtime reconciliation

`hydra doctor` now reports desired-vs-actual runtime drift and a read-only correction plan. The new `hydra reconcile` command shows the same plan; `hydra reconcile --apply` explicitly applies only safe enable/disable actions and never installs missing components automatically.

### P1 architectural foundation

HostBackend — добавлен единый injectable boundary для bounded commands, atomic file writes, systemd и сохранения firewall.
Typed errors — добавлены типизированные ошибки `HydraError`, `HostOperationError`, `ConfigurationError`, `PluginError` и `RestoreError`.
Plugin capabilities — `PluginMeta` теперь может декларативно описывать required commands, services и конфликты; `hydra plan` показывает проблемы зависимостей до применения.
UI decomposition — фоновое определение public IP, GeoIP-флага и системного DNS вынесено из монолитного `menus.py` в отдельный потокобезопасный `network_info.py`.
Log viewer — чтение файловых логов, journalctl и live-follow вынесены в отдельный `log_viewer.py`; публичные внутренние функции меню сохранены для обратной совместимости.
Typed plugin config — `ConfigFragment` вынесен в отдельную типизированную границу и валидируется до генерации Sing-Box/nftables; некорректный вывод плагина теперь останавливает apply с именем виновного плагина.
System monitor — чтение `/proc` и realtime-отрисовка метрик вынесены из `menus.py` в тестируемый `system_monitor.py`; отрицательная скорость после сброса сетевых счётчиков больше не отображается.
DNSCrypt host boundary — установка, systemd lifecycle, статус и атомарная запись конфига переведены на общий `HostBackend`; shell-цепочка установки заменена на отдельные ограниченные по времени команды.
Fail2ban host boundary — plugin и TUI-менеджер используют общий `HostBackend` для fail2ban-client, systemd и iptables с едиными таймаутами.
User application service — добавлен API-агностичный `UserService` для lifecycle-операций пользователей; CLI уже использует эту прослойку, которую смогут переиспользовать REST/API и фоновые задачи.
Protocol application service — каталог, статусы и lifecycle протоколов доступны через `ProtocolService`; основные экраны CLI больше не связывают presentation напрямую с registry/orchestrator.
Honeypot host boundary — lifecycle службы и firewall-команды переведены на общий `HostBackend`; генерируемый runtime-скрипт остаётся самостоятельным изолированным сервисом.
IPBan host boundary — ipset/iptables lifecycle, установка пакета и restore из snapshot используют `HostBackend`; boundary расширен поддержкой stdin и окружения команд.
Apply transaction — rollback Sing-Box, nftables и плагинов формализован через `ApplyTransaction` с явными фазами, приоритетами, at-most-once финализацией и продолжением отката при локальной ошибке.
Plugin transaction — `registry.apply_enabled` использует общий transaction engine; дублирующая реализация rollback удалена, обратный порядок отката плагинов закреплён тестом.
Lifecycle transaction — enable/disable плагинов используют единый rollback-план для обратного hook, восстановления AppState и повторного применения прежней конфигурации.
Install transaction — install/uninstall восстанавливают пакет, enable-hook, AppState и прежнюю конфигурацию при сбое; частично установленный новый плагин очищается.
Reinstall transaction — repair/reinstall получил внешнюю транзакцию поверх uninstall/install и восстанавливает исходный рабочий плагин при сбое повторной установки.
User lifecycle transaction — hooks транспортов при add/remove/block/unblock откатываются вместе с AppState и конфигурацией при неудачном apply.
Desired/actual runtime — статусы плагинов разделяют сохранённое намерение, фактическое состояние, health и drift; UI явно показывает лишний процесс и неизвестное состояние.
Reconciliation service — добавлен безопасный plan/apply слой для устранения drift; missing и unknown состояния только показываются, без автоматической установки или рискованных действий.

### Backup и восстановление

**Добавлен полный безопасный цикл резервного копирования и восстановления.**

Backup — команда `sudo hydra backup` создаёт атомарный архив state, ключей и известных конфигураций сервисов.
Контроль целостности — manifest содержит SHA-256 каждого файла и проверяется до восстановления.
Dry-run — `sudo hydra restore ARCHIVE --dry-run` проверяет архив и показывает план без изменения системы.
Подтверждение — фактическое восстановление требует флага `--yes`.
Защита — запрещены абсолютные пути, path traversal, симлинки и файлы за пределами каталогов HYDRA.
Страховка — перед восстановлением автоматически создаётся резервная копия текущего состояния.
Откат — при ошибке уже записанные файлы возвращаются к предыдущему содержимому.

### Проверка сервера и обновления

Doctor — добавлена read-only команда `sudo hydra doctor` для проверки state, Python, systemd, сетевых инструментов и каталога данных.
Upgrade check — команда `sudo hydra upgrade check` проверяет совместимость state, версию Python и чистоту Git worktree.
Совместимость — добавлен автоматический тест обновления state версии 2.4.0 с сохранением UUID и credentials пользователей.

### CI и релизы

Linux integration — добавлен root-smoke на Ubuntu с реальными systemd, nftables, правами файлов и циклом backup/restore dry-run.
Release workflow — публикация тега `v*` теперь требует зелёных тестов Python 3.10–3.13, совпадения версии и секции CHANGELOG, после чего автоматически создаётся GitHub Release.

## [2.4.1] — 19 июля 2026

### Надёжность применения конфигурации

**Транзакционный оркестратор доведён до production-ready состояния.**

Применение конфигурации:
Блокировка — процесс защищён потоковой и межпроцессной блокировкой.
Журналирование — все действия записываются в `apply.jsonl`.
Контроль запуска — проверяется состояние плагинов после старта.
Снимки состояния — сохраняется конфигурация `nftables` и `Sing-Box`.
Откат изменений — автоматически откатываются частично применённые настройки при ошибке.
Лог сбоев — сохраняется понятная причина последней ошибки для CLI и диагностики.

### Состояние и миграции

**Хранилище `/var/lib/hydra/state.json` стало валидируемым и восстанавливаемым.**

Валидация state — добавлена структурная и семантическая проверка состояния.
Восстановление — повреждённый `state` восстанавливается из `.bak`, а исходный файл сохраняется как `.corrupt`.
Атомарная запись — выполняется через временный файл с принудительным вызовом `fsync`.
Безопасность доступа — файлы состояния, резервных копий и блокировок создаются с правами `0600` на POSIX-системах.
Миграции — сохранены и корректно применяются миграции старых схем состояния.

### Пользователи

**Имя пользователя теперь может быть обычным идентификатором, а email остаётся поддерживаемым вариантом.**

Универсальные имена — идентификаторы вида `test` и `test@example.com` обрабатываются одинаково корректно.
Обратная совместимость — старые записи с email не мигрируются принудительно и продолжают работать.
Стабильные UUID — конфигурации протоколов используют стабильный UUID пользователя.
Безопасность — секреты и credentials не попадают в безопасный CLI-статус.

### Headless CLI и диагностика

Добавлены JSON-команды для автоматизации:

```bash
sudo hydra status
sudo hydra validate
sudo hydra plan
sudo hydra apply --dry-run
sudo hydra apply
sudo hydra user list
```

Разделение статусов — статус-панель разделяет логическое состояние конфигурации и фактическое состояние запущенных сервисов. В частности, статус `DNSCrypt` теперь определяется по `systemd` и по слушающему сокету, поэтому работающий сервис не отображается как выключенный.

### Sync Agent и Sing-Box

Очередь применения — неудачные применения конфигурации ставятся в очередь на следующий цикл.
Защита от параллелизма — добавлена защита от параллельных запусков `Sync Agent`.
Разделение проверок — разделены автоматические проверки лимитов, `WARP` и обновлений.
Ручной режим — полная ручная проверка игнорирует автоматические переключатели.
Обновление Sing-Box — добавлено безопасное обновление `Sing-Box Extended` с preflight-проверкой, резервной копией и откатом.
Исправление версий — исправлено сравнение составных версий `Sing-Box`.
Runtime-константы — кэш `WARP` и журнал `Sync Agent` вынесены в явные runtime-константы.

### Плагины и firewall

Очистка Fail2ban — исправлен бесконечный цикл очистки Portscan-правила Fail2ban (очистка теперь ограничена).
Оптимизация AmneziaWG — метод `configure()` больше не изменяет `state` и не пишет конфигурацию на диск.
Firewall для WDTT — используется общий механизм сохранения firewall-правил вместо собственной дублирующей реализации.
Изоляция тестов — устранены обращения тестов к реальным `/etc`, `/var`, `/run` и `/sys`.
Совместимость протоколов — сохранена совместимость с существующими настройками протоколов.

### Безопасность и эксплуатация

Контроль целостности — усилена проверка загружаемых бинарников и ELF-файлов.
Атомарность конфигураций — конфигурации и `state` записываются атомарно.
Обработка ошибок — улучшена обработка ошибок `systemd`, `downloader` и `firewall`.
Bootstrap-сценарий — `Bootstrap` подготавливает изолированное Python-окружение и команду `hydra`.

### CI и тестирование

Конфигурация окружения — добавлены lock-файлы зависимостей и единая конфигурация `Ruff` / `pytest`.
CI-сценарии — CI проверяет Python 3.10–3.13 на pull request и быстрый smoke-набор на push в `dev` / `main`.
Аудит безопасности — добавлен audit зависимостей.
Результаты тестирования — полный локальный набор успешно пройден (**536 passed**).

### Что не менялось

Файлы состояния — существующие пользовательские state-файлы не удаляются и не переписываются без необходимости.
Протоколы — протоколы и их публичные форматы ссылок не удалялись в этой версии.
Приоритеты версии — изменения направлены на применение, откат, диагностику, безопасность и тестируемость.

---

## [2.4.0] — 18 июля 2026

### Новые транспорты

Добавлены `ShadowTLS v3` + `Trojan`, `Hysteria2` с `Salamander` обфускацией и `Snell v4`; реализованы установка, настройка из TUI, управление пользователями и выдача клиентских конфигураций.

### Подписки и доступ

Расширена генерация конфигураций для `NekoBox` и `Throne`, сохранены цепочки `ShadowTLS` и режим `TrustTunnel QUIC`; блокировка и удаление пользователя теперь немедленно отзывают доступ.

### Мониторинг и маршрутизация

Переработаны экран трафика и просмотр сервисных логов, стабилизирован `traffic_daemon`, добавлен детальный мониторинг пользователей и повтор применения конфигурации после сбоя синхронизации. `qWDTT` интегрирован в общий контур маршрутизации.

### TUI и сеть

Унифицированы экраны управления протоколами и статусы, добавлены пресеты SNI/обфускации, повышена точность VPS-диагностики. Добавлен системный профиль автотюнинга прокси-нагрузки с резервной копией и откатом.

---

## [2.3.5] — 17 июля 2026

Транзакционный цикл — внедрён транзакционный цикл `configure` → `validate` → `apply` → `commit`/`rollback` с межпроцессными блокировками.
Управление портами — исправлено управление портами и удаление правил `UFW` / `iptables`.
Валидация конфигурации — добавлена валидация `nftables` / `Caddy` перед применением.
Учёт трафика — реализован монотонный учёт трафика по `Clash API`.
Интерфейс TUI — в TUI добавлены IEC-единицы и скрытие неактивных пиров `AmneziaWG`.

---

## [2.3.4] — 11 июля 2026

Кастомные профили — добавлена поддержка кастомных `WireGuard` / `AmneziaWG`-профилей `WARP`.
Раздельная маршрутизация — реализован раздельный роутинг списков `WARP`.

---

## [2.3.3] — 9 июля 2026

Защита Fail2ban — добавлены изолированные jail-конфигурации `Fail2ban` и защита приватных подсетей от Portscan.
Обфускация AmneziaWG — в `AmneziaWG` появился мастер настройки обфускации и профиль `low_latency`.
Поддержка Mieru — в `Mieru` добавлены пресеты обфускации и ссылки `mierus://` для `Karing`.

---

## [2.3.2] — 9 июля 2026

Мультиплексор — выполнена миграция мультиплексора с `HAProxy` на `Caddy L4`.
Порты NaiveProxy — разрешены конфликты портов `NaiveProxy`.
Сборка — добавлена кросс-компиляция на `ARM64` / `AMD64`.

---

## [2.0.0] — базовый публичный релиз

Первая помеченная тегом версия проекта. Более ранние изменения сохранены в истории Git и не переписываются задним числом.
