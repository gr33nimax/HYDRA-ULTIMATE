# Changelog

- Added the Hydracore debug.23 staged-output contract end to end. Native
  ingestion now accepts `flow_*` records and retains admission-window, KCP
  output depth/capacity, update-backpressure, mutex-wait, physical-write and
  flow-local abort metrics instead of rejecting the complete snapshot.
- Live status now gives one compact KCP-pipeline summary. The full report adds
  per-lane internals, goodput correlations and separate findings for staged
  output saturation, KCP lock contention, slow TURN/DTLS writes and isolated
  ordered-flow aborts.

- Added the Hydracore debug.22 KCP ACK-progress contract: timestamp-matched
  RTT samples, RTT variance, observed ACKs, acknowledged progress and
  in-flight depth are retained, analyzed and shown in detailed lane reports.
- Recovery timeout and full-session escalation are now terminal outcomes
  instead of unresolved lane recoveries. Worker coverage no longer requires
  session-only lane configuration fields, removing the false `partial` result.
- Removed the obsolete debug.21 finding that treated disabled Reno congestion
  control as a fault; debug.22 intentionally uses bounded per-lane queues and
  windows because TURN delay/duplication is not a reliable congestion signal.

- Hydra VK telemetry now ingests Hydracore debug.21's estimated fast-resend
  and RTO retransmission counters, reports their segment/byte split per
  session and per lane, and distinguishes timeout-dominated path pressure from
  fast-resend pressure in findings.
- Live status and full reports now summarize session-wide lane recovery
  attempts, matched reattachments, unresolved recoveries and recovery p95.
  The obsolete zero-valued `Pace` column was replaced with the actionable
  `Fast/RTO` split without adding another wide CLI scenario.

- Added the incompatible Hydracore debug.19 wire-v6 contract: exactly four
  physical VK/TURN calls, TCP flow affinity, aggregate UDP/QUIC striping,
  lossless KCP-to-worker backpressure and staged Android network handover.
  Calls state schema 14 converts the obsolete eight-worker fields back to four
  and quiesces Calls until both endpoints have switched to wire v6.
- Telemetry metadata, CLI rendering and findings now validate IDs 0..3 and the
  `call_vk_four_lane_kcp` capability. The former false "missing lanes 4..7"
  critical and all eight-lane wording were removed.

- Added the intentionally incompatible Hydracore debug.13 wire-v5 contract:
  eight independent KCP lanes, per-lane pre-KCP admission, bounded relay byte
  credit and video-class RTP payload type 96. Calls state schema 13 migrates
  existing four-lane configuration to eight lanes and quiesces enabled Calls
  until the operator switches both sides to the incompatible wire v5 runtime.
- Telemetry now requires and displays each lane's admission pace and RTP
  payload type, reports incomplete lane sets against IDs 0..7, and keeps all
  current client/server lanes visible in live status.

- Added the Hydracore debug.11 `vk_parasite` wire-v4 contract: exactly four
  independent KCP lanes, per-flow distribution with bounded receive reordering,
  and per-lane RTT/RTO, WaitSnd, retransmission, queue and flow telemetry. The
  obsolete transport profile switch was removed from CLI and generated config.
- Fixed `debug` kernel selection when GitHub returns prereleases out of
  publication order. Hydra Ultimate now chooses the newest matching published
  release instead of the first API entry, preventing an older wire-v2 VPS
  binary from being selected ahead of Hydracore debug.10.
- Added the paired Hydracore debug.10 four-call adaptive transport contract.
  Every physical VK/TURN packet now has same-path selective feedback; path
  loss, KCP retry, feedback freshness and control copies are reported as
  separate signals. Live findings use current entities and recent counters,
  so queue drops and backoffs from replaced sessions no longer contaminate the
  active diagnosis. Adaptive peer-read queues default to 512 packets.
  Client and VPS capabilities now require wire v3 exactly, so mixed old/new
  deployments fail closed during the worker handshake.
- Added adaptive VK path-controller telemetry and analysis for Hydracore
  debug.7: per-worker delivered rate, window/in-flight occupancy and backoff
  totals. Live `telemetry status` now shows a compact delivery/window view;
  the detailed report retains wire, network, queue, reconnect and TURN data.
  KCP pending saturation is evaluated against the runtime-reported adaptive
  limit instead of a hard-coded 2048 segments.
- Fixed adaptive VK telemetry ingestion: `multipath_*` session/process records
  are no longer rejected, so wire accounting and native coverage remain
  complete. Live status now hides historical sessions while the full report
  identifies them explicitly. Worker diagnostics distinguish authenticated
  network loss, KCP retry pressure, and post-KCP output-queue delay.
- Fixed live VK telemetry reports racing with newly appended native worker/event
  buckets by analyzing an immutable snapshot of the active timeline tail.
- Fixed the adaptive VK debug.5 throughput regression: the adaptive scheduler
  keeps chunk affinity, alternate-path retries and control priority but no
  longer enables one dynamic KCP congestion window across four independent
  TURN paths. Adaptive server peer queues default to 256 packets while exact
  legacy behavior keeps 128.
- Path retry now uses cumulative attempt/retransmission counters when available.
  KCP retransmission findings compare segment counters only; retransmitted byte
  totals can no longer create a false high-retransmission warning.

Все заметные изменения HYDRA собраны в этом файле. Даты указаны по календарю
релиза; факты старых записей не переписываются задним числом.

Проект использует семантическое версионирование. Полное описание архитектуры и
эксплуатации находится в [`docs/`](docs/); changelog фиксирует только то, что
изменилось между версиями.

**Релизы:** [2.5.5](#255--27-июля-2026) · [2.5.4](#254--26-июля-2026) ·
[2.5.3](#253--24-июля-2026) ·
[2.5.2](#252--21-июля-2026) · [2.5.1-dev](#251-dev--fortress--21-июля-2026) ·
[2.5.0](#250--20-июля-2026) · [2.4.1](#241--19-июля-2026) ·
[2.4.0](#240--18-июля-2026) · [2.3.5](#235--17-июля-2026) ·
[2.3.4](#234--11-июля-2026) · [2.3.3](#233--9-июля-2026) ·
[2.3.2](#232--9-июля-2026) · [2.0.0](#200--базовый-публичный-релиз)

## [Unreleased]

### Обновление

- Updater больше не передаёт шаблонные systemd units вида `name@.service` в
  команды проверки/остановки как конкретную службу. Он обнаруживает реально
  загруженные instances и сохраняет их в `active-units.txt`, поэтому активный
  пул `hydra-headless-creator-vk-calls@*.service` не блокирует обновление и
  корректно восстанавливается после переключения release либо rollback.

### Hydracore / Calls

- Calls now generates only the `vk_parasite` wire-v4 contract with exactly four
  independent KCP lanes. The CLI no longer exposes an A/B transport-profile
  switch; telemetry renders and analyses each lane directly. The exact
  `call_vk_four_lane_kcp` capability is required before activation.

- Нативная Calls-телеметрия разделена на process/session/worker и больше не
  смешивает активного тестера со stale session. CLI `status`, `stop` и `report`
  показывают покрытие, непрерывность, направления KCP, RTT/loss/queues и
  проблемные VK/TURN workers без ручного разбора JSONL.
- Timeline сохраняется полностью в сжатых 8 MiB-сегментах; лимит учитывает
  фактический объём на диске, live tail остаётся доступным, а export прозрачно
  восстанавливает единый JSONL.
- Добавлен изолированный канал ядра `debug`, доступный только для Hydracore.
  CLI и TUI выбирают только prerelease с маркером `-debug.`, не смешивают его
  с `preview`, требуют нативный контракт телеметрии и сохраняют существующие
  digest/config/health проверки с автоматическим rollback.
- Добавлена управляемая оператором техническая телеметрия Hydra VK Tunnel:
  `start/status/tail/mark/report/export/stop`. Таймера завершения нет; сессия
  работает до `stop` либо до защитного лимита данных. Единый append-only timeline
  содержит goodput/lifecycle соединений, ресурсы Hydracore и VPS,
  PSI/softnet/NIC/UDP/conntrack, категории runtime-событий и нативный контракт
  VK/TURN/DTLS/worker/KCP. Отчёт строит p50/p95/p99, фазы, корреляции и findings,
  а export создаёт очищенный `.tar.gz`. Email, IP, destination, token и raw
  connection ID в timeline не пишутся.
- Демон трафика распознаёт runtime inbound `call/...` как протокол `calls`, а
  Hydra VK Tunnel использует общий tracked-источник соединений. Если Hydracore
  передаёт аутентифицированного пользователя в Clash `metadata.user`, байты
  монотонно начисляются общему и per-protocol счётчику этого пользователя.
- Release-контракт Hydracore разделён по ролям: Ultimate загружает только
  `hydracore-vps-linux-{arch}.tar.gz` и проверяет VPS identity, server feature,
  VK-parasite-only режим и wire v4. Android client artifact на VPS
  fail-closed не принимается.
- Calls сохраняет отдельный `public_endpoint`. В административном TUI транспорт
  называется `Hydra VK Tunnel`, а только пользовательский профиль в подписке —
  «Обход БС». Endpoint не зависит от transport SNI.
- Provider-aware kernel status стал единственным источником версии/наличия
  ядра для главного экрана и экрана Sing-Box, поэтому Hydracore больше не
  отображается как «не установлен».

- Клиентские outbounds Calls теперь используют только явно настроенный IP сервера
  или определённый публичный IPv4 VPS; TLS/SNI-домен транспорта больше никогда не
  подставляется как native VK-parasite endpoint.

- Добавлен vendor-neutral desired state ядра и команды `hydra kernel status`
  / `kernel switch`. Hydracore и Sing-Box Extended загружаются только из
  фиксированных репозиториев с обязательным GitHub `asset.digest`, ELF,
  identity/capability, active-config и post-start проверками; binary/state
  транзакция возвращает прежнюю работающую службу при любом сбое.
- Legacy install/update Sing-Box Extended больше не может затереть выбранный
  Hydracore; фоновая проверка обновлений следует provider и channel из state.
- Native VK Calls теперь поддерживает только Hydracore `vk_parasite`: exact
  `call_vk_parasite` создаёт отдельный blue/green пул из 1–4 VK-комнат и
  публикует per-user Hydracore outbound через Hydra Subscription v2. Серверный
  inbound содержит общий obfs key, bounded session/worker/handshake limits и
  O(1) user lookup вместо перебора всех паролей на каждом пакете.
- Multi-user listener использует `56002/udp`, не конфликтуя с qWDTT WireGuard
  на `56001/udp`; worker count ограничен server cap, 27 workers на join-link и
  общим потолком 108.
- Schema state поднята до 11. Чистая `v10 → v11` миграция переводит legacy
  Calls в `vk_parasite`, выключает несовместимый enabled state без удаления
  installed-флага и сохраняет доступность apply для остальных протоколов.
  Повторная установка после явного switch на Hydracore создаёт managed-пул.

### Sing-Box

- Systemd-unit Sing-Box теперь выдаёт `CAP_NET_RAW`, необходимую ядру
  `1.13.16-extended-2.6.x` для повторной привязки исходящего UDP-сокета при
  `auto_detect_interface`. Обновление ядра пересоздаёт unit перед запуском, а
  `hydra apply` обнаруживает старый unit и выполняет полный restart вместо HUP,
  поэтому клиентские UDP DNS-запросы больше не падают с
  `listen udp4 :0: operation not permitted`.
- Обновление ядра больше не завершается без объяснения при ошибке GitHub API,
  проверки нового бинарника, конфигурации или запуска systemd-службы: TUI
  показывает безопасную причину, а транзакция восстанавливает прежний бинарник
  и повторно запускает ранее работавшую службу.
- Перед проверкой нового ядра legacy DNS-конфигурация, сгенерированная HYDRA,
  атомарно переводится на актуальную схему `type/server/domain_resolver`. При
  ошибке проверки или запуска вместе с бинарником восстанавливается исходный
  `/etc/sing-box/config.json`; DNS-фрагменты плагинов не переписываются.

### Зависимости

- `cryptography` обновлена до `50.0.0`, закрывающей `PYSEC-2026-3552`.

### HydraBox

- `?format=hydrabox` переведён с исторического HydraBox Subscription v1 на
  клиент-независимый Hydra Subscription v2: `hydra.io/subscription/v2`,
  `resources[]`, resource-scoped profiles, точные `requested_permissions` и
  требования HydraCore API/remote policy v2. Одинаковые native tags в разных
  resources больше не конфликтуют.
- Flattened `dir`/`A256GCM` JWE приведён к HydraCore v2: обязательный пустой
  `encrypted_key`, `typ=hydra-subscription+jwe`,
  `cty=application/vnd.hydra.subscription+json`, без `kid` в protected header.
  Случайный IV, лимиты 12/16 MiB и отсутствие plaintext fallback сохранены.
- Схема state v6 хранит отдельный приватный 256-битный ключ на пользователя;
  миграция заполняет ключи атомарно, а CLI/TUI умеют немедленно их ротировать.
- HydraBox-запрос требует `HydraBox/<version>` и reported HWID: новый клиент
  использует `X-HWID`, legacy `X-Hydra-HWID: hbx1_…` остаётся совместимым.
  Backend сохраняет только хеш идентификатора и редактированные audit-поля.
  Ошибка контракта — HTTP 400, device limit — 403.
- Генератор выдаёт ключ только во fragment `#hydra-key=…`. Status, логи и
  публичные JSON никогда не содержат ключ или полный HWID.
- Включённый native VK Calls теперь добавляет в подписку отдельный remote-safe
  `call` outbound/profile с `mode=vk_parasite`, `join_links` и core features
  `call`/`call_vk_parasite`, но без VK cookies и singular `join_link` в outbound;
  отсутствие managed-пула отклоняет выдачу fail-closed. qWDTT остаётся только
  ручным общим master-артефактом: Hydra v2 renderer не вызывает его client hook
  и не может опубликовать главный пароль.
- Backend и HydraCore используют общий deterministic AES-GCM test vector v2.

### TUI

- Длинные master-ссылки qWDTT и ссылки подключения Telemt теперь переносятся
  внутри панели без обрезания хвоста многоточием.
- Исправлена UTF-8-разметка действия ротации HydraBox JWE-ключа в меню
  пользователя и связанных подтверждений.

### Ресурсы VPS

- Для всех установок, без отдельного профиля VPS, добавлены общие умеренные
  defaults: `GOGC=50` для Sing-Box и journald budget 128 MiB на диске / 64 MiB
  для runtime-журнала. Жёсткий memory cap не применяется.
- Установка и обновление идемпотентно устанавливают systemd drop-ins, выполняют
  rotate/vacuum старых журналов до 128 MiB и применяют настройки к работающим
  службам.
- AntiDPI объединяет service- и kernel-события в один фильтрованный
  `journalctl -f`, сохраняя прежнюю атрибуцию и убирая второй долгоживущий
  процесс чтения журнала.

### Calls / qWDTT

- Native Calls принимает актуальные VK join-links с полным набором безопасных
  символов URL-сегмента и официальными доменами `vk.com`/`vk.ru`; частично
  записанная строка creator больше не вызывает преждевременную ошибку. Все
  поддержанные варианты ссылки редактируются в HYDRA-логах.
- TUI Headless Creator сведён к установке, qWDTT-подменю и удалению. Статус
  показывает установленность, готовность VK/WB cookies, реальный путь общего
  cookie-файла и число корректных уникальных qWDTT-комнат. В qWDTT-подменю
  доступны создание, остановка, размер пула 1–16, автообновление и интервал.
- Calls и qWDTT переведены на единый typed `CreatorSessionManager`: Calls
  и qWDTT владеют отдельными managed-группами из N сессий, blue/green commit и
  rollback. Новый provider подключается отдельным
  driver без ветвления в consumer-сервисах.
- qWDTT-ссылка формируется из любого настроенного числа уникальных хэшей с
  сохранением порядка и корректным percent-encoding query-параметра; токены с
  `+`, `=`, `%` и `&` больше не искажаются.
- Меню `Calls · VK` использует общий renderer протоколов и оставляет установку,
  атомарную переустановку с пересозданием пула, admin-профиль и удаление;
  отдельные enable/disable и cookie-статусы из него убраны.
- Сборка `wdtt-server` теперь охватывает весь корневой Go-пакет upstream, включая
  вынесенный `admin_api.go`; установка больше не падает с
  `undefined: registerAdminAPIRoutes`.
- Добавлен экспериментальный транспорт `calls`: native VK `call` inbound для
  Hydracore с exact capability gate, транзакционным созданием/ротацией
  managed-пула и admin-only SOCKS joiner profile; stock/P2P fallback отсутствует.
- `ApplicationService.headless_creator` стал независимым владельцем binary,
  provider credentials и creator maintenance. Один `headless-vk-creator`
  создаёт комнаты для native Calls и qWDTT; WDTT отвечает только за
  `qwdtt://`-артефакт.
- В корневом TUI появился отдельный provider-ready экран `Headless Creator`;
  `Calls · VK` теперь управляет только native транспортом. Единственный VK
  cookie-файл — `/etc/hydra/cookiesvk/cookies-vk.json`; native Calls pool хранится
  в `/var/lib/hydra/calls/vk/pool/`, creator runtime вынесен в
  `/var/lib/hydra/headless-creator/`.
- qWDTT rotation стала blue/green: новое поколение
  `hydra-headless-creator-vk@.service` запускается параллельно старому, поэтому
  прежняя master-ссылка остаётся рабочей при timeout или rollback.
- Sync Agent и его TUI читают owner-neutral maintenance facade. Задача creator
  управляется `sync_headless_creator_vk_qwdtt_enabled` и интервалом 1–24 ч.
- Schema state поднята до 9. `v6 → v7` сохраняет совместимость прежнего Calls
  layout, а `v7 → v8` переносит creator state в
  `headless_creator.providers.vk`; `v8 → v9` отделяет qWDTT desired state в
  `headless_creator.consumers.qwdtt` и сохраняет прежний default 4 комнаты.
  Native Calls не включается автоматически;
  старые units/файлы удаляет только явное `Создать комнаты` в qWDTT-подменю со
  snapshot/restore.
- Актуальная qWDTT master-ссылка отображается в TUI в «Ручных конфигах» с явной
  пометкой, что она общая для всех пользователей; в пользовательские подписки
  ссылка с главным паролем не включается.
- VK join-links и полный профиль считаются shared secrets: HYDRA редактирует их
  в status/log projections. Сырой journald остаётся чувствительным, поскольку
  upstream runtime может писать join-links на уровне INFO.

### Подписки

- Добавлен `?format=hydrabox`: сервер отдаёт plaintext HydraBox Subscription v1
  с точным vendor media type, монотонным составным `sequence`, явными
  профилями и remote-safe native Sing-Box `outbounds`/`endpoints`. Генерация
  fail-closed отклоняет duplicate JSON/native tags, циклические или внешние
  ссылки, локальные executable-поля и system WireGuard; расширенные AmneziaWG
  `I1`–`I5`, `J1`–`J3` и `Itime` сохраняются как одноимённые lowercase-поля
  объекта `amnezia`. Технические `PluginMeta.description` больше не попадают в
  имена пользовательских профилей: используются только короткие `display_name`
  или `name`. Renderer revision в младшей части `sequence` гарантирует его
  увеличение при изменении выдаваемого JSON после обновления HYDRA; клиент
  больше не отклоняет такой refresh как same-sequence/different-payload.
  HTTP-ошибка не оставляет частичный ответ.

## [2.5.5] — 27 июля 2026

### Транспорты

- `?format=singbox` больше не теряет AmneziaWG при попытке разобрать нативный
  WireGuard INI как JSON. Desktop и mobile профили экспортируются как отдельные
  `wireguard` endpoints Sing-Box Extended с параметрами `amnezia`, а
  `route.final` указывает на первый доступный AWG endpoint.
- Переключение VLESS + XHTTP из Reality в TLS теперь сразу запрашивает домен и
  атомарно применяет режим, домен и сертификат. Раньше TUI запускал apply без
  домена и неизбежно отвечал «Корректный домен обязателен для vless».
- HYDRA-заглушки теперь сохраняют в `.hydra-decoy.json` SHA-256 исходников
  встроенных рендереров. После обновления шаблона следующий apply атомарно
  публикует новую версию даже при прежних теме и домене; ручные сайты без marker
  по-прежнему не перезаписываются.
- Смена темы заглушки теперь мигрирует встроенные сайты старых установок,
  созданные до появления `.hydra-decoy.json`. Прежние страницы Apex Digital,
  TechBits, HydraDB, Meridian Daily и Northstar Cloud распознаются по строгому
  отпечатку и атомарно заменяются выбранной темой; произвольный сайт оператора
  без marker остаётся нетронутым.
- Интерактивное включение доменных транспортов теперь выполняет установку,
  проверку сертификата и enable как единый application-сценарий. Если certbot
  или выпуск сертификата завершается ошибкой, введённый домен откатывается и
  его можно сразу задать заново; уже завершённая установка плагина сохраняется.
- У установленного, но выключенного NaiveProxy доступно меню домена и
  транспорта. Домен можно исправить до повторной активации.
- Mieru больше не публикует одновременно `listen_port: 2012` и пересекающийся
  `listen_ports: 2012-2022`; сервер и `mierus://` используют один канонический
  диапазон.

### WARP

- Установка локального WGCF больше не считается неуспешной, если профиль уже
  создан, но необязательная предварительная загрузка внешних списков временно
  недоступна. Ошибка `register`/`generate` показывается в TUI вместе с
  redacted-деталями из `warp_install.log`.
- Экран WARP отличает настроенные профили и маршруты от фактически активных.
  Назначение списка на отсутствующий outbound (например, `GoogleAI → warp` без
  локального WGCF-профиля) больше не отбрасывается с неявным direct fallback:
  общий apply отклоняет такую конфигурацию с точным именем назначения.

### Пользователи и устройства

- Подписка распознаёт Shadowrocket по `User-Agent` и поддерживает явный формат
  `format=shadowrocket`. TCP-профиль NaiveProxy выдаётся в нативном виде
  `https://<url-safe-base64(user:password@host:port)>?remarks=<имя>` без
  padding; несовместимый `naive+https://` в этот список больше не попадает.
- TUI выводит клиентские URI и конфигурации отдельными строками без рамок,
  отступов и ANSI-кодов, поэтому копирование из SSH-терминала не добавляет
  пробелы и символы панели.
- Ссылки подписки показываются только после запуска `hydra-sub` и наличия пары
  HTTPS-сертификата и ключа. До готовности серверного endpoint TUI показывает
  точную причину вместо заведомо нерабочих URL.
- Сроки подписок в RFC 3339 с суффиксом `Z` одинаково распознаются на Python
  3.10–3.13; Python 3.10 больше не показывает валидную UTC-дату как ошибочную.
- Резервный отпечаток клиента без HWID больше не зависит от IP: смена мобильной
  сети или Wi-Fi не создаёт новую запись. Старые дубли с одинаковым
  `User-Agent` лениво объединяются при следующем запросе подписки с сохранением
  времени первого обращения.
- VLESS за Caddy передаёт внешний адрес через точный PROXY v2 source-relay.
  Демон трафика восстанавливает его по source port, поэтому экран сессий и
  одновременный лимит устройств больше не принимают `127.0.0.1` за устройство.
  Для старого runtime loopback отображается как внутренний адрес
  мультиплексора, а не как клиент.

### Обновление

- Чистая установка заранее устанавливает системный `certbot`; резервная
  установка при первой TLS-активации нормализует timeout и ошибки хоста вместо
  зависания или выхода из TUI.
- Launcher и транзакционный updater получили единый аккуратный вывод:
  UTF-8 locale, нумерованные этапы, понятные русские ошибки, цветные статусы в
  терминале и финальную сводку с веткой, переходом, снимком отката и логом.
  При перенаправлении вывода и с `NO_COLOR` ANSI-последовательности не
  используются.
- Публичные `bootstrap.sh`, `updater.sh` и `upgrade.sh`, команды в документации
  и regression-тесты переведены на ветку `main` по умолчанию. Явный
  `HYDRA_REF` по-прежнему позволяет проверить другую ветку.
- Перед promotion объединено исправление восстановления `caddy-l4.service` из
  `main` с новым updater из `dev`; rollback сохраняет state, код, wrapper и
  ранее активные службы.

### Документация

- Версия проекта поднята до 2.5.5. Пустой заголовок обзорной таблицы README
  заменён на семантическую HTML-разметку без лишней строки в GitHub.
- README ветки `dev` снова ведёт на `dev`: CI badge, bootstrap и updater
  используют канал разработки, а команды явно передают `HYDRA_REF=dev`,
  поэтому launcher не переключается обратно на `main`.

## [2.5.4] — 26 июля 2026

### Транспорты

- Добавлен встроенный `vless` transport на базе VLESS + XHTTP из
  `shtorm-7/sing-box-extended`: VK-parasite inbound, Sing-Box client config,
  `vless://` ссылки и выдача через общие подписки.
- VLESS + XHTTP требует отдельный TLS-домен. Caddy L4 направляет настроенный
  XHTTP-путь во внутренний Sing-Box, а остальные URL обслуживает собственный
  сайт-заглушка `/var/www/decoy-vless` в виде нейтрального цифрового издания.
- Активация VLESS теперь завершается успешно только после проверки фактического
  SNI-маршрута, загруженной Caddy пары cert/key и локального TLS handshake с
  ALPN `h2`; неполный runtime откатывается вместо ложного успешного статуса.
- Транспорт VLESS + XHTTP стал настраиваемым: паддинг, размер и число
  upload-пакетов, длительность stream-up, лимит заголовков запроса, SSE-заголовок
  и до 16 собственных HTTP-заголовков. Значения по умолчанию не изменились,
  каждая правка проходит валидацию и общий транзакционный apply.
- Добавлены профили транспорта XHTTP `balanced`, `low_latency` и `stealth`:
  одна команда согласованно выставляет режим и весь набор параметров, а их
  описания перечисляют фактические значения. Профиль и сводка тюнинга видны
  в статусе плагина и в TUI.
- VLESS получил режим Reality поверх XHTTP: команда `set_security` создаёт
  пару ключей и short_id, объявляет SNI-проброс через Caddy L4 вместо
  маршрута с сертификатом и снимает требование домена. Sing-Box сам
  завершает TLS, повторяя рукопожатие стороннего сайта; клиенты получают
  ссылки вида `security=reality&pbk=&sid=&fp=` на публичный IP сервера.
- Caddy L4 научился декларативному маршруту `tls_passthrough`: плагин
  объявляет SNI и внутренний порт, мультиплексор отдаёт соединение целиком,
  не разбирая TLS и не требуя сертификата.
- Исправлено переключение VLESS + XHTTP с собственного TLS-домена на Reality:
  подготовка конфигурации больше не возвращает удалённый decoy-маршрут, а сбой
  перестройки Caddy запускает полный rollback и перезагрузку восстановленного
  Sing-Box вместо нерабочего частично применённого runtime.
- Reality-ссылки и клиентские профили теперь используют обнаруженный публичный
  IP, когда он не сохранён в `network.server_ip`; та же проверка применяется
  при включении, а ошибка переустановки остаётся в VLESS-меню вместо сбоя TUI.
- Приватный ключ Reality никогда не попадает в статус, ссылки и профили;
  публичный ключ и short_id показываются оператору в экране протокола.
- VLESS + XHTTP получил отдельный TUI-экран по образцу AnyTLS: runtime-статус,
  клиенты, текущий профиль и прямой выбор профиля доступны на верхнем уровне,
  а домен, path, mode и тонкий тюнинг сохранены в расширенных настройках.
- Команды `plugin command vless set_tuning` и `set_preset`, а также query
  `plugin query vless get_tuning` доступны в CLI и TUI.
  Клиентская ссылка получает параметр `extra` только когда параметры отличаются
  от значений по умолчанию, поэтому старые ссылки не меняются.
- Сайты-заглушки стали выбираемыми и уникальными для каждой установки. К пяти
  существующим темам добавлены `portfolio`, `shop`, `apidocs`, `conference`,
  `gallery` и `cafe`; бренд, палитра, шрифт, тексты и favicon детерминированно
  выводятся из домена, поэтому две установки не отдают одинаковый HTML, а
  повторная генерация того же домена воспроизводима.
- Тему заглушки выбирает оператор: команда `set_decoy_theme` у `naive`,
  `anytls`, `trusttunnel`, `hysteria2` и `vless`, вопрос при первом включении
  протокола и пункт в его меню. Прежние темы остались значениями по умолчанию.
- Смена темы перегенерирует сайт и атомарно подменяет каталог; каталог помечен
  файлом `.hydra-decoy.json` с темой, доменом и отпечатком идентичности. Сайт
  без этой пометки считается размещённым оператором и не перезаписывается.
- Добавлен параметр `utls_fingerprint` для VLESS: клиентский профиль получает
  блок `tls.utls`, ссылка — `fp=`. По умолчанию `none`, поэтому существующие
  ссылки не меняются.
- Учёт трафика VLESS + XHTTP теперь сопоставляет соединение Clash API с
  аутентифицированным пользователем по journal context и source port; байты
  записываются в общий счётчик и `credentials["vless"]`.
- Plugin-owned TLS/HTTP routes стали декларативными: core валидирует порты,
  путь, каталог и тему, включает их в транзакционный Caddy apply/rollback и
  очищает динамические loopback firewall rules при остановке.

### Пользователи и устройства

- Исправлен сбой TUI с `StateConflictError` после неудачной команды плагина.
  Сессии устройств, отчёт о сертификатах и источник отложенного применения
  считались желаемой конфигурацией, поэтому фоновая запись раз в две секунды
  увеличивала ревизию и делала открытое меню устаревшим.
- Откат неудачной команды больше не падает из-за чужой записи: снимок
  восстанавливается поверх текущего состояния, сохраняя фоновые счётчики.
  Экран настроек VLESS сообщает о конкурентном изменении текстом, а причину
  неудачного применения берёт из `apply_error()`.

- Сервер подписок узнаёт настоящий адрес клиента: за мультиплексором Caddy
  передаёт PROXY v2, и запись об устройстве больше не содержит `127.0.0.1`.
  Раньше клиенты без HWID сливались в одно устройство, потому что отпечаток
  строился из адреса мультиплексора и User-Agent.
- Исправлен TLS accept-path сервера подписок за Caddy: PROXY v2 теперь
  разбирается на сыром соединении до TLS handshake. Раньше `hydra-sub` пытался
  прочитать заголовок уже из `SSLSocket`, закрывал соединение и клиент получал
  `Connection closed`, хотя systemd-служба оставалась active.
- Экран «Трафик протокола» показывает учтённые байты и для транспортов без
  собственных счётчиков: базовый плагин отдаёт то, что записал демон трафика
  под именем протокола. VLESS показывал «трафик ещё не учтён» при работающем
  учёте.
- Транспорт называется просто VLESS во всех экранах.

- Лимит устройств теперь ограничивает одновременные подключения, а не только
  выдачу подписки: демон трафика группирует активные соединения по адресу
  источника и закрывает через Clash API те, что принадлежат устройствам сверх
  лимита. Раньше клиент, один раз получивший конфиг, подключался без ограничений.
- Приоритет у подключившихся раньше: новое устройство сверх лимита получает
  отказ, а установленные сессии не рвутся. Короткий разрыв связи не считается
  новым устройством — сессия помнится 10 минут.
- Запись об устройстве вместо одной метки времени хранит первое и последнее
  обращение, источник идентификатора (заголовок HWID или определение по адресу
  и клиенту), `User-Agent` и адрес. Схема state поднята до 5 с миграцией.
- В карточке пользователя появился экран «Устройства»: зарегистрированные
  устройства с HWID-префиксом и клиентом, активные сессии с адресом, трафиком и
  пометкой сверх лимита, изменение лимита и сброс привязок в одном месте.
- В мониторинге появился раздел «Устройства и сессии», а на обзорном экране —
  строка с числом онлайн-устройств и нарушителей лимита.
- `hydra user show` и `--json` отдают список устройств; полный идентификатор не
  публикуется, только префикс.
- Вкладка «Клиенты» на экранах протоколов заменена на «Трафик протокола»:
  подключённые клиенты дублировали данные устройств, персональный учёт трафика
  сохранён.

### Обслуживание

- Sync agent раз в сутки проверяет сроки всех настроенных TLS-сертификатов:
  протоколы с собственным доменом, домен сети и домен подписок. Проверка
  read-only и опирается на `openssl x509 -enddate`.
- Истёкший, истекающий в ближайшие 30 дней или отсутствующий сертификат ставит
  отложенное применение конфигурации, поэтому существующий preflight
  переполучает материал через certbot без отдельного пути обновления.
- Сертификат сервера подписок теперь тоже продлевается автоматически: общий
  preflight его не касается, поэтому проверка вызывает выпуск напрямую и
  перезапускает `hydra-sub`. Раньше он обновлялся только вручную из TUI.
- Неудачное продление больше не повторяется каждые 5 минут: отложенное
  применение, поставленное проверкой сертификатов, снимается после первой
  неудачи и ждёт следующей суточной проверки. Отложенные применения из других
  фаз повторяются как прежде.
- Результат проверки сохраняется в state (`certificates_last_check`,
  `certificates_report`) и выводится в `hydra status` блоком `certificates`;
  проверку можно выключить флагом `sync_certificates_enabled`.

### Архитектура

- Монолитные composition/lifecycle/UI-модули разделены на application services,
  инфраструктурные адаптеры, нейтральные contracts и тонкие compatibility
  facade. Добавлены автоматические границы зависимостей, лимиты размеров
  модулей и функций и графовые проверки связности.
- Удалены process-global service locator и прямые вызовы concrete plugins из
  UI, Telegram и manager-слоя. Плагины подключаются через instance-scoped
  `PluginContainer`, явные порты и единый транзакционный lifecycle.
- Backup inventory расширяется декларациями плагинов без импорта registry из
  core. Удаление HYDRA также проходит через application boundary.
- Долгоживущие systemd units используют стабильный `/opt/hydra` и его `.venv`,
  поэтому release-каталоги можно атомарно переключать без закрепления старого
  физического пути.
- Headless CLI сведён к операторскому циклу `status` → `check` → `apply`.
  Validation, doctor, plan и reconciliation объединены в один read-only
  preflight и скрыты из основной справки; старые формы сохранены как алиасы.
  Добавлены metadata-driven inventory/lifecycle/command/query/action плагинов,
  `backup inspect`, `user show`, TTY-aware таблицы и сводки, явный `--json`,
  компактный JSON и JSON-ошибки синтаксиса.
  Системные проверки и migration вызываются через application-level ports.

### AntiDPI — покрытие VLESS

- AntiDPI отслеживает VLESS + XHTTP. Улики берутся из access-лога decoy того же
  домена, где Caddy уже восстановил реальный IP клиента через PROXY v2:
  отклонённый запрос к XHTTP-пути даёт `auth_failure`, scanner path на домене —
  `active_decoy_probe`. Успешные запросы и ошибки backend (5xx) уликами не
  считаются.
- Домен и путь читаются из конфигурации плагина и перечитываются каждые
  60 секунд; записи чужих доменов из общего лога не затрагиваются.
- Добавлен разбор отказов `inbound/vless[...]` в журнале sing-box с извлечением
  peer port и покрытие VLESS в `hydra antidpi selftest`.

### AntiDPI — логика детекции

- Повторы одного сигнала насыщаются: каждое следующее одинаковое событие в окне
  15 минут добавляет вдвое меньше предыдущего. Три опечатки в пароле больше не
  дают бан на все порты VPS, а непрерывный подбор по-прежнему блокируется
  (≈23 попытки при частоте раз в секунду).
- Для бана нужны улики двух разных семейств; улики одного типа обязаны набрать
  полуторный порог. Решающие сигналы (обращение к decoy, перебор портов)
  по-прежнему банят сами по себе, по собственному весу.
- Ранее забаненные адреса достигают порога быстрее: −1 за каждое нарушение,
  но не ниже 4.
- Улики агрегируются по подсетям `/24` и `/48`: 4 и более адресов в окне
  10 минут дают уведомление `COORDINATED`. Агрегат намеренно не банит подсеть,
  чтобы не отключить всех клиентов за общим NAT.
- Оповещения и экраны показывают требуемый порог, семейства улик и причину,
  по которой адрес ещё не заблокирован.

### AntiDPI

- Добавление сети в whitelist теперь снимает активные баны, которые эта сеть
  накрывает: адрес удаляется из ipset и из evidence, а не остаётся
  заблокированным до истечения ipset-timeout.
- Память прогрессивной эскалации (`ban_counts`) больше не растёт бесконечно: она
  очищается вместе с объясняющей её записью ban history.
- Отказ firewall при пересечении порога бана фиксируется в state и выводится в
  TUI и Telegram. Раньше детектор, работающий отдельной службой, терял этот факт.
- `management_snapshot` возвращает ограниченную проекцию оператора вместо
  глубокой копии всего state: активные баны с готовыми подписями, watchlist,
  переведённые счётчики и момент снимка. Экраны больше не копируют до 20 000
  score-записей на каждое обновление.
- TUI-экран AntiDPI переработан: состояние healthcheck с расшифровкой
  неисправных проверок, список банов с остатком срока и причиной на русском,
  раздел «Под наблюдением» для улик ниже порога бана, статистика сигналов и
  источников, ручная бессрочная блокировка, разбан по номеру или адресу и запуск
  локальной диагностики. Длинные IPv6-адреса больше не обрезаются.
- Telegram-дашборд AntiDPI показывает GeoIP/ASN, остаток срока, причину на
  русском и watchlist; кнопки разбана подписаны остатком срока, а кнопка
  `🧾 Подробнее` открывает детальный вид со счётчиками сигналов и источников.
  Обе поверхности используют один словарь формулировок, поэтому больше не
  расходятся в терминах.

### Telegram-бот

- Экраны получили граф: `⬅️` ведёт к родителю, а не в главное меню, `🔄` не
  теряет номер страницы, с вложенных экранов доступен `🏠 Меню`. Роутинг
  callback-ов заменён разбором `view:<экран>[:<страница>]` вместо цепочки
  сравнений строк.
- Списки блокировок, наблюдения и уловов honeypot листаются постранично; раньше
  они молча обрезались на 5–12 записях без способа досмотреть остальное.
- Добавлена карточка адреса: GeoIP/ASN, статус в AntiDPI с остатком срока и
  причиной, статус в Honeypot, кнопки блокировки и разблокировки. Открывается
  строкой списка или простой отправкой IP сообщением.
- Неизвестная команда больше не отвечает главным меню, а ошибки построения
  экрана показываются оператору вместо молчания.
- Уведомления: режим «только блокировки» и тихие часы с окном через полночь.
  Пропускаются только события с применённым действием или отказом защиты;
  выключенная категория остаётся сильнее обоих фильтров.
- Мониторы fail2ban и honeypot перестали спавнить два `journalctl` в секунду:
  опрос замедляется до 15 секунд на тихом хосте и возвращается к 2 секундам
  сразу после новой строки.

### Совместимость и состояние

- В `TelegramConfig` добавлены `notify_only_blocks`, `quiet_hours_enabled`,
  `quiet_hours_start` и `quiet_hours_end` со значениями по умолчанию —
  существующий state читается без миграции.
- Версия persisted state поднята с 3 до 4. Миграция 2→3 сохранена в точности как
  выпущенная в 2.5.3; миграция 3→4 переносит legacy-флаги WARP, DNSCrypt и
  security plugins в канонический `protocols` и добавляет revision.
- Миграция проверена на полном fixture 2.5.3: сохраняются лимиты и отпечатки
  устройств, credentials, Telegram-настройки, сетевые секреты и plugin config.
- Регистрация устройств подписки выполняется атомарно; stale TUI/daemon saves
  не стирают новые bindings, а явный reset остаётся авторитетным.
- Старые module entrypoints subscription server и sync agent сохранены как
  исполняемые compatibility facade для уже установленных systemd units.

### Обновление рабочей VPS

- Dev-entrypoints согласованы по ветке: `dev/bootstrap.sh`, `dev/updater.sh` и
  транзакционный `upgrade.sh` теперь без дополнительных переменных выбирают
  `dev`; URL установщика больше не переключает установку молча на `main`.
- Добавлен публичный `updater.sh`: обновление запускается одной командой,
  launcher полностью скачивает транзакционное ядро до исполнения и удаляет
  временный файл после завершения.
- Вывод `bootstrap.sh`, `updater.sh` и `upgrade.sh` унифицирован: нумерованные
  этапы, явный итог `ГОТОВО`/`ОШИБКА`, команда следующего действия и путь к
  журналу или снимку отката.
- Добавлен `upgrade.sh` для транзакционного перехода существующей установки на
  точный SHA ветки `dev`: отдельный release и `.venv`, read-only preflight,
  quiesce HYDRA-служб, два уровня backup, атомарная миграция state, проверка
  systemd и автоматический откат state/code/wrapper/services.
- Исправлен откат updater для TLS/SNI-установок: активный `caddy-l4.service`
  теперь входит в quiesce-снимок и гарантированно запускается после переключения
  либо отката. Проверка state при остановленных службах больше не зависит от
  runtime health, а сообщение об ошибке указывает конкретную операцию и её
  JSON-отчёт.
- Добавлены `hydra upgrade migrate-state`, Linux integration-сценарий
  main→dev и руководство [`docs/UPGRADE.md`](docs/UPGRADE.md).
- `bootstrap.sh` остаётся установщиком новой VPS и больше не является
  рекомендуемым способом обновления действующей установки.

### TLS-транспорты

- Исправлена установка ShadowTLS: внутренний Trojan inbound теперь создаётся как
  injectable detour без фиктивного `listen_port: 0`, поэтому конфигурация проходит
  общую валидацию и принимается Sing-Box.
- Восстановлен интерактивный запрос домена при включении NaiveProxy, AnyTLS,
  TrustTunnel и Hysteria2.
- Перед каждым применением конфигурации сертификаты включённых TLS-транспортов
  проверяются на домен, срок действия и соответствие приватному ключу.
  Некорректная сохранённая пара заменяется через certbot.
- Удалены посторонние legacy-пути сертификатов. Caddy больше не получает
  TLS-маршрут без полной пары сертификата и ключа, а TCP-профиль TrustTunnel
  явно фиксирует ALPN `h2`.

### Документация

- `README.md` переработан в обзорную витрину: что даёт система, инвентарь
  модулей, установка, обновление, структура проекта и указатели на документы.
- Подробности перенесены к профильным документам без потери содержания:
  мотивация модели и границы версии — в `ARCHITECTURE.md`, эксплуатационные
  сценарии (безопасный порядок изменения, восстановление, диагностика) и
  семантика лимитов пользователей — в `CLI.md`, описание заглушек доменных
  транспортов — в `REFERENCE.md`, локальные проверки и матрица CI — в
  `PLUGIN_DEVELOPMENT.md`.

### Сохранённая функциональность 2.5.3

- Перенесены без потерь device limits, rename/default user, uninstall, SNI
  preflight, WARP RU/IDN lists, Fail2ban whitelist, AntiDPI alert-only probes и
  транзакционные исправления Telemt.

## [2.5.3] — 24 июля 2026

### Пользователи и обслуживание

- Добавлены переименование пользователя без ротации UUID/секретов и
  настраиваемый лимит устройств на подписку. HWID хранится только в виде
  SHA-256; привязки можно сбросить из TUI или CLI.
- Чистая установка автоматически создаёт первого пользователя `default`.
- Добавлена команда полного удаления `hydra uninstall` с обязательным
  подтверждением `--yes`, режимом предварительного просмотра `--dry-run` и
  опцией сохранения данных `--keep-data`.

### Сеть и безопасность

- TLS ping/config-тесты Karing с парой `unknown_sni + handshake_failure`
  переведены в alert-only и больше не могут автоматически заблокировать IP.
- TUI Fail2ban показывает фактический `ignoreip`, включая адрес установочной
  SSH-сессии, автоматически записанный в `00-hydra-defaults.local`.
- Проверка SNI разрешает общий домен для TCP/QUIC-режимов одного протокола,
  сохраняя конфликт между разными протоколами.
- WARP заранее загружает все встроенные внешние списки при установке; RU-
  маршрутизация включает `.su`, `.ru`, `.рф` и `.xn--p1ai`.

### Telemt

- Исправлена ложная ошибка сразу после загрузки бинарника: Telemt больше не
  помечается включённым до окончания транзакционной установки.
- Установка восстанавливает отсутствующий systemd unit, конфигурация
  применяется через стабильный restart с проверкой активности, а настроенные
  iOS-фикс и SYN-limiter автоматически восстанавливают правила.

## [2.5.2] — 21 июля 2026

### Чистая установка и bootstrap

- Certbot для домена подписок теперь освобождает порт 80 также от Caddy L4,
  временно открывает firewall и гарантированно восстанавливает остановленные
  веб-службы даже при исключении.
- Первая сборка qWDTT больше не обрывается общим 30-секундным таймаутом:
  загрузке Go-модулей разрешено до 10 минут, а `go build` — до 15 минут,
  что учитывает пустой module/build cache на чистой VPS.
- Release-bootstrap по умолчанию загружает ветку `main`. Ветка из
  `HYDRA_REF` сначала разрешается в точный remote SHA; Git update, clone и
  архивный fallback устанавливают именно этот commit. До установки Python-
  зависимостей bootstrap сверяет фактический `HEAD`/маркер архива с
  выбранным SHA и останавливается при любом расхождении.
- Исправлена однострочная команда: bootstrap запускается через
  `curl ... | sudo bash` и не требует Bash process substitution.
- Для ручного `git clone` задокументирован запуск через `.venv` с
  установкой `requirements.lock`. Это устраняет ошибку
  `No module named 'qrcode'` и не смешивает зависимости HYDRA с системным
  Python. Bootstrap явно сообщает о созданной команде `sudo hydra`;
  простой clone сам по себе launcher в `/usr/local/bin` не создаёт.

### AnyTLS, Caddy L4 и состояние

- Чистая система больше не падает на сборке Caddy L4: checksum
  закреплённой версии Go ищется в полном списке релизов, а таймаут
  `xcaddy build` увеличен с 30 до 900 секунд для пустого Go module cache.
- Исправлен ложный rollback AnyTLS и Mieru: healthcheck больше не читает
  устаревший state во время транзакции.
- TUI перечитывает state после возврата из вложенных меню и больше не
  показывает только что установленный протокол выключенным.
- Исправлена десериализация `state.json`: ошибка разрешения type hints
  больше не превращала валидный `PluginState(enabled=true, installed=true)` в
  пустой объект со значениями по умолчанию.
- Status AnyTLS теперь совмещает сохранённые `installed/enabled` с
  фактическим наличием Sing-Box, а не считает любой Sing-Box
  доказательством установки AnyTLS.
- Получение сертифика NaiveProxy больше не падает с `Could not bind TCP
  port 80`, если `:80` занят уже установленным Caddy L4. Naive теперь
  временно останавливает активные `caddy-l4`, `caddy-naive`, Nginx и Apache,
  проверяет успех остановки и гарантированно восстанавливает их после Certbot,
  включая аварийный выход.

### AmneziaWG и AntiDPI

- Новая установка AmneziaWG передаёт внешнему инсталлятору адрес
  `10.67.67.1`, поэтому первый профиль создаётся в `10.67.67.0/24` и не
  пересекается с qWDTT. Существующие `awg0.conf` при обновлении не мигрируют.
- Выключение AntiDPI теперь удаляет глобальные IPv4/IPv6 DROP-правила. Ранее
  служба и сбор событий отключались, но адреса из `hydra_antidpi` продолжали
  блокироваться, из-за чего TUI показывал «выкл», а SSH оставался недоступен.
- AmneziaWG проверяет загрузку kernel module как при установке, так и
  при включении. Если DKMS собрал модуль для нового ядра, а VPS ещё
  запущена на старом, TUI показывает оба ядра и требуемую перезагрузку
  вместо безликой «Ошибки применения».
- Fallback-запуск `awg-quick` больше не проглатывает stderr; status
  AmneziaWG сверяет runtime с state, а восстановление профиля не
  переиспользует уже занятую подсеть.
- При обновлении старой установки AmneziaWG больше не пытается
  разобрать транспортные значения `network=both/quic/tcp` других протоколов
  как IP-подсети. Это устраняет ошибку `'both' does not appear to be an IPv4 or IPv6
  network` при `hydra apply`; невалидные legacy-значения теперь игнорируются.
- Обычный `hydra apply` больше не меняет подсеть уже существующего
  `awg0.conf`. Ранее штатная сеть старой установки `10.66.66.0/24` могла
  быть молча заменена на `10.67.67.0/24`, что ломало все ранее экспортированные
  PC-профили. Теперь автовыбор сети выполняется только при создании нового
  профиля, а сеть установленного интерфейса остаётся неизменной.
- AntiDPI больше не считает штатные junk-пакеты AmneziaWG
  ошибками handshake; noisy debug path отключён, а rejection-события
  остаются доступными.
- В AntiDPI ALERT добавлена кнопка ручной блокировки IP с проверкой
  Telegram-администратора, whitelist и штатным progressive ban.

### WARP/WGCF и общий загрузчик

- Загрузчик закрывает writable-дескриптор, возвращённый `mkstemp`, до
  атомарного перемещения бинарника. Это устраняет
  `[Errno 26] Text file busy` при первом `wgcf register` и утечку дескрипторов
  во всех скачиваниях через общий helper.

### Благодарность

Отдельная благодарность **@Monah99** за помощь в тестировании и
предоставление VPS.

## [2.5.1-dev] — «FORTRESS» — 21 июля 2026

### Исправления применения конфигурации

- Исправлен ложный rollback при включении AnyTLS и Mieru: healthcheck теперь
  проверяет активный Sing-Box и inbound в применяемом конфиге, не перечитывая
  устаревший флаг `enabled` из сохранённого state во время транзакции.
- TUI перечитывает state после возврата из вложенных меню и после операций
  AnyTLS, не позволяя старому снимку повторно показать или сохранить протокол
  выключенным после успешного commit.

### Новый модуль AntiDPI

Добавлен самостоятельный плагин `antidpi` — поведенческий IDS/IPS-контур для
обнаружения протокольных зондов, неправильной авторизации, malformed handshake,
decoy probes, connection burst и сканирования портов. Он не расшифровывает
пользовательский трафик и не заменяет Fail2ban: модуль нормализует доказательства
из Caddy, Sing-Box, kernel journal и нативных журналов протоколов, после чего
применяет единую scoring-политику.

Архитектурно разделены три независимые зоны ответственности:

- Fail2ban — SSH и подтверждённые auth-журналы;
- Honeypot — отдельная ловушка, собственное состояние и собственные баны;
- AntiDPI — сетевые и протокольные аномалии на всей поверхности VPS.

### Архитектура FORTRESS

- Добавлен долгоживущий сервис `hydra-antidpi`, читающий Caddy JSONL,
  `journald`, kernel LOG и нативные журналы протоколов.
- Добавлен `hydra-source-relay` с обязательным PROXY Protocol v2 и точным
  сопоставлением relay source port внешнему IPv4/IPv6. Это сохраняет реальный
  источник для TCP и QUIC backend даже после loopback-проксирования.
- Для ошибок без endpoint разрешена только ambiguity-safe корреляция: адрес
  используется, если в коротком окне присутствует единственный кандидат.
- Для AmneziaWG включается ограниченный dynamic-debug нативных rejection paths:
  `Invalid MAC`, `Invalid handshake` и `unknown peer`. Штатные AWG junk-пакеты
  из `Jc` исключены: `prepare_awg_message` принудительно выключен, а его
  `Unknown message` больше не считается ошибкой handshake.
- Из Fail2ban удалён исполняемый legacy протокольных плагинов; сохранён только
  миграционный cleanup старых jail/filter и portscan rule. Cleanup прежнего AWG
  unit больше не отключает rejection logging, принадлежащий AntiDPI.
- Caddy decoy получил отдельную access-телеметрию с сохранением внешнего IP.
- Созданы динамические ipset `hydra_antidpi` и `hydra_antidpi6`; только они
  выполняют enforcement. Телеметрические iptables/ip6tables-правила используют
  `LOG`, а не `DROP`.
- Активные баны восстанавливаются после перезапуска с оставшимся TTL.

### Политики обнаружения и блокировки

- Введены два счётчика: `Observed score` для всех сигналов и `Verified score`
  только для доказательств, которым разрешено влиять на бан.
- Score экспоненциально затухает с half-life 5 минут; старые события не могут
  сформировать позднюю блокировку.
- Обычный ALERT создаётся при observed score `6`, явный `auth_failure` — при `3`.
- BAN разрешён только при verified score `8` и свежем подтверждённом
  протокольном событии либо подтверждённом multi-port sweep.
- Сроки бана прогрессивные: 10 минут, 1 час, 24 часа, затем 7 дней.
- Telegram cooldown действует отдельно для каждого IP и протокола, поэтому
  событие Naive больше не подавляет последующие AWG, Hysteria2 или qWDTT alerts.
- Дублирующиеся browser sockets для одного unknown-SNI события объединяются.
- Встроенный whitelist исключает loopback, link-local, RFC1918, ULA, IP самой
  VPS и пользовательские сети.

### UDP spoof-safety

Прямые UDP-сигналы Hysteria2, AmneziaWG и qWDTT считаются наблюдаемыми, но не
ban-eligible. Они формируют технический ALERT с политикой
`alert-only / unverified UDP source`, однако не увеличивают verified score и не
могут подготовить будущий бан другому протоколу. Naive QUIC и TrustTunnel QUIC
могут стать ban-eligible только после точной атрибуции через source relay и
прикладного auth-события.

### Покрытие протоколов

Детекторы добавлены для TLS/Caddy L4, HTTPS decoy, AnyTLS, TrustTunnel TCP/QUIC,
ShadowTLS, Naive TCP/QUIC, Snell, Hysteria2, AmneziaWG, qWDTT и Mieru. Отдельно
решены два сложных случая:

- **Mieru** не публикует нативную ошибку неправильного пароля, поэтому детектором
  служит серия established TCP-сессий на `2012–2022`, закрывающихся после
  передачи не более 1 KiB. Сигнал alert-only.
- **AmneziaWG** отличает нативные rejection paths ядра от штатных junk-пакетов
  `Jc`, которые больше не считаются ошибкой handshake.

Адаптер Telemt сохранён, но транспорт исключён из подтверждённой матрицы.
Актуальная матрица — в [`docs/ANTIDPI.md`](docs/ANTIDPI.md).

### Telegram и эксплуатация

- ALERT/BAN содержат IP, флаг страны, ASN/владельца, event, protocol, source,
  signals, observed score, verified score, TTL и offense.
- AntiDPI ALERT получил inline-кнопку ручной блокировки IP. Действие доступно
  только настроенному администратору, соблюдает whitelist, использует штатный
  прогрессивный ipset-ban и не увеличивает offense при повторном callback.
- Добавлено раздельное включение уведомлений AntiDPI, Honeypot, Fail2ban,
  unban и system events.
- Статистика доставки хранит attempted/delivered/failed без Telegram secrets.
- Добавлены команды `hydra antidpi sync`, `selftest`, `selftest --full` и
  `capture`; внешний capture сохраняет дельту событий, журналы, firewall rules,
  UDP/TCP sockets, source-relay mappings и AWG dynamic-debug.
- Документирован полный переход с legacy-конфигурации: backup, validate/doctor,
  plan/apply, синхронизация runtime, удаление `hydra-portscan`, перезапуск
  Telegram bot и контрольная проверка сервисов, ipset и внешних событий.
- Диагностические архивы автоматически скрывают пароли, UUID, PSK, токены и
  приватные ключи и создаются с mode `0600`.

### Проверка на реальной VPS

Полный путь от внешнего клиента до Telegram подтверждён для TLS/decoy,
AnyTLS, TrustTunnel, ShadowTLS, Naive TCP/QUIC, Snell, Hysteria2,
AmneziaWG, qWDTT и Mieru. Проверки подтвердили как нативные rejection events,
так и silent-failure fallback, точную source attribution и запрет ложных
UDP-банов.

Полная спецификация архитектуры и политик находится в
[`docs/ANTIDPI.md`](docs/ANTIDPI.md).

## [2.5.0] — 20 июля 2026

### Контекст

После выпуска `2.4.1` в проекте накопился большой набор архитектурных изменений.
Они появились не ради формального рефакторинга: эксплуатация показала, что
наиболее опасные сбои возникают на границах между сохранённым состоянием,
фактически запущенными службами, сетевыми правилами и сгенерированными
конфигурациями.

Отдельно проявилась хрупкость TLS-мультиплексора: `state.json` мог уже содержать
новый домен, а Caddy L4 — ещё старый SNI-маршрут. Поэтому `2.5.0` объединяет
архитектурную переработку, транзакционное применение и эксплуатационную
диагностику в один стабильный контур.

### Что получает пользователь

- Частично применённая конфигурация больше не остаётся незаметно в системе:
  критические операции проходят через транзакции с возможностью отката.
- `hydra doctor`, `hydra plan` и `hydra status` показывают не только желаемое
  состояние, но и фактическое состояние служб и рассинхронизацию.
- TLS-мультиплексор Caddy L4 проверяется на наличие, актуальность SNI,
  сертификаты и состояние службы.
- Резервное копирование и восстановление работают с манифестом, SHA-256,
  dry-run, защитой от небезопасных путей и автоматической страховочной копией.
- Пользователи могут иметь обычные идентификаторы (`test`) или email; старые
  записи и UUID сохраняют совместимость.
- Плагины получают единый жизненный цикл и единый контракт ошибок, что делает
  сбои понятными и безопасными для повторного запуска.
- Архитектурные границы и сценарии отказа покрыты 630 автоматическими тестами.

### Архитектурная основа

- Введён единый `HostBackend` для ограниченных команд, файловых операций,
  `systemd`, firewall, Sing-Box и Caddy. Прямые обходы границы блокируются
  регрессионными проверками.
- CLI и TUI используют прикладные службы и явные зависимости через корневую
  сборку приложения, а не создают глобальные объекты вручную.
- Возможности плагинов, результаты жизненного цикла и проверки
  работоспособности, а также конфигурационные фрагменты получили типизированные
  контракты с адаптерами для старых реализаций.
- Добавлена единая модель `ErrorCode`, `ApplicationError` и `ServiceResult`.
  CLI сохраняет старое текстовое поле `error`, но дополнительно отдаёт
  структурированное поле `error_details`.
- Удалены неиспользуемые устаревшие пути и дублирование кода представления;
  совместимые миграции и адаптеры сохранены намеренно.

### Транзакционный жизненный цикл

- Единый механизм транзакций охватывает применение Sing-Box, nftables, плагины,
  включение/отключение, установку/удаление, переустановку и операции
  пользователей.
- Откат выполняется в определённом обратном порядке, продолжает работу после
  локальной ошибки и защищён от повторного завершения.
- Добавлены потоковая и межпроцессная блокировки применения, журнал
  `apply.jsonl`, снимки конфигураций и проверка работоспособности после
  перезагрузки.
- Honeypot переведён в самостоятельный жизненный цикл: общий apply не
  перезапускает его без необходимости и не блокирует включение другого протокола.

### State, миграции и фактическое состояние

- State хранится атомарно, каталоги синхронизируются после замены, повреждённые
  копии сохраняются отдельно.
- Миграции оформлены как последовательный реестр `vN → vN+1`; неизвестная
  будущая схема отклоняется с безопасной ошибкой.
- Сохранённое намерение отделено от неизменяемого снимка фактического состояния.
  Это устраняет ложные статусы вроде «выключено», когда служба реально работает.
- Добавлены `doctor`, `plan`, `reconcile`, `backup`, `restore` и
  `upgrade check` для контроля системы без ручного редактирования state.

### Caddy L4 и TLS-маршруты

- Добавлена проверка `tls_mux` только для чтения: ожидаемые домены из state
  сравниваются с фактическими SNI-маршрутами Caddy.
- Отдельно сообщаются `missing`, `stale`, ошибки сертификатов, повреждённый
  JSON-конфиг и неактивный `caddy-l4`.
- Проверка ничего не перезапускает и не меняет. Исправление выполняется
  транзакционной командой `sudo hydra apply`, которая заново создаёт и проверяет
  Caddy-конфигурацию.

### Плагины, сеть и эксплуатация

- DNSCrypt, Fail2ban, IPBan, WARP, Telemt и Honeypot переведены на общую границу
  команд хоста и жизненного цикла.
- Служба учёта трафика получила более строгий контроль монотонных счётчиков и
  повторное применение после неудачных обновлений.
- Усилены предварительные проверки зависимостей, конфликтов портов, nftables,
  Caddy и Sing-Box.
- Компоненты интерфейса для протоколов, сетевой информации, логов и системного
  монитора вынесены в тестируемые модули без изменения пользовательского меню.

### Качество и CI

- Полный локальный набор: **630 passed**.
- CI проверяет Python 3.10–3.13, компиляцию, стиль кода, зависимости и
  Linux-проверки на реальной системе.
- Тесты сценариев отказа проверяют не только исключение, но и отсутствие
  побочных изменений, корректность отката и возможность повторного запуска.

### Совместимость и границы релиза

- State schema остаётся `2`; существующие пользователи, UUID, credentials,
  сертификаты и настройки протоколов не требуют ручной миграции.
- Перед обновлением рекомендуется `sudo hydra backup`, затем
  `sudo hydra upgrade check`, `sudo hydra validate` и `sudo hydra apply`.
- REST API и web-панель в этот релиз не входят.
- Telegram-бот остаётся отдельным этапом: его рабочий контракт и проверочные
  сценарии ещё не объявляются стабильными.

## [2.4.1] — 19 июля 2026

### Надёжность применения конфигурации

Транзакционный оркестратор получил блокировку, журналирование, снимки Sing-Box и
nftables, автоматический откат, проверку работоспособности служб и понятную
причину последней ошибки.

### State и миграции

Добавлены структурная проверка, атомарная запись, восстановление из `.bak`,
сохранение `.corrupt`, права `0600` и совместимость со старыми схемами state.

### Пользователи и CLI

Имя пользователя может быть обычным идентификатором или email. Добавлен JSON
CLI для `status`, `validate`, `plan`, `apply`, `user list` и диагностики.

### Sync Agent, плагины и безопасность

Исправлены очередь повторных попыток применения конфигурации, ручные проверки,
обновление Sing-Box, учёт DNSCrypt, Fail2ban, AmneziaWG, WDTT, проверка
целостности бинарников и установщик. Добавлены файлы фиксации зависимостей,
проверка зависимостей и CI для Python 3.10–3.13.

## [2.4.0] — 18 июля 2026

Добавлены ShadowTLS v3, Hysteria2, Snell v4, расширенные подписки, мониторинг
пользователей, qWDTT, сетевой autotuning и унифицированные экраны протоколов.

## [2.3.5] — 17 июля 2026

Внедрён транзакционный цикл `configure → validate → apply → commit/rollback`,
исправлено управление портами и firewall, добавлен монотонный учёт трафика и
улучшен TUI для AmneziaWG.

## [2.3.4] — 11 июля 2026

Добавлены кастомные WARP-профили WireGuard/AmneziaWG и раздельная маршрутизация
списков WARP.

## [2.3.3] — 9 июля 2026

Добавлены изолированные Fail2ban jail, мастер обфускации AmneziaWG и поддержка
Mieru с пресетами и ссылками `mierus://`.

## [2.3.2] — 9 июля 2026

Мультиплексор перенесён с HAProxy на Caddy L4, исправлены конфликты портов
NaiveProxy и добавлена сборка для ARM64/AMD64.

## [2.0.0] — базовый публичный релиз

Первая помеченная тегом версия проекта. Более ранняя история сохраняется в Git.
