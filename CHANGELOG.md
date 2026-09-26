# Changelog

**Релизы:** [3.0.0](#300--25-сентября-2026) · [2.5.5](#255--27-июля-2026) · [2.5.4](#254--26-июля-2026) ·
[2.5.3](#253--24-июля-2026) ·
[2.5.2](#252--21-июля-2026) · [2.5.1-dev](#251-dev--fortress--21-июля-2026) ·
[2.5.0](#250--20-июля-2026) · [2.4.1](#241--19-июля-2026) ·
[2.4.0](#240--18-июля-2026) · [2.3.5](#235--17-июля-2026) ·
[2.3.4](#234--11-июля-2026) · [2.3.3](#233--9-июля-2026) ·
[2.3.2](#232--9-июля-2026) · [2.0.0](#200--базовый-публичный-релиз)

## [Unreleased]

### Исправлено

- Сборка `caddy-l4`: `GOTOOLCHAIN` закреплён на пиннутую версию Go (`goX+auto`), поэтому `go` не уходит молча в более новый тулчейн в середине сборки. Go-прокси на цензурируемых хостах задаётся `HYDRA_GOPROXY` (например `https://goproxy.cn,direct`); при ошибке загрузки тулчейна сборка подсказывает обход вместо сырого 403.

## [3.0.0] — 25 сентября 2026

### Добавлено

- Плагин `mtproto_zig`: FakeTLS MTProxy с отдельными Hydra-owned путями, непривилегированным systemd-пользователем и `CAP_NET_BIND_SERVICE`; TCP/443 напрямую или loopback `127.0.0.1:20449` за Caddy L4 по SNI, per-user `tg://proxy` через общий слой клиентских артефактов, накопленный трафик из loopback Prometheus. PROXY v2 не передаётся, IP-квоты не поддерживаются.
- Режимы WEB MTProto Zig: `off` (FakeTLS, по умолчанию), гибрид FakeTLS + WEB и только WEB для Telegram Desktop 7.1+; ссылка `tg://webproxy?server=<домен>&secret=dd<32-hex>` выдаётся на отдельный домен оператора с публичным сертификатом, прикрываемый FakeTLS-домен сертификата не требует.
- WEB-домен MTProto Zig отдаёт обычный статический сайт вместо голого `404 Not Found`: темы заглушек генерируются в `/var/www/decoy-zig`, `[web] public_dir` рендерится только после успешной генерации, тема выбирается строкой «🎭 Сайт-заглушка» и командой `set_decoy_theme`; выключение WEB убирает `public_dir`, страница моста и проверка capability сохраняют приоритет, сбой генерации виден в статусе и health и не валит применение.
- Релей WEB MTProto Zig: единственный владелец TCP/443 — управляемый `caddy-l4`, он завершает TLS и передаёт HTTP/WebSocket на `mtproto-zig-web.service` (`mtproto-zig web-relay`, `127.0.0.1:8081`, без capabilities).
- Переход MTProto Zig в «только WEB» staged: релей поднимается с `only = false`, фронтенд рендерится без маршрута FakeTLS, проверяется HTTPS-мост через локальный `:443`, затем коммитится `only = true`; сбой отдаёт снапшот, сбой отключения релея не считается успехом, неполный откат виден в журнале как `rollback_failed`. Upstream `mtbuddy`, nginx и `/opt/mtproto-proxy` не используются.
- Выбор MASQUE-адреса в меню WARP: warpscout проверяет адреса с VPS, оператор подтверждает один или возвращает автоматический выбор ядра; адрес хранится в state и проверяется через отдельный loopback SOCKS при применении, отказ восстанавливает прежнюю конфигурацию. Аккаунт сканера создаётся после подтверждения, бинарник ставит оператор.
- Списки правил WARP из каталога Geo-Aggregator вместо трёх зашитых списков itdoginfo: `db/catalog.json` (314 источников в 20 категориях) скачивается и кэшируется в `/var/lib/hydra/warp_catalog.json` и обновляется той же задачей обслуживания, что и списки; без каталога используется встроенная копия.
- Двухуровневое меню внешних источников WARP: категория → её списки с пагинацией по 20, категория направляется одним target; при расхождении направлений внутри категории показывается «разные направления», рядом печатается ожидаемое направление (`ru` → direct, `blocked` → warp).
- Переименование ключей списков WARP при загрузке state: `ext:russia` → `ext:category-ru`, `ext:geoblock` → `ext:refilter`, `ext:google_ai` → `ext:category-ai` с сохранением target; TLD `.ru`/`.su`/`.рф`/`.xn--p1ai` тянет `category-ru`; отсутствующие в каталоге `refilter` (реестр РКН) и `antifilter` (IP-диапазоны) добавлены отдельно.
- AmneziaWG обслуживает HydraCore: один `wireguard` endpoint на профиль с выдаваемыми peer'ами, HYDRA сама генерирует ключевой материал, поколение читает из конфигурации ядра, per-user трафик атрибутируется по tunnel-адресу peer'а; профили перевыпускаются, `random_trailers` работает после fork-фикса.
- Транзакционное переключение режима AmneziaWG 2.0/3.0/3.1 через пиннутый upstream-инсталлятор: unknown-ключи интерфейса сохраняются, при откате восстанавливаются конфигурация и оба состояния AWG systemd.
- Артефакты AWG 3.x: Throne `wg://` и официальный Qt-сжатый Amnezia `vpn://`; Sing-Box Extended и HydraBox включены для 3.0 и, при контракте 3.1, для 3.1, NekoBox `sn://awg` остаётся fail-closed.
- Гейт AmneziaWG 3.1: экспорт в Sing-Box Extended и HydraBox требует HydraCore с контрактом `random_trailers`/`disable_cookies`; старый ядро держит экспорт fail-closed с указанием требуемого релиза, `random_trailers` выдаётся JSON-булевым.
- Настройка `set_uot` (TUI «UDP через TCP (UoT)») в NaiveProxy, включена по умолчанию; выключение пересобирает Caddy из upstream-модуля `forwardproxy` вместо UoT-форка и убирает `uot` из Shadowrocket-ссылок, сборка распознаётся пробой бинарника, а не маркером. UDP поверх TCP-профиля Naive при этом не работает, QUIC не затронут; у форка нет опции «disable UoT», а при настроенном `upstream` его контролы `acl`/`ports` не применяются — поэтому переключателем служит сама сборка.
- Поколения Snell из мигрированного HydraCore: generation 5 (server `version: 5`, плоский `obfs_mode` `none`/`http`/`tls`) или generation 6 (свой `mode` `default`/`unshaped`/`unsafe-raw`) вместо серверного `version: 4` с вложенным объектом `obfs`, который upstream отклоняет; классическая пара — server 5 с client 4, форма Shadowrocket только для неё, обе генерации требуют HydraCore с upstream Snell.
- NekoBox `sn://awg`: emoji и non-BMP имена профилей кодируются как Kryo-совместимые Java UTF-16 characters.
- Display-имена конфигураций отделены от runtime-тегов HydraBox, различают Naive TCP и QUIC и применяются к desktop и mobile ссылкам AmneziaWG в NekoBox-совместимых подписках.
- Hydra VK Tunnel пересоздаёт blue/green пул из четырёх ссылок без полной переустановки и планирует пересоздание каждые 1–24 часа через Sync Agent (по умолчанию выключено). Отдельный TUI-экран глобальных имён конфигураций; личные имена остаются в карточке пользователя, Hydra VK Tunnel присутствует в обоих списках.
- Vendor-neutral desired state ядра и команды `hydra kernel status` / `kernel switch`; Hydracore и Sing-Box Extended загружаются только из фиксированных репозиториев с обязательными проверками GitHub `asset.digest`, ELF, identity/capability, active-config и post-start, транзакция возвращает прежнюю работающую службу при любом сбое.
- Экспериментальный транспорт `calls`: native VK `call` inbound для Hydracore с exact capability gate, транзакционным созданием/ротацией managed-пула и admin-only SOCKS joiner profile; stock/P2P fallback отсутствует. Native VK Calls на Hydracore `vk_parasite`: exact `call_vk_parasite` создаёт отдельный blue/green пул из 1–4 VK-комнат и публикует per-user Hydracore outbound через Hydra Subscription v2; серверный inbound содержит общий obfs key, bounded session/worker/handshake limits и O(1) user lookup.
- Multi-user listener Calls на `56002/udp` (не конфликтует с qWDTT WireGuard на `56001/udp`); число workers на сессию выбирается из 4/8/12/16/20 и задаёт `max_workers_per_session`.
- Импорт локального VK cookies JSON в TUI до установки Calls: нормализация, валидация перед атомарной заменой, managed-файл с mode `0600`.
- `?format=hydrabox` переведён с исторического HydraBox Subscription v1 на клиент-независимый Hydra Subscription v2: `hydra.io/subscription/v2`, `resources[]`, resource-scoped profiles, точные `requested_permissions` и требования HydraCore API/remote policy v2; одинаковые native tags в разных resources больше не конфликтуют.
- Flattened `dir`/`A256GCM` JWE приведён к HydraCore v2: обязательный пустой `encrypted_key`, `typ=hydra-subscription+jwe`, `cty=application/vnd.hydra.subscription+json`, без `kid` в protected header; случайный IV, лимиты 12/16 MiB и отсутствие plaintext fallback сохранены. Общий deterministic AES-GCM test vector v2 для backend и HydraCore.
- `?format=hydrabox` (v1-контракт): plaintext HydraBox Subscription с точным vendor media type, монотонным составным `sequence`, явными профилями и remote-safe native Sing-Box `outbounds`/`endpoints`; генерация fail-closed отклоняет duplicate JSON/native tags, циклические и внешние ссылки, локальные executable-поля и system WireGuard, а расширенные AmneziaWG `I1`–`I5`, `J1`–`J3` и `Itime` сохраняет lowercase-полями объекта `amnezia`. Имена профилей подписки берутся только из коротких `display_name` или `name`, технические `PluginMeta.description` в них не попадают; renderer revision в младшей части `sequence` растёт при изменении выдаваемого JSON, HTTP-ошибка не оставляет частичный ответ.
- Приватный 256-битный ключ на пользователя в схеме state v6: миграция заполняет ключи атомарно, CLI и TUI ротируют их немедленно.
- Запрос HydraBox требует `HydraBox/<version>` и reported HWID: новый клиент использует `X-HWID`, legacy `X-Hydra-HWID: hbx1_…` совместим; backend хранит только хеш идентификатора и редактированные audit-поля, ошибка контракта — HTTP 400, device limit — 403.
- Ключ HydraBox выдаётся только во fragment `#hydra-key=…`; status, логи и публичные JSON не содержат ключ или полный HWID.
- Native VK Calls добавляет в подписку отдельный remote-safe `call` outbound/profile с `mode=vk_parasite`, `join_links` и core features `call`/`call_vk_parasite`, без VK cookies и singular `join_link`; отсутствие managed-пула отклоняет выдачу fail-closed.
- Общие умеренные defaults ресурсов VPS без отдельного профиля: `GOGC=50` для Sing-Box и journald budget 128 MiB на диске / 64 MiB runtime; жёсткий memory cap не применяется.
- Команды AntiDPI `sync`, `selftest`, `selftest --full` и `capture`; внешний capture сохраняет дельту событий, журналы, firewall rules, UDP/TCP sockets, source-relay mappings и AWG dynamic-debug.
- Stable State Format v1 вместо release-coupled схем и 18-шаговой цепочки миграций: legacy-схемы 0–18 импортируются напрямую один раз, изменения фич (включая транспорт Calls) больше не поднимают формат state и не добавляют migration scripts, неизвестные feature namespaces переживают load/save.
- Карточка адреса AntiDPI в Telegram использует точный query `address_details` (26-й watched-адрес больше не отдаёт «no evidence») и различает «нет данных» и «чисто». `management_snapshot` AntiDPI отдаёт ограниченную проекцию оператора: активные баны с готовыми подписями, watchlist, переведённые счётчики и момент снимка — вместо копии до 20 000 score-записей на обновление.
- Экран AntiDPI в TUI: healthcheck с расшифровкой неисправных проверок, список банов с остатком срока и причиной на русском, «Под наблюдением», статистика сигналов и источников, ручная бессрочная блокировка, разбан по номеру или адресу, локальная диагностика. Telegram-дашборд AntiDPI: GeoIP/ASN, остаток срока, причина на русском, watchlist, кнопки разбана с остатком срока и `🧾 Подробнее` с детальным видом счётчиков.
- Граф экранов Telegram-бота: `⬅️` ведёт к родителю, `🔄` сохраняет номер страницы, с вложенных экранов доступен `🏠 Меню`; роутинг callback-ов — разбор `view:<экран>[:<страница>]`.
- Постраничная листалка списков блокировок, наблюдения и уловов honeypot в Telegram вместо обрезки на 5–12 записях.
- Карточка адреса в Telegram: GeoIP/ASN, статус в AntiDPI с остатком срока и причиной, статус в Honeypot, кнопки блокировки и разблокировки; открывается строкой списка или отправкой IP сообщением.
- Режим уведомлений «только блокировки» и тихие часы с окном через полночь: `notify_only_blocks`, `quiet_hours_enabled`, `quiet_hours_start`, `quiet_hours_end` в `TelegramConfig`.
- Мониторы fail2ban и honeypot опрашивают журнал раз в 15 секунд на тихом хосте и возвращаются к 2 секундам сразу после новой строки.
- Headless CLI сведён к операторскому циклу `status` → `check` → `apply`: validation, doctor, plan и reconciliation объединены в один read-only preflight, старые формы сохранены как алиасы.
- Metadata-driven inventory/lifecycle/command/query/action плагинов, `backup inspect`, `user show`, TTY-aware таблицы и сводки, явный `--json`, компактный JSON и JSON-ошибки синтаксиса.
- Read-only проверка `tls_mux`: ожидаемые домены из state сравниваются с фактическими SNI-маршрутами Caddy, отдельно сообщаются `missing`, `stale`, ошибки сертификатов, повреждённый JSON-конфиг и неактивный `caddy-l4`; исправление — транзакционный `sudo hydra apply`.
- Единый `HostBackend` для ограниченных команд, файловых операций, `systemd`, firewall, Sing-Box и Caddy; прямые обходы границы блокируются регрессионными проверками.
- Единая модель `ErrorCode`, `ApplicationError` и `ServiceResult`; CLI сохраняет текстовое `error` и дополнительно отдаёт структурированное `error_details`.
- Типизированные контракты возможностей плагинов, результатов жизненного цикла, healthcheck и конфигурационных фрагментов с адаптерами для старых реализаций.

### Изменено

- Calls работает только с контрактом `vk_parasite` и ровно четырьмя независимыми KCP lanes (`lanes: 4`); CLI больше не даёт A/B transport-profile switch; перед активацией требуется контракт HydraCore с `calls_mode = vk_parasite`.
- Канал ядра Hydracore — switch из двух значений: `stable` (по умолчанию на всех ветках HYDRA) и `debug`; `stable` берёт самый свежий опубликованный non-prerelease, `debug` — самый свежий prerelease и принимает формы `hydracore-sbe-<sbe-version>-debug-<n>` и `hydracore-sbe-<sbe-version>-rc-<n>`.
- Retired-тег `-debug.<n>` не выбирается ни одним каналом; persisted-значение `preview` больше не предлагается, но резолвится как `debug`; `bootstrap.sh` ставит самый свежий релиз выбранного канала, TUI показывает канал и версию кандидата до замены ядра; digest/config/health проверки с автоматическим rollback сохранены.
- Release-контракт Hydracore разделён по ролям: Ultimate загружает только `hydracore-vps-linux-{arch}.tar.gz` и проверяет VPS identity, server feature, VK-parasite-only режим и wire v4; Android client artifact на VPS отклоняется fail-closed.
- Calls сохраняет отдельный `public_endpoint`, не зависящий от transport SNI; в административном TUI транспорт называется `Hydra VK Tunnel`, пользовательский профиль в подписке — «Обход БС».
- Provider-aware kernel status стал единственным источником версии/наличия ядра для главного экрана и экрана Sing-Box, Hydracore больше не показывается как «не установлен».
- Клиентские outbounds Calls используют только явно настроенный IP сервера или определённый публичный IPv4 VPS; TLS/SNI-домен транспорта больше не подставляется как native VK-parasite endpoint.
- Legacy install/update Sing-Box Extended не может затереть выбранный Hydracore, фоновая проверка обновлений следует provider и channel из state.
- Демон трафика распознаёт runtime inbound `call/...` как протокол `calls`, Hydra VK Tunnel использует общий tracked-источник соединений; при передаче аутентифицированного пользователя в Clash `metadata.user` байты монотонно начисляются общему и per-protocol счётчику.
- WARP показывает и загружает только списки отдельных сервисов: сводные `category-*`, `itDog-*`, `refilter` и `antifilter` исключены, выбор `none` убран из меню, `direct` — выход с VPS и явное исключение из WARP, а не российский адрес.
- WARP: более узкие маршруты предшествуют широким, отсутствующий выбранный список останавливает apply вместо неявного перехода на direct; без каталога внешние сервисы недоступны, локальные правила работают; установка и переустановка не удаляют кэш выбранных правил; релей с активными маршрутами нельзя удалить без перенаправления, старые маршруты к удалённым источникам требуют ручной перенастройки.
- Preflight обновления снова принимает сохранённые маршруты `ext:category-ru` — единственный разрешённый сводный источник WARP, доступный в каталоге, офлайн-копии и конфигурации вместе с суффиксами российских TLD; остальные сводные списки остаются отключёнными.
- WARP больше не ставит внешний установщик профиля: транспорт переведён на нативный `masque` outbound ядра HydraCore, устройство регистрирует Cloudflare API само ядро, профиль кэшируется в `cache_file` (`store_masque_config`), поэтому перезапуск службы не создаёт новое устройство.
- Цель `warp` доступна всегда, отсутствующий профиль больше не блокирует apply; relay-профили `warp_<name>` из `/etc/hydra/warp_profiles` по-прежнему рендерятся как `wireguard` endpoints; прежний профиль wgcf не используется, новое устройство регистрируется при первом применении.
- Переключение существующей установки — `sudo hydra plugin reinstall warp` или «🔄 Переустановить» в меню WARP: удаляет `/usr/local/bin/wgcf`, `wgcf-profile.conf`, `wgcf-account.toml`, `/var/log/hydra/warp_install.log`, заново скачивает каталог и списки и сохраняет настроенные маршруты; `install()`/`uninstall()` плагина остаются совместимыми no-op.
- Ручные конфигурации больше не повторяют показанные MTProto `tg://proxy`-ссылки JSON-обёрткой `{"link": ..., "protocol": ...}`; полноценные JSON-конфигурации с дополнительными полями не фильтруются.
- VLESS CDN снова учитывает трафик и появляется в активных подключениях, когда Clash не передаёт пользователя: HYDRA сопоставляет source-port с Sing-box journal только внутри записавшего его inbound (`vless-cdn-in` → `vless_cdn`); обычный VLESS/XHTTP и CDN не могут обменять квоту при повторном использовании loopback-порта, без journal evidence соединение не кредитуется и не показывается; flat helpers VLESS/AnyTLS сохранили прежний контракт и порядок «последняя journal-запись побеждает».
- Переименованный профиль VLESS CDN доходит до клиентов под одним ключом: UI и HydraBox читали канонический `vless_cdn`, а URI pipeline искал `vless:cdn`, поэтому Throne и NekoBox падали на встроенное имя `<email> VLESS Яндекс CDN`; теперь все места используют `vless_cdn`, family override обычного VLESS больше не протекает в CDN-профиль, встроенные defaults обоих форматов не изменились.
- Установка mtproto.zig разрешает бинарник по артефакту, а не по `releases/latest`: выбирается самый новый опубликованный релиз с точным архивом под архитектуру хоста, SHA-256 проверяется по release metadata или точному `.sha256`-артефакту того же релиза; замена атомарна через `<binary>.pending`, внутри архива принимается точное архитектурное имя `mtproto-proxy-linux-*`, используемое upstream; это устраняет состояние «Не установлен», при котором поиск по `releases/latest` не находил архив `mtproto-proxy`.
- Ошибка установки mtproto.zig сохраняется после rollback и называется своей стадией (выбор релиза, проверка digest, распаковка/ELF, сервисные пути, юнит, служба, маршрутизация); прежний файл и состояние службы сохраняются при любой ошибке; FakeTLS-домен Zig не отправляется в certbot — сертификатом владеет proxy handshake, Caddy делает только SNI passthrough; upstream `bootstrap.sh` и `mtbuddy` не запускаются.
- Длинные master-ссылки qWDTT и ссылки подключения Telemt переносятся внутри панели без обрезки хвоста многоточием.
- Меню `Calls · VK` использует общий renderer протоколов и оставляет установку, атомарную переустановку с пересозданием пула, admin-профиль и удаление; отдельные enable/disable и cookie-статусы убраны.
- qWDTT-ссылка формируется из любого настроенного числа уникальных хэшей с сохранением порядка и корректным percent-encoding query-параметра; токены с `+`, `=`, `%` и `&` больше не искажаются.
- Native Calls принимает актуальные VK join-links с полным набором безопасных символов URL-сегмента и официальными доменами `vk.com`/`vk.ru`; частично записанная строка creator не вызывает преждевременную ошибку, все поддержанные варианты ссылки редактируются в логах.
- Историческая интеграция qWDTT с Headless Creator, его blue/green rotation и Sync Agent удалены: qWDTT не создаёт Creator-комнаты и не использует VK cookies, а Creator и VK cookies принадлежат только Calls.
- Native Calls не включается автоматически, а старые units и файлы qWDTT удаляет только явное `Создать комнаты` в qWDTT-подменю со snapshot/restore.
- Актуальная qWDTT master-ссылка показывается в TUI в «Ручных конфигах» с явной пометкой, что она общая для всех пользователей; в пользовательские подписки ссылка с главным паролем не включается.
- qWDTT остаётся только ручным общим master-артефактом: Hydra v2 renderer не вызывает его client hook и не может опубликовать главный пароль.
- TUI-меню используют компактные заголовки и однострочные действия вместо ASCII art, вложенных рамок и повторяющихся описаний; Telegram-дашборды безопасности показывают короткую сводку, IP-списки остаются на drill-down экранах.
- Shadowrocket-вывод подписки сохраняет реальную форму транспорта: Naive TCP — HTTPS с `http/1.1` и `h2`, Naive QUIC — HTTP/3 `h3`, TCP-варианты включают UoT v2 и TCP Fast Open, все варианты включают padding; TrustTunnel использует официальный TLV, Snell сохраняет `obfs`; Naive собирается из пиннутого Caddy-форка, замена валидирует фактический бинарник и держит backup; новый CI workflow `naive-caddy.yml` покрывает валидацию реального бинарника, HTTP/1 CONNECT и UoT magic passthrough (для этого изменения ещё не запускался).
- Shadowrocket Naive-ссылки `https://`, `http2://`, `http3://` больше не несут избыточные `peer` и `alpn`, мешавшие их HTTPS-парсеру импортировать профиль.
- Новая установка и обновление идемпотентно ставят systemd drop-ins, выполняют rotate/vacuum старых журналов до 128 MiB и применяют настройки к работающим службам.
- AntiDPI объединяет service- и kernel-события в один фильтрованный `journalctl -f`, сохраняя прежнюю атрибуцию и убирая второй долгоживущий процесс чтения журнала; мониторы fail2ban и honeypot больше не спавнят два `journalctl` в секунду.
- Ужесточённый systemd unit AntiDPI разрешает общий xtables lock под `/run`, пока `ProtectSystem=strict` остаётся включённым.

### Исправлено

- AntiScan больше не банит по отказу Snell: запись `open record header: cipher: message authentication failed` неотличима для сканера и для клиента со устаревшим PSK. Протокол убран из `PROTOCOL_REJECT_RULES`, запись остаётся диагностическим входом; процедура в `docs/ANTIDPI.md` требует owned-tag проверки в journal normalizer перед возвратом Snell.
- AntiDPI банит только доказуемое на самом хосте: protocol-owned rejection с реальным внешним peer или явный scanner path на decoy-сайте, набор разрешённых улик закрытый. Бан-вход — reject Snell и путь `/.git/`, ladder банов (10 минут, 1 час, 24 часа, 7 дней) работает от одного доказанного события; протоколы без fixture-proven reject (AnyTLS, VLESS, Naive, TrustTunnel, ShadowTLS, Hysteria2, qWDTT, AmneziaWG, Mieru, Calls) задокументированы как неподдержанные, новый протокол входит только через sanitized capture с развёрнутой реализации. Ключ плагина, имя службы и совместимые импорты не изменились, legacy `scores`/`subnets` читаются для rollback и не влияют на решения.
- AntiDPI hardening (аудит сентября 2026): kernel SYN/NEW и UDP telemetry никогда не поднимают ban eligibility, multi-port bursts остаются alert-only; ошибки ShadowTLS, атрибутированные только по времени, — alert-only hints; TrustTunnel CONNECT считается auth evidence только при явных 401/407, backend 5xx и валидные туннели — нет; decoy scanner paths сопоставляются с нормализованным request path, а не с raw URI с query; protocol-specific паттерны Sing-Box выигрывают у generic matcher.
- AntiDPI enforcement: ban intent персистится до эффекта ipset и откатывается при отказе; unban сериализует удаление firewall с обновлением state; ручные баны в том же intent-first порядке; доставка в Telegram вне state lock; collector восстанавливает ipsets, rules и сохранённые баны при старте и каждые 10 минут, снимает whitelisted баны, ведёт liveness heartbeat, переживает log rotation, сохраняет частичные строки, продолжает journald с сохранённого курсора и скорит события по их таймстампам; курсоры двигаются только после durable обработки, replay дедуплицируется; старые события затухают по собственному времени и получают не больше остатка исходного ban TTL; повреждённые state-файлы карантинятся и останавливают автo enforcement в видимом degraded mode; добавление в whitelist сообщает адреса, которые не удалось разбанить.
- AntiDPI reconciliation восстанавливает всю firewall-поверхность и записывает неудачные шаги для health/operator views, баны под whitelist не восстанавливаются; доставка в Telegram — bounded background queue с исходами delivered/failed/dropped; неудачное продвижение timed manual ban восстанавливает исходные metadata, history и offense count.
- TUI-бан-лист AntiDPI листается постранично с номерами только видимых строк и подтверждением mass unban и manual ban; строки журнала рендерятся полностью; пропущенные ban-уведомления помечаются как cooldown skips.
- Отказ применения команды плагина больше не прячет причину: при неудачном apply и неудачном откате оператор видит исходную причину применения, а сообщение об отказе отката идёт отдельной строкой (раньше причина оставалась только в `/var/log/hydra/apply.jsonl`); ступень отказа из `apply_failure()` попадает в «Plugin X apply returned false: …» в каноническом пути `PluginExecutor` и в обоих `sync_user_configs`.
- Учёт трафика записывает baseline первого poll до начисления байт, поэтому запуск сборщика не удваивает агрегатный и per-user трафик.
- Мониторинг трафика MTProto Zig отличает «HTTP 200 без поддерживаемых серий» от настоящего нуля: недоступность источника показывается как «источник недоступен» с причиной в статусе и health, последние достоверные значения сохраняются; разобранный ответ хотя бы с одним пользователем из state считается доступным, число ненайденных non-blocked пользователей видно в `status().info` как `api_missing_users`. Таблица «По протоколам» выровнена по 77-клеточной раскладке (16/12/23/13/8), паддинг считается по видимой ширине без ANSI, ненулевая доля рисует хотя бы один блок, подписи берут продуктовые имена (`AnyTLS`) при отсутствии display name, столбец статуса показывает фактическое состояние службы; профильные ключи credentials (`amneziawg_mobile`) не становятся отдельной строкой протокола.
- Sing-Box systemd unit получает `CAP_NET_RAW`, необходимую ядру `1.13.16-extended-2.6.x` для повторной привязки исходящего UDP-сокета при `auto_detect_interface`; обновление ядра пересоздаёт unit перед запуском, а `hydra apply` заменяет HUP полным restart, поэтому клиентские UDP DNS-запросы не падают с `listen udp4 :0: operation not permitted`.
- Обновление ядра не завершается без объяснения при ошибке GitHub API, проверки нового бинарника, конфигурации или запуска systemd-службы: TUI показывает безопасную причину, транзакция восстанавливает прежний бинарник и повторно запускает работавшую службу. Перед проверкой нового ядра legacy DNS-конфигурация, сгенерированная HYDRA, атомарно переводится на актуальную схему `type/server/domain_resolver`; при ошибке проверки или запуска вместе с бинарником восстанавливается исходный `/etc/sing-box/config.json`, DNS-фрагменты плагинов не переписываются.
- Выбор ядра `debug` при неупорядоченном выводе prereleases от GitHub: берётся самый новый подходящий опубликованный релиз вместо первой записи API.
- Исправлена UTF-8-разметка действия ротации HydraBox JWE-ключа в меню пользователя и связанных подтверждениях.
- Updater больше не передаёт шаблонные systemd units вида `name@.service` в команды проверки/остановки как конкретную службу: обнаруживаются реально загруженные instances и сохраняются в `active-units.txt`, поэтому активный пул `hydra-headless-creator-vk-calls@*.service` не блокирует обновление и восстанавливается после переключения release либо rollback.
- `wdtt-server` собирается из всего корневого Go-пакета upstream, включая вынесенный `admin_api.go`; установка не падает с `undefined: registerAdminAPIRoutes`.
- Updater больше не копит релизы и снимки отката навсегда: на долгоживущей установке `/opt/hydra-releases` и `/var/backups/hydra/upgrades` росли с каждой раскаткой. После успешного переключения он удаляет всё, кроме текущего release и `HYDRA_KEEP_RELEASES-1` свежих (по умолчанию 3), снимки отката старше `HYDRA_KEEP_BACKUP_DAYS` дней (по умолчанию 7) и брошенные `.staging-*`; текущий release не удаляется никогда, сбой уборки не влияет на результат установки.

### Удалено

- Telemt (MTProto-прокси) удалён полностью: код плагина, UI-менеджер и тесты; на обновляемых VPS `telemt.service` и cron `telemt-stats` снимаются автоматически через штатный uninstall-путь, MTProto-доставка остаётся через `mtproto_zig`.
- WARP: удалён внешний установщик профиля — бинарник `wgcf`, `wgcf-profile.conf`, `wgcf-account.toml`, журнал `/var/log/hydra/warp_install.log` и пункты меню установки, пересоздания и удаления профиля.
- Убрано промежуточное меню «Режим WEB» в настройках транспорта MTProto Zig: строка сразу открывает выбор режима.
- Удалена зависимость `qrcode`: ручные TUI-выводы клиентских ссылок и конфигураций больше не печатают ASCII QR-коды, сами ссылки, подписки и текстовые конфигурации не изменились.
- Удалён выбор `none` в меню WARP; сводные списки `category-*`, `itDog-*`, `refilter` и `antifilter` исключены из показа и загрузки.
- Удалён устаревший эксперимент Hydra VK Tunnel: telemetry framework, его CLI, collectors, reports, storage и требование native telemetry capability.
- Удалены выбор и установка Sing-Box Extended как отдельного ядра, включая legacy install/update-пути, способные затереть выбранный Hydracore: HYDRA использует только Hydracore VPS debug channel, а Creator runtime и фиксированный пул из четырёх комнат принадлежат Hydra VK Tunnel.
- Из Fail2ban удалён исполняемый legacy протокольных плагинов, сохранён только миграционный cleanup старых jail/filter и portscan rule.
- Из AntiDPI удалены scoring, decay, evidence families, coordinated-subnet detection и sub-threshold watchlist, а также unknown SNI, generic TLS EOF/alert/handshake failures, kernel port-scan и sweep telemetry, UDP probes, Mieru byte-count inference, subnet correlation, time-window source guessing, iptables LOG rules, AmneziaWG kernel debug hook и Caddy `layer4` JSON log.
- Удалён ALERT с inline-кнопкой бана: Telegram сообщает только о применённом бане или отказе firewall, кнопка бана осталась на карточке адреса.
- Удалена installer-era схема AmneziaWG: checkout, `--protocol-status` и `--enable-awg3*`, purge пакетов, работа с kernel module, units `awg-quick`, снапшот `params`, interface file и TPROXY entries; остатки старой установки называются и удаляются, снятие протокола не трогает пакетный менеджер и kernel module.
- Удалена устаревшая схема `stats.json` (iptables-цепочки, cron, оценка доли по сессиям) в MTProto Zig.
- Удалён transport profile switch (A/B) из CLI и генерируемого конфига Calls.

### Безопасность

- VK join-links и полный профиль считаются shared secrets: HYDRA редактирует их в status/log projections, сырой journald остаётся чувствительным, поскольку upstream runtime может писать join-links на уровне INFO.
- Диагностические архивы AntiDPI скрывают пароли, UUID, PSK, токены и приватные ключи и создаются с mode `0600`. Self-test архивы AntiDPI структурно удаляют значения `Authorization`/`Proxy-Authorization`/`Cookie`/`password`, включая JSON-объекты и массивы.
- `cryptography` обновлена до `50.0.0`, закрывающей `PYSEC-2026-3552`.

## [2.5.5] — 27 июля 2026

### Добавлено

- Shadowrocket распознаётся по `User-Agent` и поддерживает явный `format=shadowrocket`; TCP-профиль NaiveProxy выдаётся как `https://<url-safe-base64(user:password@host:port)>?remarks=<имя>` без padding, а несовместимый `naive+https://` в список не попадает.

### Изменено

- HYDRA-заглушки сохраняют в `.hydra-decoy.json` SHA-256 исходников встроенных рендереров: после обновления шаблона следующий apply атомарно публикует новую версию при прежних теме и домене, ручные сайты без marker не перезаписываются; встроенные сайты старых установок (Apex Digital, TechBits, HydraDB, Meridian Daily, Northstar Cloud) мигрируют по строгому отпечатку.
- Интерактивное включение доменных транспортов выполняет установку, проверку сертификата и enable как единый application-сценарий: ошибка certbot откатывает введённый домен, уже завершённая установка плагина сохраняется.
- У установленного, но выключенного NaiveProxy доступно меню домена и транспорта, домен можно исправить до повторной активации.
- Чистая установка заранее устанавливает системный `certbot`; резервная установка при первой TLS-активации нормализует timeout и ошибки хоста вместо зависания или выхода из TUI.
- Launcher и транзакционный updater получили единый вывод: UTF-8 locale, нумерованные этапы, русские ошибки, цветные статусы и финальную сводку с веткой, переходом, снимком отката и логом; при перенаправлении вывода и с `NO_COLOR` ANSI-последовательности не используются.
- Публичные `bootstrap.sh`, `updater.sh` и `upgrade.sh`, команды в документации и regression-тесты переведены на ветку `main` по умолчанию, явный `HYDRA_REF` по-прежнему позволяет проверить другую ветку.
- TUI выводит клиентские URI и конфигурации отдельными строками без рамок, отступов и ANSI-кодов, поэтому копирование из SSH-терминала не добавляет пробелы и символы панели.
- Ссылки подписки показываются только после запуска `hydra-sub` и наличия пары HTTPS-сертификата и ключа, до готовности endpoint TUI показывает точную причину.
- Версия проекта поднята до 2.5.5; пустой заголовок обзорной таблицы README заменён на семантическую HTML-разметку, README ветки `dev` снова ведёт на `dev`: CI badge, bootstrap и updater используют канал разработки, команды явно передают `HYDRA_REF=dev`.

### Исправлено

- `?format=singbox` больше не теряет AmneziaWG при попытке разобрать нативный WireGuard INI как JSON: desktop и mobile профили экспортируются как отдельные `wireguard` endpoints Sing-Box Extended с параметрами `amnezia`, а `route.final` указывает на первый доступный AWG endpoint.
- Переключение VLESS + XHTTP из Reality в TLS сразу запрашивает домен и атомарно применяет режим, домен и сертификат вместо apply без домена.
- Mieru больше не публикует одновременно `listen_port: 2012` и пересекающийся `listen_ports: 2012-2022`; сервер и `mierus://` используют один канонический диапазон.
- Установка локального WGCF не считается неуспешной, если профиль уже создан, а предварительная загрузка внешних списков временно недоступна; ошибка `register`/`generate` показывается в TUI с redacted-деталями из `warp_install.log`.
- Экран WARP отличает настроенные профили и маршруты от фактически активных; назначение списка на отсутствующий outbound (например, `GoogleAI → warp` без локального WGCF-профиля) отклоняется общим apply с точным именем назначения вместо неявного direct fallback.
- Сроки подписок в RFC 3339 с суффиксом `Z` одинаково распознаются на Python 3.10–3.13, Python 3.10 больше не показывает валидную UTC-дату как ошибочную.
- Резервный отпечаток клиента без HWID больше не зависит от IP; старые дубли с одинаковым `User-Agent` лениво объединяются при следующем запросе подписки с сохранением времени первого обращения.
- VLESS за Caddy передаёт внешний адрес через точный PROXY v2 source-relay, демон трафика восстанавливает его по source port, поэтому экран сессий и лимит устройств больше не принимают `127.0.0.1` за устройство; для старого runtime loopback показывается как внутренний адрес мультиплексора.
- Перед promotion объединено исправление восстановления `caddy-l4.service` из `main` с новым updater из `dev`; rollback сохраняет state, код, wrapper и ранее активные службы.

## [2.5.4] — 26 июля 2026

### Добавлено

- Встроенный `vless` transport на базе VLESS + XHTTP из `shtorm-7/sing-box-extended`: VK-parasite inbound, Sing-Box client config, `vless://` ссылки и выдача через общие подписки.
- VLESS + XHTTP требует отдельный TLS-домен; Caddy L4 направляет настроенный XHTTP-путь во внутренний Sing-Box, остальные URL обслуживает сайт-заглушка `/var/www/decoy-vless`.
- Настройка VLESS + XHTTP: паддинг, размер и число upload-пакетов, длительность stream-up, лимит заголовков запроса, SSE-заголовок и до 16 собственных HTTP-заголовков; значения по умолчанию не изменились, каждая правка проходит валидацию и общий транзакционный apply.
- Профили транспорта XHTTP `balanced`, `low_latency` и `stealth`: одна команда согласованно выставляет режим и весь набор параметров, профиль и сводка тюнинга видны в статусе плагина и в TUI.
- Режим Reality поверх XHTTP: `set_security` создаёт пару ключей и short_id, объявляет SNI-проброс через Caddy L4 вместо маршрута с сертификатом и снимает требование домена; клиенты получают ссылки `security=reality&pbk=&sid=&fp=` на публичный IP сервера.
- Caddy L4 научился декларативному маршруту `tls_passthrough`: плагин объявляет SNI и внутренний порт, мультиплексор отдаёт соединение целиком, не разбирая TLS и не требуя сертификата.
- Отдельный TUI-экран VLESS + XHTTP по образцу AnyTLS: runtime-статус, клиенты, текущий профиль и прямой выбор профиля на верхнем уровне, домен, path, mode и тонкий тюнинг в расширенных настройках.
- Команды `plugin command vless set_tuning` и `set_preset`, query `plugin query vless get_tuning`; клиентская ссылка получает параметр `extra` только когда параметры отличаются от значений по умолчанию.
- Сайты-заглушки стали выбираемыми и уникальными для каждой установки: к пяти существующим темам добавлены `portfolio`, `shop`, `apidocs`, `conference`, `gallery` и `cafe`, бренд, палитра, шрифт, тексты и favicon детерминированно выводятся из домена.
- Тему заглушки выбирает оператор командой `set_decoy_theme` у `naive`, `anytls`, `trusttunnel`, `hysteria2` и `vless`, вопросом при первом включении протокола и пунктом в его меню; прежние темы остались значениями по умолчанию.
- Смена темы перегенерирует сайт и атомарно подменяет каталог, помеченный файлом `.hydra-decoy.json` с темой, доменом и отпечатком идентичности; сайт без пометки считается размещённым оператором и не перезаписывается.
- Параметр `utls_fingerprint` для VLESS: клиентский профиль получает блок `tls.utls`, ссылка — `fp=`; по умолчанию `none`.
- Суточная проверка сертификатов через `openssl x509 -enddate`: Sync agent раз в сутки проверяет сроки сертификатов протоколов с собственным доменом, домена сети и домена подписок; истёкший, истекающий в ближайшие 30 дней или отсутствующий сертификат ставит отложенное применение, поэтому preflight переполучает материал через certbot.
- Сертификат сервера подписок продлевается автоматически: проверка вызывает выпуск напрямую и перезапускает `hydra-sub`, неудачное продление снимает отложенное применение после первой неудачи и ждёт следующей суточной проверки.
- Результат проверки сохраняется в state (`certificates_last_check`, `certificates_report`) и выводится в `hydra status` блоком `certificates`; проверка выключается флагом `sync_certificates_enabled`.
- Монолитные composition/lifecycle/UI-модули разделены на application services, инфраструктурные адаптеры, нейтральные contracts и тонкие compatibility facade; добавлены автоматические границы зависимостей, лимиты размеров модулей и функций и графовые проверки связности.
- Добавлен разбор отказов `inbound/vless[...]` в журнале sing-box с извлечением peer port и покрытие VLESS в `hydra antidpi selftest`.
- Экран «Устройства» в карточке пользователя: зарегистрированные устройства с HWID-префиксом и клиентом, активные сессии с адресом, трафиком и пометкой сверх лимита, изменение лимита и сброс привязок.
- Раздел «Устройства и сессии» в мониторинге и строка с числом онлайн-устройств и нарушителей лимита на обзорном экране.
- `hydra user show` и `--json` отдают список устройств, публикуется только префикс полного идентификатора.

### Изменено

- Учёт трафика VLESS + XHTTP сопоставляет соединение Clash API с аутентифицированным пользователем по journal context и source port, байты записываются в общий счётчик и `credentials["vless"]`; «Трафик протокола» показывает учтённые байты и для транспортов без собственных счётчиков, а вкладка «Клиенты» заменена на «Трафик протокола».
- Plugin-owned TLS/HTTP routes стали декларативными: core валидирует порты, путь, каталог и тему, включает их в транзакционный Caddy apply/rollback и очищает динамические loopback firewall rules при остановке.
- Лимит устройств ограничивает одновременные подключения, а не только выдачу подписки: демон трафика группирует активные соединения по адресу источника и закрывает через Clash API те, что принадлежат устройствам сверх лимита; приоритет у подключившихся раньше, короткий разрыв связи не считается новым устройством — сессия помнится 10 минут.
- Запись об устройстве хранит первое и последнее обращение, источник идентификатора (заголовок HWID или определение по адресу и клиенту), `User-Agent` и адрес; схема state поднята до 5 с миграцией.
- Плагины подключаются через instance-scoped `PluginContainer`, явные порты и единый транзакционный lifecycle вместо process-global service locator и прямых вызовов concrete plugins из UI, Telegram и manager-слоя.
- Backup inventory расширяется декларациями плагинов без импорта registry из core, удаление HYDRA проходит через application boundary.
- Долгоживущие systemd units используют стабильный `/opt/hydra` и его `.venv`, поэтому release-каталоги можно атомарно переключать без закрепления старого физического пути.
- В `TelegramConfig` добавлены `notify_only_blocks`, `quiet_hours_enabled`, `quiet_hours_start` и `quiet_hours_end` со значениями по умолчанию, существующий state читается без миграции.
- Версия persisted state поднята с 3 до 4: миграция 2→3 сохранена в точности как выпущенная в 2.5.3, миграция 3→4 переносит legacy-флаги WARP, DNSCrypt и security plugins в канонический `protocols` и добавляет revision.
- AntiDPI: повторы одного сигнала насыщаются (каждое следующее одинаковое событие в окне 15 минут добавляет вдвое меньше предыдущего, ≈23 попытки при частоте раз в секунду), для бана нужны улики двух разных семейств, улики одного типа обязаны набрать полуторный порог, ранее забаненные адреса достигают порога быстрее (−1 за нарушение, не ниже 4), улики агрегируются по подсетям `/24` и `/48` (4 и более адресов в окне 10 минут дают уведомление `COORDINATED`, подсеть намеренно не банится), оповещения показывают требуемый порог, семейства улик и причину незаблокированности.
- AntiDPI: whitelist снимает активные баны, которые накрывает добавленная сеть; память `ban_counts` очищается вместе с объясняющей её записью ban history; отказ firewall при пересечении порога фиксируется в state и виден в TUI и Telegram.
- TUI-экран AntiDPI переработан, Telegram-дашборд показывает GeoIP/ASN, остаток срока, причину на русском и watchlist, кнопки разбана подписаны остатком срока, а `🧾 Подробнее` открывает детальный вид; обе поверхности используют один словарь формулировок.
- Диагностические архивы AntiDPI автоматически скрывают пароли, UUID, PSK, токены и приватные ключи и создаются с mode `0600`.
- Dev-entrypoints согласованы по ветке: `dev/bootstrap.sh`, `dev/updater.sh` и транзакционный `upgrade.sh` без дополнительных переменных выбирают `dev`; добавлен публичный `updater.sh`, launcher полностью скачивает транзакционное ядро до исполнения и удаляет временный файл после завершения.
- Вывод `bootstrap.sh`, `updater.sh` и `upgrade.sh` унифицирован: нумерованные этапы, явный итог `ГОТОВО`/`ОШИБКА`, команда следующего действия и путь к журналу или снимку отката.
- Добавлен `upgrade.sh` для транзакционного перехода существующей установки на точный SHA ветки `dev`: отдельный release и `.venv`, read-only preflight, quiesce HYDRA-служб, два уровня backup, атомарная миграция state, проверка systemd и автоматический откат state/code/wrapper/services; добавлены `hydra upgrade migrate-state`, Linux integration-сценарий main→dev и руководство [`docs/UPGRADE.md`](docs/UPGRADE.md); `bootstrap.sh` остаётся установщиком новой VPS.
- `README.md` переработан в обзорную витрину, подробности перенесены к профильным документам без потери содержания: мотивация модели и границы версии — в `ARCHITECTURE.md`, эксплуатационные сценарии и семантика лимитов — в `CLI.md`, описание заглушек доменных транспортов — в `REFERENCE.md`, локальные проверки и матрица CI — в `PLUGIN_DEVELOPMENT.md`.
- AntiDPI отслеживает VLESS + XHTTP: улики берутся из access-лога decoy того же домена, где Caddy восстановил реальный IP клиента через PROXY v2, отклонённый запрос к XHTTP-пути даёт `auth_failure`, scanner path на домене — `active_decoy_probe`; успешные запросы и ошибки backend (5xx) уликами не считаются, домен и путь перечитываются каждые 60 секунд, записи чужих доменов не затрагиваются.
- Telegram-бот: неизвестная команда больше не отвечает главным меню, ошибки построения экрана видны оператору; уведомления получили режим «только блокировки» и тихие часы с окном через полночь; мониторы fail2ban и honeypot опрашивают журнал раз в 15 секунд на тихом хосте и возвращаются к 2 секундам после новой строки.
- Регистрация устройств подписки выполняется атомарно: stale TUI/daemon saves не стирают новые bindings, явный reset остаётся авторитетным; старые module entrypoints subscription server и sync agent сохранены как исполняемые compatibility facade для уже установленных systemd units.
- TLS-транспорты: перед каждым применением сертификаты включённых TLS-транспортов проверяются на домен, срок действия и соответствие приватному ключу, некорректная сохранённая пара заменяется через certbot; удалены посторонние legacy-пути сертификатов, Caddy больше не получает TLS-маршрут без полной пары сертификата и ключа, а TCP-профиль TrustTunnel явно фиксирует ALPN `h2`.
- Перенесены без потерь device limits, rename/default user, uninstall, SNI preflight, WARP RU/IDN lists, Fail2ban whitelist, AntiDPI alert-only probes и транзакционные исправления Telemt.

### Исправлено

- Переключение VLESS + XHTTP с собственного TLS-домена на Reality больше не возвращает удалённый decoy-маршрут, а сбой перестройки Caddy запускает полный rollback и перезагрузку восстановленного Sing-Box.
- Reality-ссылки и клиентские профили используют обнаруженный публичный IP, когда он не сохранён в `network.server_ip`, та же проверка применяется при включении, а ошибка переустановки остаётся в VLESS-меню вместо сбоя TUI.
- Активация VLESS завершается успешно только после проверки фактического SNI-маршрута, загруженной Caddy пары cert/key и локального TLS handshake с ALPN `h2`, неполный runtime откатывается вместо ложного успешного статуса.
- Исправлен сбой TUI с `StateConflictError` после неудачной команды плагина: сессии устройств, отчёт о сертификатах и источник отложенного применения больше не считаются желаемой конфигурацией, а фоновая запись раз в две секунды не делает открытое меню устаревшим.
- Откат неудачной команды больше не падает из-за чужой записи: снимок восстанавливается поверх текущего состояния с сохранением фоновых счётчиков, экран настроек VLESS сообщает о конкурентном изменении текстом, а причину неудачного применения берёт из `apply_error()`.
- Сервер подписок узнаёт настоящий адрес клиента: за мультиплексором Caddy передаёт PROXY v2, PROXY v2 разбирается на сыром соединении до TLS handshake; раньше `hydra-sub` пытался прочитать заголовок уже из `SSLSocket`, закрывал соединение и клиент получал `Connection closed`, запись об устройстве содержала `127.0.0.1`.
- Исправлена установка ShadowTLS: внутренний Trojan inbound создаётся как injectable detour без фиктивного `listen_port: 0`, поэтому конфигурация проходит общую валидацию и принимается Sing-Box; восстановлен интерактивный запрос домена при включении NaiveProxy, AnyTLS, TrustTunnel и Hysteria2.

## [2.5.3] — 24 июля 2026

### Добавлено

- Переименование пользователя без ротации UUID/секретов и настраиваемый лимит устройств на подписку; HWID хранится только как SHA-256, привязки сбрасываются из TUI или CLI.
- Чистая установка автоматически создаёт первого пользователя `default`.
- Команда полного удаления `hydra uninstall` с обязательным подтверждением `--yes`, режимом `--dry-run` и опцией сохранения данных `--keep-data`.

### Изменено

- TLS ping/config-тесты Karing с парой `unknown_sni + handshake_failure` переведены в alert-only и больше не могут автоматически заблокировать IP.
- Проверка SNI разрешает общий домен для TCP/QUIC-режимов одного протокола, сохраняя конфликт между разными протоколами.
- WARP заранее загружает все встроенные внешние списки при установке; RU-маршрутизация включает `.su`, `.ru`, `.рф` и `.xn--p1ai`.

### Исправлено

- Установка Telemt больше не помечает его включённым до окончания транзакционной установки; установка восстанавливает отсутствующий systemd unit, применяет конфигурацию через стабильный restart с проверкой активности, а настроенные iOS-фикс и SYN-limiter автоматически восстанавливают правила.
- TUI Fail2ban показывает фактический `ignoreip`, включая адрес установочной SSH-сессии, автоматически записанный в `00-hydra-defaults.local`.

## [2.5.2] — 21 июля 2026

### Изменено

- Release-bootstrap по умолчанию загружает ветку `main`; ветка из `HYDRA_REF` сначала разрешается в точный remote SHA, Git update, clone и архивный fallback устанавливают именно этот commit, а до установки Python-зависимостей bootstrap сверяет фактический `HEAD`/маркер архива с выбранным SHA.
- Однострочная команда установки запускается через `curl ... | sudo bash` и не требует Bash process substitution.
- Для ручного `git clone` задокументирован запуск через `.venv` с установкой `requirements.lock` — это устраняет `No module named 'qrcode'` и не смешивает зависимости HYDRA с системным Python; bootstrap явно сообщает о созданной команде `sudo hydra`, простой clone сам launcher в `/usr/local/bin` не создаёт.
- Новая установка AmneziaWG передаёт внешнему инсталлятору адрес `10.67.67.1`, поэтому первый профиль создаётся в `10.67.67.0/24` и не пересекается с qWDTT. `hydra apply` больше не меняет подсеть уже существующего `awg0.conf`: штатная сеть старой установки `10.66.66.0/24` не заменяется молча, автовыбор сети выполняется только при создании нового профиля.
- Status AmneziaWG сверяет runtime со state, fallback-запуск `awg-quick` больше не проглатывает stderr, а восстановление профиля не переиспользует уже занятую подсеть.
- AntiDPI больше не считает штатные junk-пакеты AmneziaWG ошибками handshake, noisy debug path отключён, rejection-события остаются доступными.

### Исправлено

- Certbot для домена подписок освобождает порт 80 также от Caddy L4, временно открывает firewall и гарантированно восстанавливает остановленные веб-службы даже при исключении.
- Первая сборка qWDTT больше не обрывается общим 30-секундным таймаутом: загрузке Go-модулей разрешено до 10 минут, `go build` — до 15 минут.
- Сборка Caddy L4 на чистой системе: checksum закреплённой версии Go ищется в полном списке релизов, таймаут `xcaddy build` увеличен с 30 до 900 секунд.
- Исправлен ложный rollback AnyTLS и Mieru: healthcheck больше не читает устаревший state во время транзакции, а TUI после возврата из вложенных меню больше не показывает только что установленный протокол выключенным.
- Исправлена десериализация `state.json`: ошибка разрешения type hints больше не превращает валидный `PluginState(enabled=true, installed=true)` в пустой объект со значениями по умолчанию; status AnyTLS совмещает сохранённые `installed/enabled` с фактическим наличием Sing-Box.
- Получение сертификата NaiveProxy больше не падает с `Could not bind TCP port 80`, если `:80` занят установленным Caddy L4: активные `caddy-l4`, `caddy-naive`, Nginx и Apache временно останавливаются и гарантированно восстанавливаются после Certbot, включая аварийный выход.
- Выключение AntiDPI удаляет глобальные IPv4/IPv6 DROP-правила, а не только отключает службу и сбор событий.
- AmneziaWG проверяет загрузку kernel module при установке и при включении: если DKMS собрал модуль для нового ядра, а VPS запущена на старом, TUI показывает оба ядра и требуемую перезагрузку.
- Обновление старой установки AmneziaWG не пытается разобрать транспортные значения `network=both/quic/tcp` других протоколов как IP-подсети, ошибка `'both' does not appear to be an IPv4 or IPv6 network` устранена, невалидные legacy-значения игнорируются.
- Загрузчик закрывает writable-дескриптор, возвращённый `mkstemp`, до атомарного перемещения бинарника, устраняя `[Errno 26] Text file busy` при первом `wgcf register` и утечку дескрипторов во всех скачиваниях через общий helper.
- В AntiDPI ALERT добавлена кнопка ручной блокировки IP с проверкой Telegram-администратора, whitelist и штатным progressive ban.

Отдельная благодарность **@Monah99** за помощь в тестировании и предоставление VPS.

## [2.5.1-dev] — «FORTRESS» — 21 июля 2026

### Добавлено

- Самостоятельный плагин `antidpi` — поведенческий IDS/IPS-контур для обнаружения протокольных зондов, неправильной авторизации, malformed handshake, decoy probes, connection burst и сканирования портов; он не расшифровывает пользовательский трафик и не заменяет Fail2ban, а нормализует доказательства из Caddy, Sing-Box, kernel journal и нативных журналов протоколов и применяет единую политику.
- Разделены три независимые зоны ответственности: Fail2ban — SSH и подтверждённые auth-журналы, Honeypot — отдельная ловушка с собственным состоянием и банами, AntiDPI — сетевые и протокольные аномалии на всей поверхности VPS.
- Долгоживущий сервис `hydra-antidpi`, читающий Caddy JSONL, `journald`, kernel LOG и нативные журналы протоколов.
- `hydra-source-relay` с обязательным PROXY Protocol v2 и точным сопоставлением relay source port внешнему IPv4/IPv6 для TCP и QUIC backend даже после loopback-проксирования; для ошибок без endpoint разрешена только ambiguity-safe корреляция.
- Динамические ipset `hydra_antidpi` и `hydra_antidpi6` — только они выполняют enforcement, телеметрические iptables/ip6tables-правила используют `LOG`, а не `DROP`; активные баны восстанавливаются после перезапуска с оставшимся TTL.
- Детекторы для TLS/Caddy L4, HTTPS decoy, AnyTLS, TrustTunnel TCP/QUIC, ShadowTLS, Naive TCP/QUIC, Snell, Hysteria2, AmneziaWG, qWDTT и Mieru; адаптер Telemt сохранён, но транспорт исключён из подтверждённой матрицы.
- Детектор Mieru: серия established TCP-сессий на `2012–2022`, закрывающихся после передачи не более 1 KiB, сигнал alert-only.
- AmneziaWG dynamic-debug нативных rejection paths: `Invalid MAC`, `Invalid handshake` и `unknown peer`, штатные junk-пакеты из `Jc` исключены, `prepare_awg_message` принудительно выключен, его `Unknown message` не считается ошибкой handshake.
- Команды `hydra antidpi sync`, `selftest`, `selftest --full` и `capture`: внешний capture сохраняет дельту событий, журналы, firewall rules, UDP/TCP sockets, source-relay mappings и AWG dynamic-debug.
- Раздельное включение уведомлений AntiDPI, Honeypot, Fail2ban, unban и system events; статистика доставки хранит attempted/delivered/failed без Telegram secrets. ALERT/BAN содержат IP, флаг страны, ASN/владельца, event, protocol, source, signals, observed score, verified score, TTL и offense; inline-кнопка ручной блокировки IP доступна настроенному администратору, соблюдает whitelist, использует штатный прогрессивный ipset-ban и не увеличивает offense при повторном callback.
- Диагностические архивы автоматически скрывают пароли, UUID, PSK, токены и приватные ключи и создаются с mode `0600`.
- Документирован полный переход с legacy-конфигурации: backup, validate/doctor, plan/apply, синхронизация runtime, удаление `hydra-portscan`, перезапуск Telegram bot и контрольная проверка сервисов, ipset и внешних событий.

### Изменено

- Введены два счётчика: `Observed score` для всех сигналов и `Verified score` только для доказательств, которым разрешено влиять на бан; score экспоненциально затухает с half-life 5 минут.
- Обычный ALERT создаётся при observed score `6`, явный `auth_failure` — при `3`; BAN разрешён только при verified score `8` и свежем подтверждённом протокольном событии либо подтверждённом multi-port sweep; сроки бана прогрессивные: 10 минут, 1 час, 24 часа, затем 7 дней.
- Telegram cooldown действует отдельно для каждого IP и протокола, дублирующиеся browser sockets для одного unknown-SNI события объединяются.
- Встроенный whitelist исключает loopback, link-local, RFC1918, ULA, IP самой VPS и пользовательские сети.
- Прямые UDP-сигналы Hysteria2, AmneziaWG и qWDTT считаются наблюдаемыми, но не ban-eligible: они формируют технический ALERT с политикой `alert-only / unverified UDP source` и не увеличивают verified score; Naive QUIC и TrustTunnel QUIC могут стать ban-eligible только после точной атрибуции через source relay и прикладного auth-события.
- Из Fail2ban удалён исполняемый legacy протокольных плагинов, сохранён только миграционный cleanup старых jail/filter и portscan rule, а cleanup прежнего AWG unit больше не отключает rejection logging, принадлежащий AntiDPI.
- Caddy decoy получил отдельную access-телеметрию с сохранением внешнего IP.
- Полный путь от внешнего клиента до Telegram подтверждён на реальной VPS для TLS/decoy, AnyTLS, TrustTunnel, ShadowTLS, Naive TCP/QUIC, Snell, Hysteria2, AmneziaWG, qWDTT и Mieru, включая нативные rejection events, silent-failure fallback, точную source attribution и запрет ложных UDP-банов; спецификация — в [`docs/ANTIDPI.md`](docs/ANTIDPI.md).

### Исправлено

- Исправлен ложный rollback при включении AnyTLS и Mieru: healthcheck проверяет активный Sing-Box и inbound в применяемом конфиге, не перечитывая устаревший флаг `enabled` из сохранённого state во время транзакции.
- TUI перечитывает state после возврата из вложенных меню и после операций AnyTLS, не позволяя старому снимку повторно показать или сохранить протокол выключенным после успешного commit.

## [2.5.0] — 20 июля 2026

### Добавлено

- Единый `HostBackend` для ограниченных команд, файловых операций, `systemd`, firewall, Sing-Box и Caddy; прямые обходы границы блокируются регрессионными проверками. Типизированные контракты возможностей плагинов, результатов жизненного цикла, проверок работоспособности и конфигурационных фрагментов с адаптерами для старых реализаций.
- Единая модель `ErrorCode`, `ApplicationError` и `ServiceResult`; CLI сохраняет старое текстовое поле `error` и дополнительно отдаёт структурированное `error_details`.
- Единый механизм транзакций для применения Sing-Box, nftables, плагинов, включения/отключения, установки/удаления, переустановки и операций пользователей; откат выполняется в обратном порядке, продолжается после локальной ошибки и защищён от повторного завершения.
- Потоковая и межпроцессная блокировки применения, журнал `apply.jsonl`, снимки конфигураций и проверка работоспособности после перезагрузки. Honeypot переведён в самостоятельный жизненный цикл: общий apply не перезапускает его без необходимости и не блокирует включение другого протокола.
- State хранится атомарно, каталоги синхронизируются после замены, повреждённые копии сохраняются отдельно. Миграции оформлены как последовательный реестр `vN → vN+1`, неизвестная будущая схема отклоняется с безопасной ошибкой.
- Сохранённое намерение отделено от неизменяемого снимка фактического состояния, что устраняет ложные статусы вроде «выключено», когда служба реально работает.
- Добавлены `hydra doctor`, `hydra plan`, `hydra reconcile`, `hydra backup`, `hydra restore` и `hydra upgrade check` для контроля системы без ручного редактирования state; `hydra doctor`, `hydra plan` и `hydra status` показывают не только желаемое состояние, но и фактическое состояние служб и рассинхронизацию.
- Резервное копирование и восстановление работают с манифестом, SHA-256, dry-run, защитой от небезопасных путей и автоматической страховочной копией. Проверка `tls_mux` только для чтения: ожидаемые домены из state сравниваются с фактическими SNI-маршрутами Caddy, отдельно сообщаются `missing`, `stale`, ошибки сертификатов, повреждённый JSON-конфиг и неактивный `caddy-l4`.
- DNSCrypt, Fail2ban, IPBan, WARP, Telemt и Honeypot переведены на общую границу команд хоста и жизненного цикла.
- Служба учёта трафика получила более строгий контроль монотонных счётчиков и повторное применение после неудачных обновлений. Усилены предварительные проверки зависимостей, конфликтов портов, nftables, Caddy и Sing-Box.
- Компоненты интерфейса для протоколов, сетевой информации, логов и системного монитора вынесены в тестируемые модули без изменения пользовательского меню.

### Изменено

- CLI и TUI используют прикладные службы и явные зависимости через корневую сборку приложения вместо создания глобальных объектов вручную.
- Пользователи могут иметь обычные идентификаторы (`test`) или email, старые записи и UUID сохраняют совместимость.
- State schema остаётся `2`: существующие пользователи, UUID, credentials, сертификаты и настройки протоколов не требуют ручной миграции.
- Перед обновлением рекомендуется `sudo hydra backup`, затем `sudo hydra upgrade check`, `sudo hydra validate` и `sudo hydra apply`.
- REST API и web-панель в этот релиз не входят; Telegram-бот остаётся отдельным этапом, его рабочий контракт и проверочные сценарии ещё не объявляются стабильными.
- Удалены неиспользуемые устаревшие пути и дублирование кода представления, совместимые миграции и адаптеры сохранены намеренно.
- CI проверяет Python 3.10–3.13, компиляцию, стиль кода, зависимости и Linux-проверки на реальной системе; полный локальный набор — **630 passed**, тесты сценариев отказа проверяют не только исключение, но и отсутствие побочных изменений, корректность отката и возможность повторного запуска.

## [2.4.1] — 19 июля 2026

### Добавлено

- Имя пользователя может быть обычным идентификатором или email; добавлен JSON CLI для `status`, `validate`, `plan`, `apply`, `user list` и диагностики.
- Добавлены файлы фиксации зависимостей, проверка зависимостей и CI для Python 3.10–3.13.

### Изменено

- Транзакционный оркестратор получил блокировку, журналирование, снимки Sing-Box и nftables, автоматический откат, проверку работоспособности служб и понятную причину последней ошибки.
- State: структурная проверка, атомарная запись, восстановление из `.bak`, сохранение `.corrupt`, права `0600` и совместимость со старыми схемами state.

### Исправлено

- Исправлены очередь повторных попыток применения конфигурации, ручные проверки, обновление Sing-Box, учёт DNSCrypt, Fail2ban, AmneziaWG, WDTT, проверка целостности бинарников и установщик.

## [2.4.0] — 18 июля 2026

### Добавлено

- ShadowTLS v3, Hysteria2, Snell v4, расширенные подписки, мониторинг пользователей, qWDTT, сетевой autotuning и унифицированные экраны протоколов.

## [2.3.5] — 17 июля 2026

### Добавлено

- Монотонный учёт трафика и улучшенный TUI для AmneziaWG.

### Изменено

- Внедрён транзакционный цикл `configure → validate → apply → commit/rollback`.

### Исправлено

- Исправлено управление портами и firewall.

## [2.3.4] — 11 июля 2026

### Добавлено

- Кастомные WARP-профили WireGuard/AmneziaWG и раздельная маршрутизация списков WARP.

## [2.3.3] — 9 июля 2026

### Добавлено

- Изолированные Fail2ban jail, мастер обфускации AmneziaWG и поддержка Mieru с пресетами и ссылками `mierus://`.

## [2.3.2] — 9 июля 2026

### Добавлено

- Сборка для ARM64/AMD64.

### Изменено

- Мультиплексор перенесён с HAProxy на Caddy L4.

### Исправлено

- Исправлены конфликты портов NaiveProxy.

## [2.0.0] — базовый публичный релиз

### Добавлено

- Первая помеченная тегом версия проекта; более ранняя история сохраняется в Git.
