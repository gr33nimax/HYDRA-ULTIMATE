# Операционный справочник

Реестр всего, что HYDRA размещает на хосте: службы, каталоги, файлы состояния,
журналы, порты и переменные окружения установщиков. Документ предназначен для
аудита, настройки firewall, мониторинга и разбора инцидентов.

## Содержание

- [Модули](#модули)
- [Systemd-службы](#systemd-службы)
- [Каталоги и файлы](#каталоги-и-файлы)
- [Состояние в `/var/lib/hydra`](#состояние-в-varlibhydra)
- [Журналы](#журналы)
- [Сетевые порты](#сетевые-порты)
- [Формат persisted state](#формат-persisted-state)
- [Переменные окружения](#переменные-окружения)
- [Быстрая диагностика](#быстрая-диагностика)

## Модули

Канонические имена плагинов — это ключи в `state.protocols`. Они же используются
в выводе `hydra status` и `hydra check`.

Плагины разделены на три категории; фильтр доступен как
`hydra plugin list --category {transport,enhancement,security}`.

### `transport` — транспорты

| Ключ | Название | Назначение |
| :--- | :--- | :--- |
| `amneziawg` | AmneziaWG 2.0 / 3.0 / 3.1 | WireGuard-транспорт: туннель обслуживает ядро, режим — поле конфига |
| `mieru` | Mieru | Обфусцированный mTLS-транспорт с ссылками `mierus://` |
| `naive` | NaiveProxy | HTTP/2-прокси на базе Caddy forward-proxy; UoT вкл/выкл |
| `anytls` | AnyTLS | TLS-подобный обфусцированный туннель |
| `trusttunnel` | TrustTunnel | TLS-транспорт с режимами TCP/QUIC и сайтом-заглушкой |
| `hysteria2` | Hysteria2 | QUIC-транспорт с Salamander и браузерной заглушкой |
| `vless` | VLESS + XHTTP | XHTTP-транспорт Hydracore: свой домен с сертификатом либо Reality с чужим рукопожатием |
| `vless_cdn` | VLESS + CDN | VLESS через внешний CDN: XHTTP packet-up, uplink GET; origin-порт ядра выделяется автоматически, публикация — на стороне CDN |
| `shadowtls` | ShadowTLS | ShadowTLS v3 с Trojan detour |
| `snell` | Snell 5/6 | TCP/UDP-прокси Hydracore: поколение 5 с `obfs_mode` `none`/`http`/`tls` или поколение 6 с `mode` `default`/`unshaped`/`unsafe-raw` |
| `mtproto_zig` | MTProto Zig | FakeTLS MTProxy: напрямую на TCP/443, за Caddy L4 по SNI или WEB-мост для Telegram Desktop 7.1+ |
| `calls` | Hydra VK Tunnel | Native `call`: только Hydracore VK-parasite; профиль подписки «Обход БС» |
| `wdtt` | qWDTT | WireGuard-туннелирование поверх TURN |

**Calls · VK.** Требует ядро Hydracore с ролью `vps` и режимом `vk_parasite`;
stock/P2P отклоняются. Пул — 4 VK-комнаты на `56002/udp`, blue/green: новое
поколение поднимается до commit, прежнее снимается только после проверки, при
сбое откат. Пул пересоздаётся из меню `Calls · VK` или по расписанию (интервал
1–24 ч). VK cookies импортируются в меню локальным JSON и хранятся в
`/etc/hydra/cookiesvk/cookies-vk.json` (`0600`).

**qWDTT** не использует cookies и creator-пул; владеет только своим сервером и
master-артефактом `qwdtt://`.

Профиль native Calls и qWDTT master-link — административные shared secrets, в
пользовательские подписки не входят. HYDRA редактирует join-links в своих
проекциях логов; upstream Sing-Box пишет их в INFO journald, поэтому сырой
`journalctl -u sing-box` держите закрытым.

Сайт-заглушка на собственном домене есть у AnyTLS, TrustTunnel, Hysteria2,
NaiveProxy, VLESS + XHTTP, VLESS + CDN и MTProto Zig (каталог `/var/www/decoy-zig`). VLESS требует отдельный домен: XHTTP
занимает настроенный путь (`/xhttp` по умолчанию), а остальные URL этого домена
обслуживает сайт из `/var/www/decoy-vless`; у VLESS + CDN свой каталог
`/var/www/decoy-cdn`. Транспорт XHTTP настраивается
поштучно или готовым профилем, см. [CLI.md](CLI.md#плагины).

Тема заглушки выбирается оператором из 11 вариантов (`landing`, `blog`, `docs`,
`media`, `status`, `portfolio`, `shop`, `apidocs`, `conference`, `gallery`,
`cafe`) при включении протокола и позже в его меню. Бренд, палитра, шрифт и
тексты выводятся из домена, поэтому одинаковых установок не бывает. Каталог
сайта содержит `.hydra-decoy.json` с темой, доменом, отпечатком идентичности и
SHA-256 исходников встроенных рендереров — по ним определяется необходимость
перегенерации. Marker старого формата без SHA-256 вызывает одну безопасную
пересборку при следующем apply.

Клиентские ссылки и профили выдаются через сервер подписок и TUI; Mieru
использует схему `mierus://` с единственным диапазоном `2012-2022`. В TUI URI
и JSON-конфигурации печатаются отдельными строками без рамок и отступов, чтобы
копирование из SSH-терминала не меняло содержимое. Ссылка подписки строится из
state и печатается независимо от службы; сама выдача работает, пока запущен
`hydra-sub.service` и у него есть валидная пара сертификат/ключ. Пару выбирает
`find_any_cert` при старте сервера подписок и повторно — при показе ссылок в TUI
(`admin.subscription_certificate`).
Auto endpoint распознаёт NekoBox, Shadowrocket и Throne по `User-Agent`; для
ручного выбора доступны `format=nekobox`, `format=shadowrocket`,
`format=throne` и `format=singbox`. Shadowrocket получает Naive TCP двумя
ссылками — `https://` (HTTP/1.1) и `http2://` (HTTP/2), Naive QUIC — `http3://`;
параметр `alpn` сервер не выставляет.
TCP-варианты включают `uot=2` и `tfo=1`, а все три варианта — `padding=1`,
TrustTunnel с official TLV, а Snell сохраняет `obfs-mode`/`obfs-host` классической
пары и пропускает профиль поколения 6 без перезаписи формата подписки.

Naive собирается из закреплённого форка Caddy и ставится только после валидации
бинарника; замена — с backup предыдущего рабочего файла.

UoT (UDP через TCP) можно выключить: `set_uot` в CLI или пункт «UDP через TCP
(UoT)» в настройках NaiveProxy. Значение по умолчанию — включено (поведение без
изменений). Выключение собирает Caddy из upstream `forwardproxy` без UoT-кода и убирает
`uot` из клиентских ссылок Shadowrocket; `tfo` и `padding` остаются.
При выключенном UoT UDP по TCP-профилю Naive не ходит (QUIC-профиль не затронут),
а клиенты с явным `udp_over_tcp` должны выключить его на своей стороне.
Если установленный бинарник не соответствует настройке, apply пересобирает его;
состояние видно командой/меню, а не угадывается.

Hysteria2 по умолчанию использует `8443/udp`. Если профиль работает по Wi-Fi,
но не работает через мобильную сеть, сначала проверяют доступность UDP/8443 у
оператора и внешнего firewall: HYDRA не передаёт настройки в 3x-ui и не зависит
от него. NaiveProxy требует, чтобы используемый клиент поддерживал Naive либо
имел соответствующий внешний модуль; отсутствие клиентского модуля нельзя
исправить серверной конфигурацией.

Формат подписки `?format=singbox` собирается из plugin-owned клиентских
проекций. Для AmneziaWG 2.0 он содержит отдельный `wireguard` endpoint Sing-Box
Extended для каждого доступного desktop/mobile профиля. Параметры `Jc`, `Jmin`,
`Jmax`, `S1`–`S4`, `H1`–`H4` и `I1` находятся во вложенном объекте `amnezia`;
`route.final` ссылается на первый AWG endpoint. Для AWG 3.0 Sing-Box Extended
и HydraBox получают source-proven `amnezia` поля; AWG 3.1 выдаётся там же,
когда установлено ядро HydraCore `v1.14.0-extended-2.7.1-hydracore.12` или
новее: оно несёт оба поля поколения (`random_trailers`, `disable_cookies`).

Серверную сторону AmneziaWG обслуживает само ядро: HYDRA выдаёт по одному
`wireguard` endpoint на профиль вместе с выписанными пирами. Адреса, ключи и
материал поколения живут в состоянии, ключи считает сама HYDRA, режим 2.0/3.0/3.1
меняется конфигом ядра и читается обратно из него. Удаление протокола не трогает
пакетный менеджер и kernel module. Профили выдаются заново — клиенты импортируют
конфигурацию повторно.
На более старом ядре экспорт 3.1 остаётся fail-closed с причиной, называющей
требуемый релиз.
`wg://` (complete-ссылка со всеми директивами поколения) получают клиенты, которые её понимают:
Throne (проверено на `1.3.0-beta.3`) и NekoBox, импортирующий её как AmneziaWG
(проверено на устройстве); официальный Amnezia получает
Qt-compressed `vpn://` с полным `last_config`. Нативный `.conf` доступен для всех
поколений, а NekoBox-формат `sn://awg` — только для профилей без
`RandomTrailers`/`DisableCookies`: совместимость его 3.x-импортёра не подтверждена,
и поля поколения в нём не едут.

`?format=hydrabox` — защищённый формат для HydraBox. Запрос требует
`User-Agent: HydraBox/<version>` и reported HWID (`X-HWID`; legacy
`X-Hydra-HWID: hbx1_…` совместим). Сервер хеширует HWID и не хранит сырой.
Неверная идентификация → HTTP 400, превышение лимита устройств → HTTP 403.

Ответ — flattened JWE (`dir` + `A256GCM`, media type `application/jose+json`),
plaintext-fallback нет. Каждый транспорт публикуется отдельным ресурсом
`sing-box-json`; при включённом Calls добавляется изолированный `call`-outbound
без серверных cookies (неполный пул отклоняет выдачу fail-closed). qWDTT в
подписку не попадает. Ссылка выдаётся как
`https://<origin>/sub/<id>?format=hydrabox#hydra-key=<key>`: 256-битный ключ
живёт только во fragment (HTTP-серверу не передаётся) и в private state;
`status`, логи и публичный JSON показывают только производный `kid`. Ротация
ключа немедленно инвалидирует прежние ссылки.

Бинарник `mtproto_zig` ставится из upstream-релиза с архивом под архитектуру
хоста: SHA-256 проверяется до распаковки, замена атомарна, при любой ошибке
сохраняются прежний бинарник и состояние службы. Флаг
`HYDRA_ALLOW_UNVERIFIED_DOWNLOADS` на этот путь не распространяется. Собственные
`bootstrap.sh`/`mtbuddy` upstream не запускаются.

У транспорта `mtproto_zig` есть три режима доступа, которые переключаются строкой
`🌐 Режим WEB` в его настройках:

| Режим | Что выдаётся клиенту | Прямой вход |
| :--- | :--- | :--- |
| `off` (по умолчанию) | только обычная `tg://proxy`-ссылка FakeTLS | работает |
| `hybrid` | FakeTLS-ссылка и `tg://webproxy` | работает |
| `web-only` | только `tg://webproxy` | закрыт: маршрут FakeTLS снят с фронтенда, прежние `tg://proxy`-ссылки не подключаются |

WEB-ссылка (`tg://webproxy?server=<домен>&secret=dd<32-hex>`) требует **отдельный домен оператора**
с A-записью на этот сервер и публичный TLS-сертификат: Telegram Desktop отклоняет IP и однословные
имена, а прикрываемый FakeTLS-домен (например `max.ru`) остаётся чужим именем и сертификата не
требует. Управляемый фронтенд `caddy-l4` остаётся единственным владельцем TCP/443: он завершает
TLS для WEB-домена и передаёт расшифрованный HTTP/WebSocket-поток на loopback-релей
`mtproto-zig-web.service` (`127.0.0.1:8081`), запущенный тем же проверенным бинарником
(`mtproto-zig web-relay`). Собственных `nginx`, `/opt/mtproto-proxy`, юнитов и firewall-правил
Hydra не создаёт.

Переход в `web-only` staged: релей поднимается, фронтенд рендерится без маршрута
FakeTLS (прежние прямые ссылки перестают работать на этой стадии), затем мост
проверяется реальным клиентским подключением через `:443` перед коммитом. Если
мост не подтверждён (в том числе когда нет активных пользователей), снапшот
возвращает прежний режим, маршрут и выданные ссылки, а ошибка видна оператору.
Смена WEB-домена ломает все выданные WEB-ссылки и требует подтверждения.
Ограничение v1: per-IP лимиты Zig к WEB-клиентам не применяются.

### `enhancement` — сетевые расширения

| Ключ | Название | Назначение |
| :--- | :--- | :--- |
| `dnscrypt` | DNSCrypt | Локальный шифрованный DNS-резолвер |
| `warp` | WARP (MASQUE) | Выборочная маршрутизация через Cloudflare по HTTP/3 CONNECT-IP |

WARP применяет списочные маршруты только когда enhancement включён. Цель `warp`
обслуживает само ядро: HydraCore регистрирует устройство в Cloudflare API и
говорит с ним по MASQUE (HTTP/3 CONNECT-IP), поэтому внешний установщик профиля
и файлы WireGuard не нужны. Цель `warp_<name>` — соответствующий relay-профиль
из `/etc/hydra/warp_profiles`. Релей нельзя удалить, пока на него направлен
хотя бы один список: сначала выберите для этих списков другой выход.
Отсутствующая цель считается ошибкой конфигурации
и блокирует apply, чтобы трафик не ушёл напрямую незаметно для оператора.
Профиль устройства кэшируется в `cache_file` sing-box (`store_masque_config`):
перезапуск службы не создаёт новое устройство в аккаунте Cloudflare, а снос
кэша — создаёт. `sudo hydra plugin reinstall warp` (или «🔄 Переустановить» в
меню) обновляет каталог, сохраняет настроенные маршруты и их кэш правил.
Кэш правил остаётся на диске даже после удаления плагина; правила из него не
применяются, пока WARP выключен. Меню несёт обычный жизненный цикл плагина:
«🔧 Установить», «▶️ Включить/⏸️ Выключить», «🔄 Переустановить», «❌ Удалить»
(удаление снимает маршруты, но оставляет кэш правил для безопасной
переустановки).

В меню «Сервер подключения WARP» можно запустить warpscout **с этой VPS**,
выбрать один найденный MASQUE/UDP `IP:port` или вернуть автоматический выбор
HydraCore. Это не настройка страны выхода и не изменение релеев `warp_<name>`.
warpscout должен быть установлен оператором из проверенного релиза; при первом
поиске отдельно подтверждается регистрация его устройства. Файл учётной записи
хранится в `/var/lib/hydra/warpscout/account.json` (`0600`, каталог `0700`),
не в state. Поиск не меняет маршруты и не запускается при apply. Результаты
живут только в текущем экране TUI. Закреплённый адрес хранится в
`protocols.warp.config.masque_endpoint` и сохраняется при выключении и
переустановке WARP; удаление WARP снимает настройку, но не удаляет учётную
запись сканера. При выборе адреса ядро применяет конфигурацию и проверяет
`warp=on` через отдельный SOCKS-вход `127.0.0.1:11880`, который направлен
строго в `warp`. При неудаче общий apply откатывает config и state.
Выбранный вручную адрес проверяется на каждом последующем apply; недоступность
Cloudflare либо `curl` блокирует изменение вместо подтверждения мнимого успеха.
На Windows unit-тесты не заменяют проверку на Linux/VPS.

Списки отдельных сервисов берутся из каталога Geo-Aggregator (`db/catalog.json`).
Из сводных списков сохранён только `category-ru` (вместе с доменными суффиксами
`.ru`, `.su`, `.рф`, `.xn--p1ai`); остальные `category-*`, все `itDog-*`,
`refilter` и `antifilter` исключены из каталога и меню. Каталог кэшируется в
`/var/lib/hydra/warp_catalog.json` и обновляется ежедневно. До первой успешной
загрузки внешних сервисов доступен лишь `category-ru` из встроенной копии;
локальный список доменов WARP также работает без сети. Для маршрута по
`category-ru` его данные должны быть скачаны в кэш правил.

В меню можно направить всю категорию сервисов или выбрать один источник
внутри неё, включая единственный сводный `category-ru` (поиск и страницы
по 20, `[n]`/`[p]`). Цель маршрута — `warp`, настроенный релей или `direct`.
`direct` означает выход с VPS,
а не обязательно российский адрес. Он совпадает с маршрутом по умолчанию при
отсутствии иных совпадающих правил, но служит явным исключением для точного
домена или подсети. Более узкие доменные суффиксы и IP-префиксы ставятся раньше
широких; при совпадении точного значения `direct` имеет приоритет. Если
выбранный внешний список отсутствует или пуст в кэше, применение останавливается
с ошибкой, а не переводит его трафик незаметно на `direct`. Сохранённые ссылки
на удалённые широкие источники также блокируют apply до перенастройки.

### `security` — защита

| Ключ | Название | Назначение |
| :--- | :--- | :--- |
| `antidpi` | AntiScan | Доказанные отказы протоколов и сканы decoy-сайтов с динамическим ipset |
| `fail2ban` | Fail2ban | Блокировка SSH и аутентификационных атак |
| `honeypot` | Honeypot | Обнаружение сканирования портов |
| `ipban` | IPBan | Статические списки IP/CIDR/ASN/стран |

Учёт трафика и применение лимитов выполняет служба `hydra-traffic-daemon` — она
принадлежит ядру и плагином не является.
Первый poll после запуска использует baseline без начисления уже увиденных
байтов, поэтому общий и пользовательский счётчики не получают двойное
начисление.
Для VLESS + XHTTP демон сопоставляет `sourcePort` активного соединения Clash API
с аутентифицированным именем пользователя из того же journal context Sing-Box,
поскольку сам Clash API не возвращает `metadata.user`. Если VLESS работает за
Caddy, тот же source port используется для точного поиска внешнего IP в
`hydra-source-relay`; в сессии сохраняется клиентский адрес, а не loopback-хоп.

Для Hydra VK Tunnel Clash runtime type `call/...` нормализуется в имя плагина
`calls`. Per-user учёт требует, чтобы серверный Hydracore экспортировал уже
аутентифицированное имя Calls-пользователя как `metadata.user`; демон не
угадывает владельца соединения по общему UDP-порту или IP-адресу.

## Systemd-службы

### Службы HYDRA

| Unit | Роль |
| :--- | :--- |
| `hydra-antidpi.service` | Коллектор и enforcement AntiScan |
| `hydra-honeypot.service` | Ловушка сканирования портов |
| `hydra-source-relay.service` | TCP source-relay: PROXY v2 → loopback backend |
| `hydra-udp-source-relay.service` | UDP source-relay для QUIC-маршрутов |
| `hydra-caddy-source.service` | Обработчик source-транспарентности Caddy |
| `hydra-sub.service` | Сервер подписок |
| `hydra-traffic-daemon.service` | Учёт трафика, применение лимитов/сроков и sampler активной Calls-телеметрии |
| `hydra-sync-agent.service` | Периодические задачи: лимиты пользователей, обслуживание плагинов, суточная проверка TLS-сертификатов, обновление Sing-Box |
| `hydra-sync-agent.timer` | Расписание sync agent |
| `hydra-tg-admin.service` | Telegram Admin Bot |

HYDRA не создаёт debug-юниты AmneziaWG. Если `hydra-awg-fail2ban-debug.service`
или `hydra-awg-antidpi-debug.service` остались на хосте, сверка снимает их
(`systemctl disable --now`) вместе с debug-хуком ядра.

Legacy unit `hydra-tg-bot.service` сохранён только для удаления на старых
установках; новый код его не создаёт.

### Внешние службы под управлением HYDRA

| Unit | Роль |
| :--- | :--- |
| `sing-box.service` | Основное ядро транспортов и маршрутизации |
| `caddy-l4.service` | TLS/SNI-мультиплексор на общем TCP/443 |
| `caddy-naive.service` | Caddy forward-proxy для NaiveProxy |
| `mtproto-zig.service` | FakeTLS MTProxy, запускаемый непривилегированным `mtproto-zig` с `CAP_NET_BIND_SERVICE` |
| `mtproto-zig-web.service` | WEB-релей mtproto.zig: `mtproto-zig web-relay`, loopback `127.0.0.1:8081`, без capabilities |
| `wdtt.service` | Демон qWDTT |
| `hydra-headless-creator-vk-calls@.service` | Отдельные поколения 1–4 VK-комнат Hydracore Calls |
| `fail2ban.service` | SSH и auth jails |

> [!NOTE]
> Долгоживущие units ссылаются на стабильный `/opt/hydra` и интерпретатор
> `/opt/hydra/.venv/bin/python`, а не на физический release-каталог. Поэтому
> транзакционное ядро `upgrade.sh` может атомарно переключать release без правки
> unit-файлов; публичный запуск выполняется через `updater.sh`.

## Каталоги и файлы

### Программные пути

| Путь | Содержание |
| :--- | :--- |
| `/opt/hydra` | Стабильная точка входа установки (символьная ссылка на release) |
| `/opt/hydra/.venv` | Изолированное Python-окружение |
| `/opt/hydra-releases` | Каталог изолированных release для updater |
| `/usr/local/bin/hydra` | Wrapper команды `hydra` |
| `/usr/local/bin/sing-box` | Проверенный Hydracore VPS debug binary |
| `/usr/local/bin/caddy-l4` | Бинарник Caddy с модулем layer4 |
| `/usr/local/bin/mtproto-zig` | Проверенный upstream бинарник mtproto.zig |

### Конфигурации

| Путь | Содержание |
| :--- | :--- |
| `/etc/hydra` | Служебные конфигурации HYDRA |
| `/etc/sing-box/config.json` | Сгенерированная конфигурация Sing-Box |
| `/etc/systemd/system/sing-box.service.d/90-hydra-memory.conf` | Общий `GOGC=50` без жёсткого memory cap |
| `/etc/systemd/system/hydra-headless-creator-vk-calls@.service` | Template unit отдельного VK-parasite Calls-пула |
| `/etc/systemd/journald.conf.d/90-hydra-journald.conf` | Бюджеты постоянного и runtime-журнала |
| `/etc/caddy-l4/config.json` | Сгенерированная конфигурация TLS-мультиплексора |
| `/etc/nftables.conf` | Правила nftables, включая TPROXY |
| `/etc/iptables/rules.v4` | Сохранённые правила iptables (DROP-правила банов AntiScan) |
| `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` | Конфигурация DNSCrypt |
| `/etc/hydra-mtproto-zig/config.toml` | Конфигурация mtproto.zig; при SNI-mux слушает только `127.0.0.1:20449`, а `[web]` описывает WEB-релей |
| `/var/lib/hydra/mtproto-zig/traffic-totals.json` | Накопленные per-user байты метрик mtproto.zig |
| `/etc/hydra/cookiesvk/` | Единый закрытый каталог провайдера VK; права `0700` |
| `/etc/hydra/cookiesvk/cookies-vk.json` | VK Creator JSON только для native Calls; импортируется через Calls TUI, файл `0600`, не входит в state |
| `/var/lib/hydra/calls/vk/native.join` | Только legacy-артефакт для cleanup при uninstall; новый Calls его не создаёт и не читает |
| `/var/lib/hydra/calls/vk/pool/` | Multi-user Calls metadata и join-links двух поколений; `0700/0600` |
| `/etc/wdtt/qwdtt_link.txt` | Единственная master qWDTT-ссылка с актуальным упорядоченным списком хешей |
| `/run/lock/hydra-calls.lock` | Межпроцессная сериализация Calls room-pool/lifecycle транзакций |
| `/etc/cron.d/hydra-traffic` | Только legacy-путь для cleanup при uninstall: расписания HYDRA не создаёт, учёт ведёт служба `hydra-traffic-daemon` |

При обновлении бинарника Sing-Box HYDRA сначала сохраняет снимок
`/etc/sing-box/config.json`, затем атомарно мигрирует только собственный legacy
DNS default на схему `type/server/domain_resolver` и проверяет результат новым
ядром. Перед запуском нового ядра пересоздаётся `sing-box.service`: его bounding
и ambient capability sets включают `CAP_NET_RAW`, необходимую новым UDP dialer
для повторного `SO_BINDTODEVICE`. Если проверка конфигурации или запуск службы
завершается ошибкой, транзакция восстанавливает и прежний бинарник, и исходный
конфиг. DNS-секция, принадлежащая плагину, автоматически не переписывается.

`hydra apply` сравнивает установленный `sing-box.service` с актуальным unit.
При расхождении выполняется полный restart, чтобы новый capability set получил
уже запущенный процесс; при совпадении сохраняется обычный graceful reload.

### Сайты-заглушки

| Путь | Владелец |
| :--- | :--- |
| `/var/www/decoy-a`, `/var/www/decoy-b`, `/var/www/decoy-c` | Общие decoy-сайты Caddy L4 |
| `/var/www/decoy-hysteria2` | Браузерная заглушка Hysteria2 |
| `/var/www/decoy-vless` | Отдельная media-заглушка VLESS + XHTTP |
| `/var/www/naive-fake` | Заглушка NaiveProxy |

Управляемая HYDRA заглушка содержит `.hydra-decoy.json` с темой, доменом,
отпечатком идентичности и ревизией рендерера. При apply старые встроенные
страницы без marker распознаются по строгому отпечатку и атомарно мигрируют в
этот формат, поэтому смена темы работает и после обновления прежней установки.
Неизвестный сайт без marker считается созданным оператором и не
перезаписывается.

### Резервные копии

| Путь | Содержание |
| :--- | :--- |
| `/var/backups/hydra/upgrades` | Постоянные снимки транзакционного обновления |

## Состояние в `/var/lib/hydra`

| Файл | Владелец | Содержание |
| :--- | :--- | :--- |
| `state.json` | ядро | Единственный источник истины желаемой конфигурации |
| `state.json.bak` | ядро | Предыдущая проверенная ревизия |
| `state.json.corrupt` | ядро | Изолированная копия повреждённого файла |
| `state.lock` | ядро | Файловая блокировка чтения/записи |
| `master.key` | ядро | Ключ шифрования чувствительных значений |
| `antidpi.json` | `antidpi` | Активные баны с уликой, offense counters, whitelist и курсор журнала. Поле `scores` читается ради непрерывности offense и улик ручного бана, но в операторские проекции не попадает; `subnets` не используется |
| `honeypot.json` | `honeypot` | События и собственные баны ловушки |
| `ipban.json` | `ipban` | Статические списки блокировок |
| `ip-intel-cache.json` | сервисы | Кэш GeoIP/ASN для уведомлений |
| `caddy-source-state.json` | ядро | Состояние source-транспарентности |
| `network-tuning-backup.json` | ядро | Исходные значения sysctl до тюнинга |
| `warp_external.json` | `warp` | Скачанные списки правил WARP |
| `warp_catalog.json` | `warp` | Кэш каталога источников Geo-Aggregator |

> [!WARNING]
> `state.json` записывается только через `save_state()`/`update_state()` —
> атомарно, с backup, fsync и проверкой ревизии. Ручная правка файла ломает
> optimistic concurrency и может привести к потере изменений другого процесса.
> Фактическое состояние служб в state не хранится: оно вычисляется через
> runtime-проекции.

## Журналы

| Путь | Содержание |
| :--- | :--- |
| `/var/log/hydra/install.log` | Журнал `bootstrap.sh` |
| `/var/log/hydra/upgrade.log` | Журнал updater (права `0600`) |
| `/var/log/hydra/apply.jsonl` | Структурированный журнал транзакций применения |
| `/var/log/hydra/traffic-daemon.log` | Демон учёта трафика |
| `/var/log/hydra/sync-agent.log` | Агент периодического обслуживания |
| `/var/log/hydra-honeypot.log` | События ловушки |
| `/var/log/caddy-l4/antidpi.jsonl` | Не создаётся с 3.0.0: generic-TLS наблюдения удалены, файл можно удалить вручную |
| `/var/log/caddy-naive/access.log` | Access-журнал NaiveProxy |
| `/var/log/fail2ban.log` | Журнал Fail2ban |

Журналы служб доступны через systemd:

```bash
journalctl -u sing-box -u caddy-l4 --no-pager -n 100
journalctl -u hydra-antidpi -u hydra-source-relay -u hydra-tg-admin -n 150 --no-pager
```

Bootstrap и updater поддерживают общий журнал в пределах 128 MiB, runtime-журнал
в пределах 64 MiB и файлы журнала не крупнее 16 MiB. При установке policy текущий
journal сначала ротируется, затем архивы очищаются до 128 MiB; это ограничивает
рост на всех VPS без отдельного resource-профиля.

## Сетевые порты

Значения ниже — заводские значения по умолчанию. Фактические порты хранятся в
state (`protocols[*].port`, `network.*`) и настраиваются через TUI; проверяйте их
командой `hydra status`.

### Внешние (публикуются в интернет)

| Порт | Транспорт | Владелец |
| ---: | :--- | :--- |
| `443/tcp` | TCP | Caddy L4 — общий SNI-мультиплексор для NaiveProxy, AnyTLS, TrustTunnel, ShadowTLS и VLESS + XHTTP |
| `443/udp` | UDP | Один QUIC-транспорт: NaiveProxy **или** TrustTunnel |
| `8443/udp` | UDP | Hysteria2 |
| `51820/udp`, `51821/udp` | UDP | AmneziaWG |
| `56000/udp` | UDP | qWDTT — DTLS/TURN |
| `56001/udp` | UDP | qWDTT — WireGuard |
| `56002/udp` | UDP | Hydra VK Tunnel — Hydracore VK Calls VK-parasite listener |
| `2012–2022/tcp` | TCP | Mieru (диапазон) |
| `32000–32999/tcp` | TCP | Snell (диапазон) |
| `9443/tcp` | TCP | Сервер подписок (обычно за Caddy L4 по домену) |
| `9999/tcp` | TCP | Honeypot — ловушка сканирования |

> [!IMPORTANT]
> UDP/443 нельзя распределить по SNI. Прямым владельцем этого порта может быть
> только один QUIC-транспорт; конфликт отклоняется до применения конфигурации.
> Hysteria2 владельцем UDP/443 не является: его UDP-порт и TCP-заглушка
> управляются отдельно.

### Локальные (только loopback)

| Адрес | Назначение |
| :--- | :--- |
| `127.0.0.1:2021` | Admin API `caddy-l4` (намеренно не `2019`, чтобы не конфликтовать со сторонним Caddy) |
| `127.0.0.1:5300` | DNSCrypt-резолвер (`network.dnscrypt_port`) |
| `127.0.0.1:9000` | Локальный TUN-порт qWDTT |
| `127.0.0.1:9090` | Clash API Sing-Box, если включён (`network.clash_api_port`) |
| `127.0.0.1:20448` | Внутренний VLESS + XHTTP inbound Sing-Box |
| `127.0.0.1:10804` | HTTP-router и сайт-заглушка домена VLESS + XHTTP |
| `127.0.0.1:21448` | PROXY v2 source-relay для VLESS за Caddy |
| `1081` | TPROXY Sing-Box, если включён (`network.tproxy_port`) |

Порты source-relay назначаются динамически на loopback и сопоставляются с
внешними endpoint в памяти процесса; см. [ANTIDPI.md](ANTIDPI.md).

### ipset

| Набор | Содержание |
| :--- | :--- |
| `hydra_antidpi` | Активные баны AntiScan, IPv4 |
| `hydra_antidpi6` | Активные баны AntiScan, IPv6 |

## Формат persisted state

В ветке `dev` используется стабильный State Format **v1** — один на весь
репозиторий, от ветки не зависит. Корень
`state.json`:

| Поле | Тип | Содержание |
| :--- | :--- | :--- |
| `format_version` | `int` | Версия envelope, не версия приложения или feature |
| `revision` | `int` | Монотонная ревизия желаемой конфигурации |
| `core` | `object` | `install`, `users`, `telegram`, `network`, `configuration_names` |
| `features` | `object` | `protocols`, `headless_creator`, `kernel` и независимые feature namespaces |

Неизвестные namespaces внутри `core` и `features` сохраняются при load/save.
Добавление поля feature не меняет `format_version`: defaults и semantic
validation принадлежат самой feature. Формат повышается только при несовместимой
смене envelope.

`User`: `email`, `uuid`, `traffic_limit_gb`, `traffic_used_bytes`, `expiry_date`,
`blocked`, `created_at`, `telegram_id`, `credentials`, `device_limit`, `devices`,
`hydrabox_jwe_key`, `configuration_name_overrides`.

`devices` — карта `id устройства → запись`. Идентификатор — хеш того, чем
клиент представился, поэтому исходный HWID в state не хранится. При отсутствии
HWID используется нормализованный `User-Agent`, чтобы смена адреса не создавала
новое устройство; если нет и него, последним сигналом остаётся адрес. Несколько
старых записей `network-client` с одним `User-Agent` объединяются при следующем
запросе подписки. Запись содержит `first_seen`, `last_seen`, `source`,
`user_agent` и последний известный `address`.

`network`: `domain`, `sub_domain`, `server_ip`, `dns_servers`, `dnscrypt_port`,
`tproxy_enabled`, `tproxy_port`, `clash_api_enabled`, `clash_api_port`,
`clash_api_secret`.

Cookies, join-links и хэши в state не хранятся. Creator runtime принадлежит
Calls; legacy-сервис qWDTT-creator в коде остался, но к приложению не подключён,
а в state сохраняются только поля прежнего `headless_creator.consumers.qwdtt`
(`provider`, `room_count`, `pool_enabled`, `refresh_interval_seconds`).

Старые плоские schema 0–18 поддерживает один importer: он сразу создаёт State
Format v1, нормализует Calls в актуальный `vk_parasite` и переносит прежний
creator desired state. Поштучных migration modules нет. Импорт не меняет host
binary, units или creator runtime. Совместимость Calls с Hydracore определяется
runtime capabilities, а не номером persisted state или wire-полем в нём.

`install` хранит служебные отметки фоновых проверок:

| Ключ | Содержание |
| :--- | :--- |
| `sync_limits_enabled` | Проверять лимиты и сроки пользователей |
| `sync_updates_enabled` | Проверять обновления Sing-Box |
| `sync_certificates_enabled` | Проверять сроки TLS-сертификатов |
| `sync_config_pending` | Отложенное применение конфигурации |
| `sync_config_pending_source` | Фаза, поставившая отложенное применение (`certificates` снимается после первой неудачи) |
| `singbox_last_update_check`, `singbox_update_available`, `singbox_latest_version` | Результат проверки обновлений |
| `certificates_last_check` | Момент последней проверки сертификатов (UTC, ISO 8601) |
| `certificates_report` | Результат проверки: домен, владелец, статус, дней до истечения |
| `device_sessions` | Активные устройства по пользователям: адрес, соединения, байты, разрешено ли |
| `traffic_connection_counters` | Счётчики соединений демона трафика, включая адрес источника |
| `protocol_traffic_totals`, `traffic_report_totals`, `traffic_user_reset_epochs` | Накопители трафика по протоколам и пользователям |
| `traffic_daemon_last_poll`, `traffic_log_cursors` | Позиция демона учёта: последний опрос и курсоры журнала |
| `caddy_l4_migrated` | Одноразовая миграция раскладки Caddy L4 выполнена |

Ноль в `traffic_limit_gb` и `device_limit` означает «без ограничения». Пустой
`expiry_date` означает «без срока»; значение разбирается как ISO-8601 и при
отсутствии таймзоны трактуется как UTC.

Правила миграции и конкурентности — в
[ARCHITECTURE.md](ARCHITECTURE.md#6-state-и-рабочее-состояние).

## Переменные окружения

### `updater.sh` и `upgrade.sh`

`updater.sh` — публичный однокомандный launcher. Он использует `HYDRA_REF`,
полностью скачивает соответствующий `upgrade.sh` во временный файл, проверяет
тип содержимого и только затем запускает транзакцию. `upgrade.sh` — внутреннее
транзакционное ядро и compatibility entrypoint для интеграционных процедур.

| Переменная | По умолчанию | Назначение |
| :--- | :--- | :--- |
| `HYDRA_REF` | `main` | Ветка, чей точный SHA нужно установить |
| `HYDRA_REPO_URL` | официальный репозиторий | Git remote |
| `HYDRA_INSTALL_DIR` | `/opt/hydra` | Стабильная точка входа установки |
| `HYDRA_RELEASES_DIR` | `/opt/hydra-releases` | Каталог изолированных release |
| `HYDRA_UPGRADE_BACKUP_DIR` | `/var/backups/hydra/upgrades` | Постоянные снимки отката |
| `HYDRA_KEEP_RELEASES` | `3` | Сколько release остаётся после успешного обновления |
| `HYDRA_KEEP_BACKUP_DAYS` | `7` | Сколько дней хранятся снимки отката |
| `HYDRA_UPGRADE_LOCK_FILE` | внутреннее | Блокировка от параллельного запуска updater |

### `bootstrap.sh`

| Переменная | По умолчанию | Назначение |
| :--- | :--- | :--- |
| `HYDRA_REF` | `main` | Устанавливаемая ветка; имя проверяется `git check-ref-format` |

Остальные `HYDRA_*` — внутренние значения, которые скрипты устанавливают сами:
данные для откатa (`HYDRA_PREVIOUS_REV`, `HYDRA_BACKUP_DIR` и подобные) и
передача состояния от launcher к транзакционному ядру
(`HYDRA_UPDATER_LAUNCHED`). Переопределять их извне не следует.

Отдельно `HYDRA_INSTALL_DIR` читает и сам Python-код: он задаёт стабильный
корень установки, от которого вычисляется интерпретатор
`<root>/.venv/bin/python` для генерируемых systemd-units.

### Runtime management

| Переменная | По умолчанию | Назначение |
| :--- | :--- | :--- |
| `HYDRA_GITHUB_TOKEN` / `GITHUB_TOKEN` | пусто | Bearer token для GitHub release API; значение не логируется |
| `HYDRA_GOPROXY` | пусто | Go-прокси для сборки `caddy-l4` (`GOPROXY`) на сетях, где заблокировано хранилище go.dev/тулчейнов; например `https://goproxy.cn,direct` |
| `HYDRA_CALLS_LOCK_FILE` | `/run/lock/hydra-calls.lock` | Calls multi-process operation lock |
| `HYDRA_APPLY_LOCK_FILE` | `/run/lock/hydra-apply.lock` | Общий apply lock |

`HYDRA_ALLOW_UNVERIFIED_DOWNLOADS=1` остаётся аварийным escape hatch старых
downloaders, но намеренно не отключает обязательный digest при `kernel switch`.

## Быстрая диагностика

```bash
# Общее состояние
hydra status

# Проверки, будущие изменения и drift
hydra check

# Ядро и мультиплексор
sudo systemctl status sing-box caddy-l4
sudo journalctl -u sing-box -u caddy-l4 --no-pager -n 100

# Активная конфигурация мультиплексора
sudo curl -fsS http://127.0.0.1:2021/config/ | jq .

# Слушающие сокеты
sudo ss -ltnup

# Баны AntiScan
sudo ipset list hydra_antidpi
sudo ipset list hydra_antidpi6

# Какая версия установлена физически
readlink -f /opt/hydra
```
