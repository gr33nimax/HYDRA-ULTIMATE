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
- [Схема persisted state](#схема-persisted-state)
- [Переменные окружения](#переменные-окружения)
- [Быстрая диагностика](#быстрая-диагностика)

## Модули

Канонические имена плагинов — это ключи в `state.protocols`. Они же используются
в выводе `hydra status` и `hydra check`.

Плагины разделены на три категории; фильтр доступен как
`hydra plugin list --category {transport,enhancement,security}`.

### `transport` — транспорты

| Ключ | Модуль | Назначение |
| :--- | :--- | :--- |
| `amneziawg` | AmneziaWG 2.0 | WireGuard-транспорт с расширенной обфускацией и TPROXY |
| `mieru` | Mieru | Обфусцированный mTLS-транспорт с ссылками `mierus://` |
| `naive` | NaiveProxy | HTTP/2-прокси на базе Caddy forward-proxy |
| `anytls` | AnyTLS | TLS-подобный обфусцированный туннель |
| `trusttunnel` | TrustTunnel | TLS-транспорт с режимами TCP/QUIC и сайтом-заглушкой |
| `hysteria2` | Hysteria2 | QUIC-транспорт с Salamander и браузерной заглушкой |
| `vless` | VLESS + XHTTP | XHTTP-транспорт Sing-Box Extended: свой домен с сертификатом либо Reality с чужим рукопожатием |
| `shadowtls` | ShadowTLS | ShadowTLS v3 с Trojan detour |
| `snell` | Snell v4 | TCP/UDP-прокси из Sing-Box Extended |
| `telemt` | MTProto / Telemt | Telegram MTProxy с управлением пользователями |
| `wdtt` | qWDTT | WireGuard-туннелирование поверх TURN |

Для qWDTT TUI предлагает пункт «Настроить VK headless creator». Оператор
помещает экспортированный многострочный Creator JSON в фиксированный файл
`/etc/hydra/cookiesvk/cookies-vk.json`; ручного ввода cookies в TUI нет. При
отсутствии файла setup создаёт каталог `cookiesvk` и сообщает ожидаемый путь. Затем
HYDRA выбирает последний `whitelist-bypass-cli-linux-*.zip` по архитектуре VPS,
проверяет опубликованный GitHub Release SHA-256, извлекает и атомарно устанавливает
`/usr/local/bin/headless-vk-creator`, затем запускает четыре экземпляра и ждёт
четыре разных `vk.com/call/join/...` хеша. В `/etc/wdtt/qwdtt_link.txt`
сохраняется одна ссылка `qwdtt://` с главным паролем; временные пароли в неё не
подставляются. Maintenance task sync-agent каждые пять минут проверяет выбранный
оператором интервал от 1 до 24 часов (по умолчанию 24 часа) и при необходимости
перезапускает четыре инстанса и атомарно заменяет ссылку. Если
systemd восстановил упавший creator и его live-хеш изменился раньше срока,
следующий цикл sync-agent немедленно согласует все четыре звонка и master-ссылку.
Экран явно показывает владельца операций. В автоматическом режиме звонками
управляет Sync Agent; в ручном он пропускает creator, а звонки меняются только
командами меню. Переключение режима не завершает текущие звонки.
Административный экран пользователя «Ручные конфиги» читает эту master-ссылку
через объявленный плагином manual-artifact query. Она общая для всех пользователей
и намеренно не включается в пользовательские subscription endpoints.
После первичной настройки пункт «VK headless creator» работает как экран
управления: обычный вход не меняет runtime. Отдельные пункты немедленно
пересоздают четыре звонка, завершают и отключают все creator-инстансы, меняют
общий таймер, выбирают автоматический или ручной режим либо проверяют установку.
При завершении звонков недействительная master-ссылка удаляется; автоматически
новую создаёт только Sync Agent в автоматическом режиме.
Каталоги `/etc/hydra/cookiesvk` и `/etc/wdtt/headless` создаются с правами `0700`,
а cookies-файл атомарно получает `0600`; cookies не передаются через аргументы процесса.

Сайт-заглушка на собственном домене есть у AnyTLS, TrustTunnel, Hysteria2,
NaiveProxy и VLESS + XHTTP. VLESS требует отдельный домен: XHTTP занимает
настроенный путь (`/xhttp` по умолчанию), а остальные URL этого домена
обслуживает сайт из `/var/www/decoy-vless`. Транспорт XHTTP настраивается
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
копирование из SSH-терминала не меняло содержимое. Ссылки подписки выдаются
только когда `hydra-sub.service` запущен и HTTPS-сертификат с ключом доступны.
Auto endpoint распознаёт NekoBox, Shadowrocket и Throne по `User-Agent`; для
ручного выбора доступны `format=nekobox`, `format=shadowrocket`,
`format=throne` и `format=singbox`. В Shadowrocket-подписке TCP-профиль
NaiveProxy сериализуется как нативный HTTPS proxy: url-safe base64 от
`user:password@host:port` без `=` и с именем в параметре `remarks`.

Hysteria2 по умолчанию использует `8443/udp`. Если профиль работает по Wi-Fi,
но не работает через мобильную сеть, сначала проверяют доступность UDP/8443 у
оператора и внешнего firewall: HYDRA не передаёт настройки в 3x-ui и не зависит
от него. NaiveProxy требует, чтобы используемый клиент поддерживал Naive либо
имел соответствующий внешний модуль; отсутствие клиентского модуля нельзя
исправить серверной конфигурацией.

Формат подписки `?format=singbox` собирается из plugin-owned клиентских
проекций. Для AmneziaWG он содержит отдельный `wireguard` endpoint Sing-Box
Extended для каждого доступного desktop/mobile профиля. Параметры `Jc`, `Jmin`,
`Jmax`, `S1`–`S4`, `H1`–`H4` и `I1` находятся во вложенном объекте `amnezia`;
`route.final` ссылается на первый AWG endpoint. Нативная INI-конфигурация
AmneziaWG при этом не изменяется.

`?format=hydrabox` принимает только `User-Agent: HydraBox/<version>` и
`X-Hydra-HWID: hbx1_<base64url-sha256>`. Неверная идентификация возвращает
HTTP 400, превышение device limit — HTTP 403. Ответ всегда имеет media type
`application/jose+json` и представляет flattened JWE с единственными полями
`protected`, `iv`, `ciphertext`, `tag`. Protected header фиксирован:
`alg=dir`, `enc=A256GCM`, `typ=hbx+jwe`,
`cty=application/vnd.hydrabox.subscription+json`; `kid` является безопасным
идентификатором ключа. Plaintext HydraBox fallback отсутствует.

После расшифровки envelope имеет точные
`api_version=hydrabox.io/subscription/v1` и `kind=SubscriptionData`, стабильную
identity tuple `(issuer, subscription_id, stable)` и использует revision state
как старшую часть монотонного `sequence`; младшая часть содержит ревизию
HydraBox-renderer и повышается при изменении выдаваемого JSON без изменения
state. Поэтому обновление кода не создаёт запрещённую комбинацию «прежний
sequence + новый payload». В `runtime.document` попадают только разрешённые
remote policy v1 `outbounds` и userspace `wireguard` endpoints: локальные
inbounds/DNS/route и `direct` отбрасываются, а executable-поля,
зарезервированные теги и system WireGuard блокируют выдачу fail-closed.
AmneziaWG-параметры `I1`–`I5`, `J1`–`J3` и `Itime` сохраняются в endpoint как
`amnezia.i1`–`amnezia.i5`, `amnezia.j1`–`amnezia.j3` и `amnezia.itime` вместе с
`Jc`/`Jmin`/`Jmax`, `S1`–`S4` и `H1`–`H4`. Detour-зависимости сохраняются с
исходными тегами, а `profiles` явно указывает только на корневые
selectable entrypoints. Пользовательское имя профиля берётся из
`PluginMeta.display_name`, с fallback на короткий `PluginMeta.name`;
операторское `PluginMeta.description` в подписку не публикуется. Plaintext
ограничен 12 MiB, внешний JWE — 16 MiB; каждый ответ получает случайный
12-байтовый IV и 16-байтовый authentication tag и публикуется с
`Cache-Control: private, no-store`.

TUI и генератор выдают ссылку
`https://<origin>/sub/<id>?format=hydrabox#hbx-key=<base64url-key>`. Fragment не
передаётся HTTP-серверу. Per-user 256-битный ключ хранится только в private
state; `status`, логи и публичный JSON показывают максимум производный `kid`.
Ротация немедленно инвалидирует все ранее выданные HydraBox-ссылки.

### `enhancement` — сетевые расширения

| Ключ | Модуль | Назначение |
| :--- | :--- | :--- |
| `dnscrypt` | DNSCrypt | Локальный шифрованный DNS-резолвер |
| `warp` | WARP | Выборочная маршрутизация через Cloudflare WireGuard |

WARP применяет списочные маршруты только когда enhancement включён. Каждый
target обязан ссылаться на существующий outbound: `warp` требует локальный
WGCF-профиль, а `warp_<name>` — соответствующий relay-профиль. Отсутствующая
цель считается ошибкой конфигурации и блокирует apply, чтобы трафик не ушёл
напрямую незаметно для оператора. Ошибки регистрации и генерации WGCF доступны
в `/var/log/hydra/warp_install.log`; вывод команд перед записью редактируется.

### `security` — защита

| Ключ | Модуль | Назначение |
| :--- | :--- | :--- |
| `antidpi` | AntiDPI | Корреляция protocol probes и сканирования с динамическим ipset |
| `fail2ban` | Fail2ban | Блокировка SSH и аутентификационных атак |
| `honeypot` | Honeypot | Обнаружение сканирования портов |
| `ipban` | IPBan | Статические списки IP/CIDR/ASN/стран |

Учёт трафика и применение лимитов выполняет служба `hydra-traffic-daemon` — она
принадлежит ядру и плагином не является.
Для VLESS + XHTTP демон сопоставляет `sourcePort` активного соединения Clash API
с аутентифицированным именем пользователя из того же journal context Sing-Box,
поскольку сам Clash API не возвращает `metadata.user`. Если VLESS работает за
Caddy, тот же source port используется для точного поиска внешнего IP в
`hydra-source-relay`; в сессии сохраняется клиентский адрес, а не loopback-хоп.

## Systemd-службы

### Службы HYDRA

| Unit | Роль |
| :--- | :--- |
| `hydra-antidpi.service` | Коллектор и enforcement AntiDPI |
| `hydra-honeypot.service` | Ловушка сканирования портов |
| `hydra-source-relay.service` | TCP source-relay: PROXY v2 → loopback backend |
| `hydra-udp-source-relay.service` | UDP source-relay для QUIC-маршрутов |
| `hydra-caddy-source.service` | Обработчик source-транспарентности Caddy |
| `hydra-sub.service` | Сервер подписок |
| `hydra-traffic-daemon.service` | Учёт трафика и применение лимитов/сроков |
| `hydra-sync-agent.service` | Периодические задачи: лимиты пользователей, обслуживание плагинов, суточная проверка TLS-сертификатов, обновление Sing-Box |
| `hydra-sync-agent.timer` | Расписание sync agent |
| `hydra-tg-admin.service` | Telegram Admin Bot |

Вспомогательные отладочные units, включаемые по требованию:
`hydra-awg-antidpi-debug.service`, `hydra-awg-fail2ban-debug.service`.

Legacy unit `hydra-tg-bot.service` сохранён только для удаления на старых
установках; новый код его не создаёт.

### Внешние службы под управлением HYDRA

| Unit | Роль |
| :--- | :--- |
| `sing-box.service` | Основное ядро транспортов и маршрутизации |
| `caddy-l4.service` | TLS/SNI-мультиплексор на общем TCP/443 |
| `caddy-naive.service` | Caddy forward-proxy для NaiveProxy |
| `telemt.service` | Демон MTProto-прокси |
| `wdtt.service` | Демон qWDTT |
| `wdtt-headless-creator@.service` | Четыре VK headless creator-инстанса для суточного обновления qWDTT-хешей |
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
| `/usr/local/bin/sing-box` | Бинарник Sing-Box Extended |
| `/usr/local/bin/caddy-l4` | Бинарник Caddy с модулем layer4 |

### Конфигурации

| Путь | Содержание |
| :--- | :--- |
| `/etc/hydra` | Служебные конфигурации HYDRA |
| `/etc/sing-box/config.json` | Сгенерированная конфигурация Sing-Box |
| `/etc/systemd/system/sing-box.service.d/90-hydra-memory.conf` | Общий `GOGC=50` без жёсткого memory cap |
| `/etc/systemd/journald.conf.d/90-hydra-journald.conf` | Бюджеты постоянного и runtime-журнала |
| `/etc/caddy-l4/config.json` | Сгенерированная конфигурация TLS-мультиплексора |
| `/etc/nftables.conf` | Правила nftables, включая TPROXY |
| `/etc/iptables/rules.v4` | Сохранённые правила iptables (телеметрия AntiDPI) |
| `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` | Конфигурация DNSCrypt |
| `/etc/telemt/telemt.toml` | Конфигурация MTProto-прокси |
| `/etc/hydra/cookiesvk/` | Фиксированный каталог VK cookies; права `0700` |
| `/etc/hydra/cookiesvk/cookies-vk.json` | Экспортированный Creator JSON; файл `0600`, не входит в state |
| `/etc/wdtt/headless/` | Закрытый runtime-каталог VK creator с правами `0700` |
| `/etc/wdtt/headless/state.json` | Четыре последних call-хеша и время обновления |
| `/etc/wdtt/qwdtt_link.txt` | Единственная master qWDTT-ссылка с актуальными четырьмя хешами |
| `/etc/cron.d/hydra-traffic` | Задание учёта трафика |
| `/etc/cron.d/telemt-stats` | Задание статистики Telemt |

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
| `antidpi.json` | `antidpi` | Score, evidence, активные баны и offense counters |
| `honeypot.json` | `honeypot` | События и собственные баны ловушки |
| `ipban.json` | `ipban` | Статические списки блокировок |
| `ip-intel-cache.json` | сервисы | Кэш GeoIP/ASN для уведомлений |
| `caddy-source-state.json` | ядро | Состояние source-транспарентности |
| `network-tuning-backup.json` | ядро | Исходные значения sysctl до тюнинга |
| `warp_external.json` | `warp` | Внешняя конфигурация WARP |
| `telemt_syn_limiter.json` | `telemt` | Состояние SYN-лимитера |
| `telemt_ios_fix.json` | `telemt` | Состояние обхода для клиентов iOS |

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
| `/var/log/hydra/warp_install.log` | Установка WARP |
| `/var/log/hydra-honeypot.log` | События ловушки |
| `/var/log/caddy-l4/antidpi.jsonl` | JSONL-события layer4 для AntiDPI |
| `/var/log/caddy-naive/access.log` | Access-журнал NaiveProxy |
| `/var/log/fail2ban.log` | Журнал Fail2ban |
| `/var/log/telemt_install.log` | Установка Telemt |

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

```text
   ИНТЕРНЕТ                                     LOOPBACK (127.0.0.1)
   ─────────────────────────────────────        ──────────────────────────────
   443/tcp    Caddy L4 · SNI-мультиплексор      2021  admin API caddy-l4
   443/udp    один QUIC-транспорт               5300  DNSCrypt
   8443/udp   Hysteria2                         9000  локальный TUN qWDTT
   8443/tcp   Telemt (MTProto)                  9090  Clash API (если включён)
   9443/tcp   сервер подписок                   1081  TPROXY (если включён)
   9999/tcp   Honeypot
   51820/udp  AmneziaWG                         + динамические порты
   51821/udp  AmneziaWG                           source-relay
   56000/udp  qWDTT · DTLS/TURN
   56001/udp  qWDTT · WireGuard
   2012–2022/tcp    Mieru
   32000–32999/tcp  Snell
```

### Внешние (публикуются в интернет)

| Порт | Транспорт | Владелец |
| ---: | :--- | :--- |
| `443/tcp` | TCP | Caddy L4 — общий SNI-мультиплексор для NaiveProxy, AnyTLS, TrustTunnel, ShadowTLS и VLESS + XHTTP |
| `443/udp` | UDP | Один QUIC-транспорт: NaiveProxy **или** TrustTunnel |
| `8443/udp` | UDP | Hysteria2 |
| `8443/tcp` | TCP | Telemt (MTProto) |
| `51820/udp`, `51821/udp` | UDP | AmneziaWG |
| `56000/udp` | UDP | qWDTT — DTLS/TURN |
| `56001/udp` | UDP | qWDTT — WireGuard |
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
| `hydra_antidpi` | Активные баны AntiDPI, IPv4 |
| `hydra_antidpi6` | Активные баны AntiDPI, IPv6 |

## Схема persisted state

В текущей ветке `dev` актуальна схема **6**. Корень `state.json`:

| Поле | Тип | Содержание |
| :--- | :--- | :--- |
| `version` | `int` | Версия схемы |
| `revision` | `int` | Монотонная ревизия желаемой конфигурации |
| `install` | `object` | Метаданные установки |
| `protocols` | `map[str, PluginState]` | Состояние плагинов по каноническому имени |
| `users` | `list[User]` | Пользователи и их credentials |
| `telegram` | `object` | Настройки Telegram-адаптера и категорий уведомлений |
| `network` | `object` | Сетевые настройки, не принадлежащие плагину |

`User`: `email`, `uuid`, `traffic_limit_gb`, `traffic_used_bytes`, `expiry_date`,
`blocked`, `created_at`, `telegram_id`, `credentials`, `device_limit`, `devices`,
`hydrabox_jwe_key`.

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

`install` хранит служебные отметки фоновых проверок:

| Ключ | Содержание |
| :--- | :--- |
| `sync_limits_enabled` | Проверять лимиты и сроки пользователей |
| `sync_updates_enabled` | Проверять обновления Sing-Box |
| `sync_certificates_enabled` | Проверять сроки TLS-сертификатов |
| `sync_wdtt_headless_enabled` | Автоматически создавать и обновлять VK-звонки qWDTT |
| `sync_config_pending` | Отложенное применение конфигурации |
| `sync_config_pending_source` | Фаза, поставившая отложенное применение (`certificates` снимается после первой неудачи) |
| `singbox_last_update_check`, `singbox_update_available`, `singbox_latest_version` | Результат проверки обновлений |
| `certificates_last_check` | Момент последней проверки сертификатов (UTC, ISO 8601) |
| `certificates_report` | Результат проверки: домен, владелец, статус, дней до истечения |
| `device_sessions` | Активные устройства по пользователям: адрес, соединения, байты, разрешено ли |
| `traffic_connection_counters` | Счётчики соединений демона трафика, включая адрес источника |

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

# Баны AntiDPI
sudo ipset list hydra_antidpi
sudo ipset list hydra_antidpi6

# Какая версия установлена физически
readlink -f /opt/hydra
```
