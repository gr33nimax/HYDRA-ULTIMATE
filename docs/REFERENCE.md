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
| `vless` | VLESS + XHTTP | XHTTP-транспорт Sing-Box Extended с отдельным доменом и заглушкой |
| `shadowtls` | ShadowTLS | ShadowTLS v3 с Trojan detour |
| `snell` | Snell v4 | TCP/UDP-прокси из Sing-Box Extended |
| `telemt` | MTProto / Telemt | Telegram MTProxy с управлением пользователями |
| `wdtt` | qWDTT | WireGuard-туннелирование поверх TURN |

### `enhancement` — сетевые расширения

| Ключ | Модуль | Назначение |
| :--- | :--- | :--- |
| `dnscrypt` | DNSCrypt | Локальный шифрованный DNS-резолвер |
| `warp` | WARP | Выборочная маршрутизация через Cloudflare WireGuard |

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
поскольку сам Clash API не возвращает `metadata.user`.

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
| `hydra-sync-agent.service` | Периодические задачи обслуживания плагинов |
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
| `/etc/caddy-l4/config.json` | Сгенерированная конфигурация TLS-мультиплексора |
| `/etc/nftables.conf` | Правила nftables, включая TPROXY |
| `/etc/iptables/rules.v4` | Сохранённые правила iptables (телеметрия AntiDPI) |
| `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` | Конфигурация DNSCrypt |
| `/etc/telemt/telemt.toml` | Конфигурация MTProto-прокси |
| `/etc/cron.d/hydra-traffic` | Задание учёта трафика |
| `/etc/cron.d/telemt-stats` | Задание статистики Telemt |

### Сайты-заглушки

| Путь | Владелец |
| :--- | :--- |
| `/var/www/decoy-a`, `/var/www/decoy-b`, `/var/www/decoy-c` | Общие decoy-сайты Caddy L4 |
| `/var/www/decoy-hysteria2` | Браузерная заглушка Hysteria2 |
| `/var/www/decoy-vless` | Отдельная media-заглушка VLESS + XHTTP |
| `/var/www/naive-fake` | Заглушка NaiveProxy |

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
| `1081` | TPROXY Sing-Box, если включён (`network.tproxy_port`) |

Порты source-relay назначаются динамически на loopback и сопоставляются с
внешними endpoint в памяти процесса; см. [ANTIDPI.md](ANTIDPI.md).

### ipset

| Набор | Содержание |
| :--- | :--- |
| `hydra_antidpi` | Активные баны AntiDPI, IPv4 |
| `hydra_antidpi6` | Активные баны AntiDPI, IPv6 |

## Схема persisted state

Актуальная версия схемы в 2.5.4 — **4**. Корень `state.json`:

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
`blocked`, `created_at`, `telegram_id`, `credentials`, `device_limit`, `devices`.

`network`: `domain`, `sub_domain`, `server_ip`, `dns_servers`, `dnscrypt_port`,
`tproxy_enabled`, `tproxy_port`, `clash_api_enabled`, `clash_api_port`,
`clash_api_secret`.

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
| `HYDRA_REF` | `dev` | Ветка, чей точный SHA нужно установить |
| `HYDRA_REPO_URL` | официальный репозиторий | Git remote |
| `HYDRA_INSTALL_DIR` | `/opt/hydra` | Стабильная точка входа установки |
| `HYDRA_RELEASES_DIR` | `/opt/hydra-releases` | Каталог изолированных release |
| `HYDRA_UPGRADE_BACKUP_DIR` | `/var/backups/hydra/upgrades` | Постоянные снимки отката |
| `HYDRA_UPGRADE_LOCK_FILE` | внутреннее | Блокировка от параллельного запуска updater |

### `bootstrap.sh`

| Переменная | По умолчанию | Назначение |
| :--- | :--- | :--- |
| `HYDRA_REF` | `dev` | Устанавливаемая ветка; имя проверяется `git check-ref-format` |

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
