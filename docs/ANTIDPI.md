# AntiDPI

> **Модуль:** `antidpi` · **Служба:** `hydra-antidpi` · **Введён:** 2.5.1-dev «FORTRESS» · **Актуален в:** 2.5.4

AntiDPI — поведенческий контур обнаружения протокольной разведки: malformed
handshakes, неверной авторизации, обращений к приманкам и сканирования сетевой
поверхности VPS. Он коррелирует сигналы из разных журналов и применяет временные
блокировки через динамические IPv4/IPv6 ipset.

Главный инвариант модуля:

> Сомнительное событие может уведомить оператора, но не должно автоматически
> заблокировать адрес без достаточного проверенного доказательства.

## Содержание

- [1. Задача и границы ответственности](#1-задача-и-границы-ответственности)
- [2. Поток данных](#2-поток-данных)
- [3. Нормализованное событие](#3-нормализованное-событие)
- [4. Атрибуция внешнего IP](#4-атрибуция-внешнего-ip)
- [5. Сигналы и веса](#5-сигналы-и-веса)
- [6. Два уровня score](#6-два-уровня-score)
- [7. Политика ALERT](#7-политика-alert)
- [8. Политика BAN](#8-политика-ban)
- [9. UDP spoof-safety](#9-udp-spoof-safety)
- [10. Протокольная матрица](#10-протокольная-матрица)
- [11. Сетевая телеметрия](#11-сетевая-телеметрия)
- [12. Whitelist](#12-whitelist)
- [13. Уведомления Telegram](#13-уведомления-telegram)
- [14. Состояние и лимиты ресурсов](#14-состояние-и-лимиты-ресурсов)
- [15. Эксплуатация](#15-эксплуатация)
- [16. Ввод в эксплуатацию и миграция с legacy](#16-ввод-в-эксплуатацию-и-миграция-с-legacy)
- [17. Что модуль не обещает](#17-что-модуль-не-обещает)

## 1. Задача и границы ответственности

HYDRA публикует принципиально разные транспорты: TLS, HTTP-прокси, QUIC, DTLS,
WireGuard-подобные UDP-протоколы и собственные бинарные протоколы. У каждого
сервера свой формат ошибок, а некоторые реализации намеренно ничего не сообщают
при неверном пароле. Fail2ban эту задачу не решает: он рассчитан на стабильный
текстовый auth-журнал и не умеет безопасно объединять сетевые, TLS-, QUIC- и
kernel-сигналы.

До появления AntiDPI это давало семь конкретных проблем:

1. Один и тот же probe выглядел по-разному в Caddy, Sing-Box и kernel journal.
2. После локального проксирования backend видел `127.0.0.1`, а не адрес источника.
3. Mieru молча закрывал соединение и не оставлял auth error.
4. Hysteria2, AmneziaWG и qWDTT работают поверх UDP, где source IP подделывается.
5. Сканирование портов было смешано с SSH/auth-защитой Fail2ban.
6. Honeypot и AntiDPI могли учесть одно событие дважды.
7. Синтетический тест фильтра не доказывал доставку события в Telegram и
   фактическое применение firewall.

Модуль рассматривает каждую строку журнала или firewall LOG как доказательство,
а не как готовый приговор.

| Контур | Ответственность |
| :--- | :--- |
| Fail2ban | SSH brute force и стабильные auth-журналы |
| Honeypot | Выделенная ловушка, её события и её собственные баны |
| **AntiDPI** | Протокольные probes, malformed handshake, decoy, сканирование и корреляция |
| Firewall провайдера | Объёмный DDoS до достижения VPS |

AntiDPI не расшифровывает трафик, не анализирует содержимое успешной
пользовательской сессии и не выявляет злоумышленника, который уже располагает
корректными credentials.

## 2. Поток данных

```text
Caddy L4 / decoy JSONL ─────┐
Caddy Naive access log ─────┤
Sing-Box и protocol journal ├──> adapters ──> normalized event
AmneziaWG dynamic-debug ────┤                         │
kernel iptables LOG ────────┘                         v
                                             score + correlation
                                                      │
                                  ┌───────────────────┴───────────────────┐
                                  v                                       v
                         Telegram ALERT                         verified decision
                                                                          │
                                                                          v
                                                          IPv4/IPv6 ipset DROP
```

Основной процесс — `hydra-antidpi`. Сборщики работают независимо:

- JSONL-tails переживают truncate и rotation;
- journal worker читает Caddy, Sing-Box и protocol units;
- kernel worker читает firewall и AmneziaWG messages;
- очередь ограничена и при переполнении сохраняет наиболее свежие события;
- state обновляется под file lock и записывается атомарно.

Единственный источник enforcement — firewall ipset. В Caddy не встраивается
статический список адресов: он устаревал бы без reload и мог бы удерживать IP
после истечения таймаута.

### Поверхности наблюдения

| Поверхность | Источник | Сигналы |
| :--- | :--- | :--- |
| TCP/443 и Caddy L4 | JSON logger `layer4` | unknown SNI, malformed ClientHello, handshake failure |
| HTTPS decoy | Caddy access JSON | CONNECT/TRACE, поиск `.env`, WordPress, CGI, actuator |
| Транспорты Sing-Box | journald | protocol/auth/handshake failures с публичным peer IP |
| AmneziaWG | kernel dynamic-debug | invalid MAC/handshake |
| Hysteria2 / QUIC | journald | invalid packet, QUIC handshake/retry |
| Mieru, Snell, Telemt, Naive, qWDTT | journald | ошибки конкретных реализаций |
| Вся VPS | rate-limited kernel firewall telemetry | TCP SYN/UDP и multi-port sweep |

Honeypot намеренно не входит в источники AntiDPI: ловушка сама владеет своими
событиями, состоянием и firewall-блокировками. Это исключает двойной учёт и
повторные Telegram-уведомления.

## 3. Нормализованное событие

Разные журналы приводятся к общей минимальной схеме:

```json
{
  "ip": "203.0.113.10",
  "protocol": "naive",
  "kind": "auth_failure",
  "source": "caddy-source-relay",
  "ban_eligible": true
}
```

| Поле | Значение |
| :--- | :--- |
| `ip` | Валидированный IPv4/IPv6 |
| `protocol` | Владелец события |
| `kind` | Тип ошибки |
| `source` | Источник доказательства |
| `ban_eligible` | Разрешено ли событию увеличивать verified score |
| `policy` | Объяснение alert-only режима |

Неизвестные поля не влияют на scorer. Невалидный IP отбрасывается до обращения к
state и firewall.

## 4. Атрибуция внешнего IP

### 4.1 Прямые службы

Если приложение или kernel journal содержит публичный peer endpoint, AntiDPI
использует его напрямую.

### 4.2 Caddy и source relay

Для проксируемых TCP/QUIC-маршрутов Caddy передаёт обязательный PROXY Protocol
v2 в `hydra-source-relay`. Relay:

1. валидирует PROXY v2 header;
2. извлекает внешний IP и source port;
3. соединяется с loopback backend;
4. записывает соответствие backend relay port внешнему endpoint;
5. передаёт backend чистый протокольный payload.

Когда backend пишет ошибку от `127.0.0.1:<relay-port>`, AntiDPI восстанавливает
точный IP по паре `protocol + relay-port`. Mapping живёт 300 секунд и ограничен
по размеру.

### 4.3 Ошибка без endpoint

Если строгая нативная ошибка не содержит peer, допускается окно корреляции
2 секунды. Адрес возвращается только тогда, когда все свежие mappings указывают
на один IP. При двух кандидатах событие остаётся неатрибутированным.

## 5. Сигналы и веса

| Сигнал | Вес |
| :--- | ---: |
| `active_decoy_probe` | 8 |
| `port_sweep` | 6 |
| `malformed_tls` | 4 |
| `udp_probe` | 4 |
| `non_tls_on_tls` | 3 |
| `protocol_mismatch` | 3 |
| `invalid_first_packet` | 3 |
| `auth_failure` | 3 |
| `low_volume_session` | 3 |
| `unknown_sni` | 2 |
| `handshake_failure` | 2 |
| `connection_burst` | 2 |
| `quic_retry_burst` | 2 |
| `port_scan` | 2 |

Одно событие может дать несколько сигналов. Повреждённый TLS ClientHello к
неизвестному SNI способен одновременно сформировать `malformed_tls`,
`unknown_sni` и `handshake_failure`.

`active_decoy_probe` означает, что клиент дошёл до прикладной HTTP-приманки, а не
просто открыл TCP-порт. При подтверждённом внешнем IP этот сигнал может
немедленно сформировать первый 10-минутный бан.

## 6. Два уровня score

### Observed score

Содержит все признаки, включая подделываемый UDP и косвенные поведенческие
сигналы. Используется только для уведомления оператора.

| Параметр | Значение |
| :--- | :--- |
| Порог обычного ALERT | 6 |
| Порог ALERT для явного `auth_failure` | 3 |
| Верхняя граница отображаемого накопления | 16 |
| Half-life | 5 минут |

### Verified score

Содержит только доказательства, которым разрешено приводить к firewall-бану.
UDP alert-only и Mieru inference этот счётчик не увеличивают.

Два счётчика ведутся параллельно и расходятся именно на подделываемых сигналах:

```text
   событие ──▶ распознанные сигналы ──┬──▶ observed score ──▶ ALERT оператору
                                      │      всё, включая
                                      │      UDP и inference
                                      │
                                      └──▶ verified score ──▶ BAN в ipset
                                             только ban_eligible

   пример: ошибка Hysteria2 по UDP
      observed  +4  ──▶ ALERT возможен
      verified  +0  ──▶ бана не будет никогда

   пример: auth failure Naive с точной атрибуцией через relay
      observed  +3  ──▶ ALERT
      verified  +3  ──▶ накапливается к порогу 8
```

BAN возможен при одновременном выполнении двух условий:

```text
verified_score >= 8
AND
(recent verified protocol evidence OR recent verified port sweep)
```

Свежим считается подтверждение не старше 10 минут. Благодаря decay старые слабые
события не могут позднее превратиться в бан.

## 7. Политика ALERT

- Адрес не должен находиться в активном AntiDPI-бане.
- Событие должно иметь хотя бы один распознанный сигнал.
- Observed score должен достичь соответствующего порога.
- Cooldown равен 5 минутам и хранится отдельно для каждой пары IP/protocol.
- Один Naive-alert не подавляет последующий AWG, Hysteria2, qWDTT или
  Mieru-alert того же IP.
- Параллельные сокеты браузера с одинаковым unknown SNI в окне 0,5 секунды
  объединяются.

Alert-only сообщение дополнительно показывает `Policy` и `Verified score`.

## 8. Политика BAN

При достижении verified score `8` IP добавляется в один из наборов:

```text
hydra_antidpi    # IPv4
hydra_antidpi6   # IPv6
```

INPUT DROP по ipset блокирует **весь** входящий трафик адреса, а не только
протокол, на котором он был обнаружен. После бана с этого IP перестают работать
SSH, TLS, QUIC, VPN и любые другие подключения.

Прогрессивные сроки:

| Offense | TTL |
| ---: | :--- |
| 1 | 10 минут |
| 2 | 1 час |
| 3 | 24 часа |
| 4+ | 7 дней |

```text
   offense   1           2            3              4+
             ├───────────┼────────────┼──────────────┼──────────────▶
   TTL       10 мин      1 час        24 часа        7 дней

   счётчик offense НЕ сбрасывается ни по истечении TTL,
   ни после ручного разбана — повторное появление адреса
   сразу получает следующую ступень
```

После перезапуска службы активные записи возвращаются в ipset с оставшимся TTL.
История хранит до 1000 последних записей.

## 9. UDP spoof-safety

Источник UDP-датаграммы не подтверждается трёхсторонним handshake и может быть
подделан. Автоматический бан по одиночной ошибке AWG, Hysteria2 или qWDTT
позволил бы атакующему заблокировать чужой DNS, VPN exit или адрес
администратора.

Поэтому:

```text
direct UDP evidence -> observed score -> ALERT -> никогда автоматический BAN
```

Такие события не только не банят сами, но и не «подготавливают» verified score
для будущего TCP-события.

Naive QUIC и TrustTunnel QUIC могут стать подтверждёнными — но только после
прикладной auth error и точной атрибуции через source relay.

## 10. Протокольная матрица

| Протокол | Детектор | Политика |
| :--- | :--- | :--- |
| TLS / Caddy | malformed TLS, non-TLS, unknown SNI, failed handshake | ALERT + BAN |
| HTTPS decoy | активный запрос к scanner/decoy path | немедленный BAN |
| AnyTLS | auth failure, EOF до первого пакета | ALERT + BAN |
| TrustTunnel TCP/QUIC | auth/authorization failure, malformed handshake | ALERT + BAN |
| ShadowTLS | HMAC mismatch, malformed TLS, Trojan auth failure | ALERT + BAN |
| Naive TCP/QUIC | HTTP proxy authentication failure | ALERT + BAN |
| Snell | malformed first packet, handshake failure | ALERT + BAN |
| Hysteria2 | нативный reject и UDP rate telemetry | только ALERT |
| AmneziaWG | invalid MAC/handshake, unknown peer (штатный `Jc` junk игнорируется) | только ALERT |
| qWDTT | нативная ошибка DTLS handshake | только ALERT |
| Mieru | серия established low-volume TCP closes | только ALERT |
| Telemt | нативный адаптер сохранён | не входит в подтверждённую матрицу |

## 11. Сетевая телеметрия

Все telemetry rules используют target `LOG` и не блокируют пакет напрямую.

### Общая поверхность VPS

| Транспорт | Threshold | Burst |
| :--- | ---: | ---: |
| TCP NEW/SYN | 120/мин | 60 |
| UDP NEW | 300/мин | 150 |

Для каждого IP запоминаются destination ports за 60 секунд. Четыре и более порта
формируют `port_sweep`.

### Включённые UDP-протоколы

Для фактических портов Hysteria2, AmneziaWG, qWDTT, Naive QUIC и TrustTunnel
QUIC устанавливается более чувствительная телеметрия:

```text
12 NEW datagrams/minute, burst 4, per source IP
```

При совместном использовании UDP/443 протокол указывается как составной, а не
приписывается случайному владельцу.

### Mieru silent reject

Неверный пароль Mieru не создаёт server log. Реальная сессия показала
установленное TCP-соединение, менее 1 KiB клиентского трафика и закрытие без
прикладного ответа. AntiDPI журналирует серию FIN/RST на портах `2012–2022`,
если одновременно:

- соединение находится в состоянии `ESTABLISHED`;
- в исходном направлении передано от 1 до 1024 байт;
- частота превышает 2/мин с burst 2.

Сигнал `low_volume_session` остаётся alert-only: аналогичное поведение возможно
при нестабильной сети.

## 12. Whitelist

До scoring исключаются:

- loopback и link-local;
- IP самой VPS из state;
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`;
- `fc00::/7`;
- пользовательские IPv4/IPv6-адреса и сети.

Kernel-правила используют только target `LOG` и никогда не блокируют трафик
напрямую.

## 13. Уведомления Telegram

Технический alert содержит IP, флаг GeoIP, ASN/owner, event, protocol и source,
текущие сигналы, observed score, verified score (если он отличается), policy для
alert-only evidence, а для бана — TTL и номер offense.

GeoIP и ASN обогащают сообщение, но не влияют на score. Категорию AntiDPI можно
отключить независимо от Honeypot, Fail2ban и системных уведомлений. Статистика
`attempted`, `delivered` и `failed` позволяет отличить отсутствие угроз от сбоя
доставки.

Подробности интерфейса — в [TELEGRAM_BOT.md](TELEGRAM_BOT.md).

## 14. Состояние и лимиты ресурсов

Основной state: `/var/lib/hydra/antidpi.json` — записывается атомарно с fsync и
правами `0600`, read-modify-write защищён `flock`.

| Ресурс | Лимит |
| :--- | :--- |
| Score entries | 20 000 IP |
| Retention неактивного evidence | 24 часа |
| Сигналы на IP | последние 16 типов |
| Ban history | последние 1000 записей |
| Source relay mappings | 8 MiB |
| TCP relay connections | 2048 |
| UDP relay flows | 4096, idle timeout 60 секунд |

Служба запускается с ограниченным набором capabilities. Healthcheck проверяет
службу, оба ipset, DROP-правила и kernel telemetry.

## 15. Эксплуатация

### Установка и обновление runtime

```bash
sudo hydra antidpi sync
```

Команда идемпотентна и безопасна для повторного запуска. Она устанавливает
недостающие зависимости `ipset`/`iptables`, создаёт IPv4/IPv6 ban sets и
enforcement rules, обновляет TCP/UDP-, port-sweep- и Mieru-телеметрию, включает
AmneziaWG dynamic-debug (если его предоставляет ядро), записывает актуальный
systemd unit, выполняет `daemon-reload`, включает и перезапускает
`hydra-antidpi` и возвращает в ipset ещё не истёкшие активные баны.

### Проверка состояния

```bash
sudo systemctl is-active hydra-antidpi
hydra check
sudo ipset list hydra_antidpi
sudo ipset list hydra_antidpi6
sudo journalctl -u hydra-antidpi -n 100 --no-pager
```

### Локальный self-test

Безопасная симуляция ошибочных подключений ко всем включённым транспортам:

```bash
sudo hydra antidpi selftest
```

Расширенный режим дополнительно запускает временные нативные клиенты с заведомо
неверной авторизацией:

```bash
sudo hydra antidpi selftest --full --wait 3
```

Self-test последовательно отправляет короткие некорректные TCP-, TLS- и
UDP-пакеты на локальные порты AmneziaWG, AnyTLS, TrustTunnel, ShadowTLS,
Hysteria2, Mieru, NaiveProxy, Snell, Telemt и qWDTT. Отключённые протоколы
явно отмечаются как `skipped_disabled`, а Snell без активного пользователя —
как `skipped_no_target`.

Для AnyTLS, TrustTunnel, ShadowTLS, Hysteria2, Mieru, NaiveProxy и Snell
используется установленный `sing-box`. Временный конфиг создаётся с правами
`0600`, не меняет конфигурации пользователей и служб и удаляется вместе с
клиентским процессом. Telemt, qWDTT и AmneziaWG не имеют совместимого локального
клиента — в матрице покрытия это указывается явно, без ложного статуса проверки.

После каждого протокола команда собирает `journald` и новые строки AntiDPI/Caddy
и проверяет их текущими адаптерами. Результат — архив с правами `0600`:

```text
/tmp/hydra-antidpi-selftest-YYYYMMDDTHHMMSSZ.tar.gz
```

Известные пароли, токены, UUID, PSK и приватные ключи заменяются на
`[REDACTED]`. Перед передачей архив всё равно необходимо просмотреть:

```bash
tar -tzf /tmp/hydra-antidpi-selftest-*.tar.gz
tar -xOzf /tmp/hydra-antidpi-selftest-*.tar.gz \
  hydra-antidpi-selftest/report.json | jq .
```

При медленной записи журналов задержку можно увеличить, а путь задать явно:

```bash
sudo hydra antidpi selftest --wait 3 --output /tmp/antidpi-native.tar.gz
```

В `report.json` для каждого протокола есть матрица `coverage`: отправка
повреждённых пакетов, запуск нативного клиента, наличие нативного лога и
совпадение с текущим фильтром.

> [!IMPORTANT]
> Локальный self-test намеренно не банит `127.0.0.1`. Он проверяет нативные
> ошибки и фильтры, но **не** проверяет firewall и доставку в Telegram. Полный
> внешний путь подтверждается только запросом с другого IP.

### Окно внешнего тестирования

```bash
sudo hydra antidpi capture --seconds 180
```

Capture включает journal, новые JSONL-записи, runtime delta, доставку
уведомлений, firewall rules, TCP/UDP listeners, relay mappings и AWG debug.
Во время окна выполните неправильные подключения с другого адреса, затем
проверьте Telegram, `/var/lib/hydra/antidpi.json`, журналы службы и наличие IP
в `hydra_antidpi`/`hydra_antidpi6`.

Для UDP и Mieru нормальный результат — технический `ALERT` без автоматического
бана. Для подтверждённых TCP/TLS auth events бан появляется только после
достижения `verified_score >= 8`.

## 16. Ввод в эксплуатацию и миграция с legacy

На установке, где ранее работали `hydra-portscan`, прежняя схема Caddy или
ранняя версия AntiDPI, порядок такой.

**Шаг 1. Обновить HYDRA.** Используйте транзакционный updater из
[UPGRADE.md](UPGRADE.md). Не выполняйте `git pull` вручную и не запускайте
`bootstrap.sh` поверх рабочей установки.

**Шаг 2. Применить общую конфигурацию.**

```bash
hydra check
sudo hydra apply
```

`apply` пересобирает Sing-Box и Caddy L4 из актуального state, обновляет
маршруты с PROXY Protocol v2, создаёт и включает `hydra-source-relay` там, где
он нужен, синхронизирует plugin runtime и применяет миграцию Fail2ban. В рамках
миграции удаляются jail/filter `hydra-portscan`, старые protocol jails и legacy
iptables LOG rule — их функцию принимает AntiDPI. Удалять `hydra-portscan`
вручную не нужно.

**Шаг 3. Синхронизировать AntiDPI runtime.**

```bash
sudo hydra antidpi sync
```

**Шаг 4. Перезапустить Telegram-бот** — чтобы загрузился новый формат сообщений,
GeoIP/ASN и категории уведомлений:

```bash
sudo systemctl restart hydra-tg-admin
```

Отдельно перезапускать `hydra-antidpi` после успешного `sync` не требуется;
Caddy и source relay уже пересобраны командой `apply`.

**Шаг 5. Проверить результат.**

```bash
sudo systemctl is-active caddy-l4 hydra-source-relay hydra-antidpi hydra-tg-admin fail2ban
sudo ss -ltnp | grep -E ':2021|caddy-l4|hydra-source-relay'
sudo curl -fsS http://127.0.0.1:2021/config/ \
  | jq '[.. | objects | select(.proxy_protocol? == "v2")] | length'
sudo fail2ban-client status
sudo ipset list hydra_antidpi
sudo ipset list hydra_antidpi6
hydra check
```

Ожидаемый результат:

- основные службы имеют статус `active`;
- admin API `caddy-l4` слушает `127.0.0.1:2021`, а не занятый другим Caddy
  порт `2019`;
- количество маршрутов `proxy_protocol: v2` больше нуля, если включены
  протоколы, использующие source relay;
- jail `hydra-portscan` больше не существует;
- оба AntiDPI-ipset существуют;
- `hydra check` не показывает критической рассинхронизации.

`hydra-source-relay` может отсутствовать или быть неактивным только если в
текущем state нет ни одного маршрута, которому нужна relay-атрибуция. Для
конфигурации с AnyTLS, TrustTunnel, ShadowTLS или Naive это ошибка — проверьте
вывод `hydra apply` и journal.

**Шаг 6. Проверить полный путь уведомления** — см.
[локальный self-test](#локальный-self-test) и
[окно внешнего тестирования](#окно-внешнего-тестирования).

> [!WARNING]
> Не очищайте `/var/lib/hydra/antidpi.json` и ipset без отдельной причины: там
> находятся активные TTL, история offenses и состояние прогрессивных банов.

`hydra apply` и `hydra antidpi sync` рассчитаны на повторный запуск. Если
обновление оборвалось, устраните ошибку из JSON или journal и повторите обе
команды в том же порядке.

## 17. Что модуль не обещает

AntiDPI существенно расширяет наблюдаемость, но не может математически
гарантировать обнаружение любой атаки:

- корректное одиночное соединение неотличимо от обычного клиента;
- low-and-slow probe может оставаться ниже rate threshold;
- валидные украденные credentials выглядят как легитимная авторизация;
- протокол без публичного peer IP в журнале нельзя связать с адресом;
- NAT объединяет независимых клиентов за одним IP;
- прямой UDP source нельзя безопасно использовать для автоматического бана;
- upstream DDoS должен фильтроваться провайдером до VPS;
- GeoIP и ASN являются справочной, а не доказательной информацией.

Для максимального покрытия используйте AntiDPI вместе с Honeypot, Fail2ban для
SSH/auth, закрытым firewall по allow-list и DDoS-защитой провайдера.
