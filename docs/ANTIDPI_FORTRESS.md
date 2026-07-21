# AntiDPI FORTRESS

Версия: **2.5.2-dev «FORTRESS»**

Статус: подтверждено внешними тестами на реальной VPS

Назначение: обнаружение протокольной разведки, malformed handshakes,
неправильной авторизации и сканирования сетевой поверхности HYDRA.

## 1. Зачем появился FORTRESS

HYDRA публикует несколько принципиально разных транспортов: TLS, HTTP proxy,
QUIC, DTLS, WireGuard-подобные UDP-протоколы и собственные бинарные протоколы.
У каждого сервера свой формат ошибок, а некоторые реализации намеренно ничего
не сообщают при неверном пароле. Обычный Fail2ban не решает эту задачу: он
ожидает стабильный текстовый auth-журнал и не умеет безопасно объединять
сетевые, TLS-, QUIC- и kernel-сигналы.

До FORTRESS это приводило к нескольким проблемам:

1. Один и тот же probe выглядел по-разному в Caddy, Sing-Box и kernel journal.
2. После локального проксирования backend видел `127.0.0.1`, а не атакующий IP.
3. Mieru молча закрывал соединение и не оставлял auth error.
4. Hysteria2, AmneziaWG и qWDTT работали поверх UDP, где source IP может быть
   подделан.
5. Port scan был смешан с SSH/auth-защитой Fail2ban.
6. Honeypot и AntiDPI могли считать одно событие дважды.
7. Синтетический тест фильтра не доказывал доставку реального события в
   Telegram и применение firewall.

FORTRESS создаёт самостоятельный слой между сетевой телеметрией и enforcement.
Он рассматривает каждую строку журнала или firewall LOG как доказательство, а
не как готовый приговор.

## 2. Границы ответственности

| Контур | Ответственность |
|---|---|
| Fail2ban | SSH brute force и стабильные auth-журналы |
| Honeypot | Выделенная ловушка, её события и её firewall-баны |
| AntiDPI | Протокольные probes, malformed handshake, decoy, scans и корреляция |
| Provider firewall | Объёмный DDoS до достижения VPS |

AntiDPI не является DPI-движком расшифровки и не анализирует содержимое
успешной зашифрованной пользовательской сессии. Он также не определяет
злоумышленника, который уже располагает корректными credentials.

## 3. Поток данных

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

- JSONL tails переживают truncate и rotation;
- journal worker читает Caddy, Sing-Box и protocol units;
- kernel worker читает firewall и AmneziaWG messages;
- очередь ограничена, а при переполнении сохраняет наиболее свежие события;
- state обновляется под file lock и записывается атомарно.

## 4. Нормализованное событие

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

Ключевые поля:

- `ip` — валидированный IPv4/IPv6;
- `protocol` — владелец события;
- `kind` — тип ошибки;
- `source` — источник доказательства;
- `ban_eligible` — разрешено ли событию увеличивать verified score;
- `policy` — объяснение alert-only режима.

Неизвестные поля не влияют на scorer. Невалидный IP отбрасывается до доступа к
state и firewall.

## 5. Атрибуция внешнего IP

### 5.1 Прямые сервисы

Если приложение или kernel journal содержит public peer endpoint, AntiDPI
использует его напрямую.

### 5.2 Caddy и source relay

Для проксируемых TCP/QUIC маршрутов Caddy передаёт обязательный PROXY Protocol
v2 в `hydra-source-relay`. Relay:

1. валидирует PROXY v2 header;
2. извлекает внешний IP и source port;
3. соединяется с loopback backend;
4. записывает соответствие backend relay port внешнему endpoint;
5. передаёт backend чистый протокольный payload.

Когда backend пишет ошибку от `127.0.0.1:<relay-port>`, AntiDPI восстанавливает
точный IP по паре `protocol + relay-port`. Mapping живёт 300 секунд и ограничен
по размеру.

### 5.3 Ошибка без endpoint

Если строгая native error не содержит peer, допускается окно корреляции 2
секунды. Адрес возвращается только тогда, когда все свежие mappings указывают
на один IP. При двух кандидатах событие остаётся неатрибутированным.

## 6. Сигналы и веса

| Сигнал | Вес |
|---|---:|
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

Одно событие может дать несколько сигналов. Например, повреждённый TLS
ClientHello неизвестному SNI способен одновременно сформировать
`malformed_tls`, `unknown_sni` и `handshake_failure`.

## 7. Два уровня score

### Observed score

Содержит все признаки, включая spoofable UDP и косвенные поведенческие
сигналы. Используется для уведомления оператора.

- порог обычного ALERT: `6`;
- порог ALERT для явного `auth_failure`: `3`;
- верхняя граница отображаемого накопления: `16`;
- half-life: 5 минут.

### Verified score

Содержит только доказательства, которым разрешено приводить к firewall ban.
UDP alert-only и Mieru inference не увеличивают этот счётчик.

BAN возможен при выполнении обоих условий:

```text
verified_score >= 8
AND
(recent verified protocol evidence OR recent verified port sweep)
```

Свежим считается подтверждение не старше 10 минут. Старые слабые события не
могут позднее превратиться в бан благодаря decay.

## 8. Политика ALERT

- Адрес не должен находиться в активном AntiDPI ban.
- Событие должно иметь хотя бы один распознанный signal.
- Observed score должен достичь соответствующего порога.
- Cooldown равен 5 минутам и хранится отдельно для каждой пары IP/protocol.
- Один Naive alert не подавляет последующий AWG, Hysteria2, qWDTT или Mieru
  alert того же IP.
- Параллельные browser sockets с одинаковым unknown SNI в окне 0,5 секунды
  объединяются.

Alert-only сообщение дополнительно показывает `Policy` и `Verified score`.

## 9. Политика BAN

При verified score `8` IP добавляется в один из наборов:

```text
hydra_antidpi   # IPv4
hydra_antidpi6  # IPv6
```

INPUT DROP по ipset блокирует весь входящий трафик адреса, а не только
протокол, на котором он был обнаружен. Поэтому после бана перестают работать
SSH, TLS, QUIC, VPN и другие подключения с этого IP.

Прогрессивные сроки:

| Offense | TTL |
|---:|---:|
| 1 | 10 минут |
| 2 | 1 час |
| 3 | 24 часа |
| 4+ | 7 дней |

Offense counter сохраняется после expiry и ручного unban. После перезапуска
активные записи возвращаются в ipset с оставшимся TTL. История хранит до 1000
последних ban records.

## 10. UDP spoof-safety

Исходный адрес UDP не подтверждается трёхсторонним handshake и может быть
подделан. Автоматический ban по одиночной AWG/Hysteria2/qWDTT ошибке позволил
бы атакующему заблокировать чужой DNS, VPN exit или адрес администратора.

Поэтому:

```text
direct UDP evidence -> observed score -> ALERT -> never automatic BAN
```

Такие события не только не банят сами, но и не «подготавливают» verified score
для будущего TCP-события.

Naive QUIC и TrustTunnel QUIC могут стать подтверждёнными после прикладной
auth error и точной source-relay attribution.

## 11. Протокольная матрица

| Протокол | Детектор | Политика |
|---|---|---|
| TLS/Caddy | malformed TLS, non-TLS, unknown SNI, failed handshake | ALERT/BAN |
| HTTPS decoy | активный запрос к scanner/decoy path | немедленный BAN |
| AnyTLS | auth failure, EOF before first packet | ALERT/BAN |
| TrustTunnel TCP/QUIC | auth/authorization failure, malformed handshake | ALERT/BAN |
| ShadowTLS | HMAC mismatch, malformed TLS, Trojan auth failure | ALERT/BAN |
| Naive TCP/QUIC | HTTP proxy authentication failure | ALERT/BAN |
| Snell | malformed first packet, handshake failure | ALERT/BAN |
| Hysteria2 | native reject и UDP rate telemetry | ALERT only |
| AmneziaWG | Invalid MAC/handshake, unknown peer; штатный Jc junk игнорируется | ALERT only |
| qWDTT | native DTLS handshake failure | ALERT only |
| Mieru | repeated established low-volume TCP closes | ALERT only |
| Telemt | native adapter сохранён | не входит в подтверждённую матрицу |

## 12. Сетевая телеметрия

Все telemetry rules используют target `LOG`. Они не блокируют пакет напрямую.

### Общая поверхность VPS

| Транспорт | Threshold | Burst |
|---|---:|---:|
| TCP NEW/SYN | 120/min | 60 |
| UDP NEW | 300/min | 150 |

Для каждого IP запоминаются destination ports за 60 секунд. Четыре и более
порта формируют `port_sweep`.

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
установленный TCP connection, менее 1 KiB client traffic и закрытие без
прикладного ответа. FORTRESS журналирует серию FIN/RST на `2012–2022`, если:

- connection находится в `ESTABLISHED`;
- original direction передал от 1 до 1024 bytes;
- частота превышает 2/min с burst 2.

Сигнал `low_volume_session` остаётся alert-only: аналогичное поведение возможно
при нестабильной сети.

## 13. Decoy policy

`active_decoy_probe` означает, что клиент дошёл до прикладной HTTP-приманки, а
не просто открыл TCP-порт. Сигнал имеет вес 8 и при подтверждённом внешнем IP
может немедленно сформировать первый 10-минутный ban.

## 14. Whitelist

До scoring исключаются:

- loopback и link-local;
- IP самой VPS из state;
- `10.0.0.0/8`;
- `172.16.0.0/12`;
- `192.168.0.0/16`;
- `fc00::/7`;
- пользовательские IPv4/IPv6 адреса и сети.

## 15. Telegram

Технический alert содержит:

- IP;
- флаг GeoIP;
- ASN/owner;
- event, protocol и source;
- текущие signals;
- observed score;
- verified score, если он отличается;
- policy для alert-only evidence;
- TTL и offense для ban.

GeoIP/ASN обогащают сообщение, но не влияют на score. Категорию AntiDPI можно
отключить независимо от Honeypot, Fail2ban и system notifications.

Статистика `attempted`, `delivered` и `failed` позволяет отличить отсутствие
угроз от сбоя доставки Telegram.

## 16. Состояние и ограничения ресурсов

Основной state:

```text
/var/lib/hydra/antidpi.json
```

Ограничения:

- score entries: максимум 20 000 IP;
- retention неактивного evidence: 24 часа;
- signals на IP: последние 16 типов;
- ban history: последние 1000 записей;
- source relay mappings: максимум 8 MiB;
- TCP relay connections: максимум 2048;
- UDP relay flows: максимум 4096, idle timeout 60 секунд.

## 17. Эксплуатация

Установка или обновление runtime:

```bash
sudo hydra antidpi sync
```

Проверка состояния:

```bash
sudo systemctl is-active hydra-antidpi
sudo hydra doctor
sudo ipset list hydra_antidpi
sudo ipset list hydra_antidpi6
sudo journalctl -u hydra-antidpi -n 100 --no-pager
```

Безопасный локальный тест:

```bash
sudo hydra antidpi selftest --full --wait 3
```

Окно реального внешнего тестирования:

```bash
sudo hydra antidpi capture --seconds 180
```

Capture включает journal, новые JSONL records, runtime delta, доставку
уведомлений, firewall rules, TCP/UDP listeners, relay mappings и AWG debug.

## 18. Обновление с legacy-конфигурации

Этот порядок предназначен для существующей VPS с уже установленной HYDRA,
старым `hydra-portscan`, прежней схемой Caddy и/или AntiDPI ранней версии.
Команды выполняются на сервере из каталога проекта.

### Шаг 1. Сохранить состояние

До получения нового кода создайте штатную резервную копию:

```bash
cd /opt/hydra
sudo hydra backup --output /root/hydra-before-fortress.tar.gz
sudo hydra validate
```

Если очень старая версия ещё не содержит команды `hydra backup`, сначала
сохраните `/var/lib/hydra` и конфигурации сервисов доступным на сервере способом,
а затем продолжайте обновление. Не удаляйте старые файлы вручную до успешного
завершения `apply`.

### Шаг 2. Получить FORTRESS из ветки dev

```bash
cd /opt/hydra
git status --short
git pull origin dev
git rev-parse --short HEAD
```

`git status --short` должен быть пустым. Если на VPS есть локальные изменения,
их нужно сохранить отдельно и разрешить конфликт до `git pull`; принудительный
reset для обновления не требуется.

### Шаг 3. Проверить план миграции

```bash
sudo hydra validate
sudo hydra doctor
sudo hydra plan
```

`validate` проверяет persisted state, `doctor` — зависимости и runtime, а
`plan` строит конфигурацию без изменения системы. На этом шаге нужно устранить
ошибки портов, доменов, сертификатов и `tls_mux`, если они появились в выводе.

### Шаг 4. Применить общую конфигурацию

```bash
sudo hydra apply
```

`apply` пересобирает Sing-Box и Caddy L4 из актуального state, обновляет
маршруты с PROXY Protocol v2, создаёт и включает `hydra-source-relay` там, где
он нужен, синхронизирует plugin runtime и применяет миграцию Fail2ban. В рамках
миграции удаляются jail/filter `hydra-portscan`, старые protocol jails и legacy
iptables LOG rule; их функцию принимает AntiDPI. Удалять `hydra-portscan`
вручную до `apply` не нужно.

Успешный результат имеет вид:

```json
{
  "ok": true,
  "error": ""
}
```

### Шаг 5. Принудительно синхронизировать AntiDPI runtime

```bash
sudo hydra antidpi sync
```

Команда идемпотентна и безопасна для повторного запуска. Она:

- устанавливает недостающие `ipset`/`iptables` зависимости;
- создаёт IPv4/IPv6 ban sets и enforcement rules;
- обновляет TCP/UDP, port-sweep и Mieru telemetry rules;
- включает AmneziaWG dynamic-debug, если его предоставляет ядро;
- записывает актуальный systemd unit;
- выполняет `daemon-reload`, включает и перезапускает `hydra-antidpi`;
- возвращает в ipset ещё не истёкшие активные баны.

### Шаг 6. Перезапустить Telegram bot

```bash
sudo systemctl restart hydra-tg-admin
```

Это загружает новый формат сообщений, GeoIP/ASN, категории уведомлений и
обновлённую логику статусов. Отдельно перезапускать `hydra-antidpi` после
успешного `hydra antidpi sync` не требуется. Caddy и source relay уже
пересобраны командой `hydra apply`.

### Шаг 7. Проверить сервисы и миграцию

```bash
sudo systemctl is-active caddy-l4 hydra-source-relay hydra-antidpi hydra-tg-admin fail2ban
sudo ss -ltnp | grep -E ':2021|caddy-l4|hydra-source-relay'
sudo curl -fsS http://127.0.0.1:2021/config/ \
  | jq '[.. | objects | select(.proxy_protocol? == "v2")] | length'
sudo fail2ban-client status
sudo fail2ban-client status hydra-portscan
sudo ipset list hydra_antidpi
sudo ipset list hydra_antidpi6
sudo hydra doctor
```

Ожидаемый результат:

- основные сервисы имеют статус `active`;
- admin API `caddy-l4` слушает `127.0.0.1:2021`, а не занятый другим Caddy
  порт `2019`;
- количество маршрутов `proxy_protocol: v2` больше нуля, если включены
  протоколы, использующие source relay;
- `fail2ban-client status hydra-portscan` сообщает, что jail не существует;
- оба AntiDPI ipset существуют;
- `hydra doctor` не показывает критической рассинхронизации.

`hydra-source-relay` может отсутствовать или быть неактивным только если в
текущем state нет ни одного маршрута, которому нужна relay-атрибуция. Для
конфигурации с AnyTLS, TrustTunnel, ShadowTLS, Naive или другими relay routes
это является ошибкой и требует просмотра `hydra apply` и journal.

### Шаг 8. Проверить журналы и полный путь уведомления

```bash
sudo journalctl -u hydra-antidpi -u hydra-source-relay -u hydra-tg-admin \
  -n 150 --no-pager
sudo hydra antidpi selftest --full --wait 3
```

Selftest проверяет установку детекторов и создаёт диагностический архив. Для
подтверждения реального внешнего IP, нативной ошибки и Telegram delivery нужно
открыть capture-окно и выполнить неправильные подключения с другого адреса:

```bash
sudo hydra antidpi capture --seconds 180
```

После теста проверьте Telegram, `/var/lib/hydra/antidpi.json`, журналы сервиса и
наличие IP в `hydra_antidpi`/`hydra_antidpi6`. Для UDP и Mieru нормальным
результатом является технический `ALERT` без автоматического бана; для
подтверждённых TCP/TLS auth events бан появляется только после достижения
`verified_score >= 8`.

### Повторное применение и восстановление

Команды `hydra apply` и `hydra antidpi sync` рассчитаны на повторный запуск.
Если обновление оборвалось после `git pull`, сначала устраните ошибку из JSON
или journal, затем повторите обе команды в том же порядке. Не очищайте
`/var/lib/hydra/antidpi.json` и ipset без отдельной причины: там находятся
активные TTL, история offenses и состояние прогрессивных банов.

## 19. Отношения с Fail2ban и Honeypot

Устаревший `hydra-portscan` удалён из Fail2ban. AntiDPI отвечает за общую
сетевую разведку, а Fail2ban сохраняет SSH/auth jails.

Honeypot не является источником AntiDPI evidence. Если адрес одновременно
находится в двух контурах, AntiDPI удаляет дублирующее владение своим ban, не
ломая состояние Honeypot.

## 20. Что система не обещает

FORTRESS существенно расширяет наблюдаемость, но не может математически
гарантировать обнаружение любой атаки:

- корректное одиночное соединение неотличимо от обычного клиента;
- low-and-slow probe может оставаться ниже rate threshold;
- валидные украденные credentials выглядят как легитимная авторизация;
- NAT объединяет независимых клиентов за одним IP;
- прямой UDP source нельзя безопасно использовать для автоматического ban;
- upstream DDoS должен фильтроваться провайдером до VPS;
- GeoIP и ASN являются справочной, а не доказательной информацией.

Главный инвариант FORTRESS: **сомнительное событие может уведомить оператора,
но не должно автоматически заблокировать адрес без достаточного проверенного
доказательства**.
