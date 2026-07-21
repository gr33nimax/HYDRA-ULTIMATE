# Анти-DPI модуль

> Актуальная полная спецификация релиза `2.5.1-dev «FORTRESS»`, включая
> двухуровневый scoring, UDP spoof-safety, source relay, Mieru silent-reject и
> подтверждённую протокольную матрицу, находится в
> [ANTIDPI_FORTRESS.md](ANTIDPI_FORTRESS.md).

AntiDPI — отдельный поведенческий контур. Fail2ban отвечает за SSH и
аутентификационные журналы, Honeypot — за ловушку на выделенном порту, а
AntiDPI коррелирует сетевые и протокольные признаки и применяет временные
блокировки через динамические IPv4/IPv6 ipset.

## Поток обработки

```text
Caddy JSONL ─┐
journald ────┼─> adapters -> normalized event -> score/decay/correlation
kernel LOG ─┘                                      |
                                                    v
                                     whitelist -> ipset -> INPUT DROP
                                                    |
                                                    v
                                      state/history/Telegram
```

Firewall ipset является единственным источником enforcement. В Caddy не
встраивается статический список адресов: он устаревал бы без reload и мог бы
удерживать IP после завершения таймаута.

## Источники

| Поверхность | Источник | Сигналы |
|---|---|---|
| TCP/443 и Caddy L4 | JSON logger `layer4` | unknown SNI, malformed ClientHello, handshake failure |
| HTTPS decoy | Caddy access JSON | CONNECT/TRACE, поиск `.env`, WordPress, CGI, actuator |
| Sing-Box transports | journald | protocol/auth/handshake failures с public peer IP |
| AmneziaWG | kernel dynamic-debug | invalid MAC/handshake |
| Hysteria2/QUIC | journald | invalid packet, QUIC handshake/retry |
| Mieru/Snell/Telemt/Naive/qWDTT | journald | implementation-specific ошибки |
| Вся VPS | rate-limited kernel firewall telemetry | TCP SYN/UDP и multi-port sweep |

Honeypot намеренно не входит в источники AntiDPI. Ловушка самостоятельно
владеет своими событиями, состоянием и firewall-блокировками; это исключает
двойной учёт и повторные Telegram-уведомления.

## Защита от ложных блокировок

Отдельный слабый сигнал не банит адрес. Score имеет half-life 5 минут. Kernel
SYN можно подделать, поэтому высокая частота одного порта сама по себе не даёт
права на бан. Блокировка разрешается, когда за 60 секунд замечены минимум
четыре destination port, сетевой burst коррелирует с ошибкой протокола либо
получен сильный сигнал встроенного HTTPS decoy.

Kernel-правила используют только target `LOG` и не блокируют трафик напрямую.
RFC1918, ULA, loopback, link-local, IP сервера и пользовательский whitelist
исключаются из анализа.

## Firewall и владение

Создаются ipset `hydra_antidpi` и `hydra_antidpi6`. В INPUT размещаются DROP по
ipset и rate-limited LOG-only правила TCP SYN/UDP. Старое правило и jail
`hydra-portscan` удаляются Fail2ban как миграционный артефакт. Fail2ban
сохраняет ответственность за SSH и auth-события.

## Состояние и health

`/var/lib/hydra/antidpi.json` записывается атомарно с fsync и mode 0600.
Read-modify-write защищён flock. Evidence ограничен по размеру и очищается по
возрасту. Healthcheck проверяет службу, оба ipset, DROP и kernel telemetry.
Служба запускается с ограниченным набором capabilities.

## Реальные ограничения

Невозможно гарантировать обнаружение абсолютно каждого сканера:

- корректное одиночное соединение неотличимо от обычного клиента;
- low-and-slow ботнет может остаться ниже per-IP порога;
- протокол без public peer IP в журнале нельзя связать с адресом;
- NAT объединяет многих клиентов за одним IP;
- DDoS-фильтрация должна выполняться у провайдера до VPS.

Для максимального покрытия используйте AntiDPI, Honeypot, Fail2ban для
SSH/auth, закрытый firewall по allow-list и provider DDoS protection.

## Нативный self-test

Для безопасной симуляции ошибочных подключений ко всем включённым транспортам:

```bash
sudo hydra antidpi selftest
```

Расширенный режим дополнительно запускает временные нативные клиенты с заведомо
неверной авторизацией:

```bash
sudo hydra antidpi selftest --full --wait 3
```

Для AnyTLS, TrustTunnel, ShadowTLS, Hysteria2, Mieru, NaiveProxy и Snell он
использует установленный `sing-box`. Временный конфиг создаётся с правами `0600`,
не меняет конфиги пользователей или сервисов и удаляется вместе с клиентским
процессом. Telemt, qWDTT и AmneziaWG не имеют совместимого локального клиента;
для них в матрице покрытия это указывается явно, без ложного статуса проверки.

Self-test последовательно отправляет короткие некорректные TCP, TLS и UDP первые
пакеты на локальные порты AmneziaWG, AnyTLS, TrustTunnel, ShadowTLS, Hysteria2,
Mieru, NaiveProxy, Snell, Telemt и qWDTT. Отключённые протоколы явно отмечаются
как `skipped_disabled`; их демон не работает и не может сформировать нативную
ошибку. Для Snell без активного пользователя будет указан `skipped_no_target`.

После каждого протокола команда отдельно собирает `journald` и новые строки
AntiDPI/Caddy-логов, проверяет их текущими адаптерами и создаёт архив с правами
`0600`:

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
повреждённых пакетов, запуск нативного клиента, наличие нативного лога и совпадение
с текущим фильтром. Проверка внешнего IP, firewall и доставки Telegram всегда
отмечается как требующая отдельного запуска с другой сети.

Локальный self-test намеренно не банит `127.0.0.1`, поэтому он проверяет
нативные ошибки и фильтры, но не Telegram и firewall. Полный внешний путь
проверяется отдельным запросом с другого IP на decoy URL.
