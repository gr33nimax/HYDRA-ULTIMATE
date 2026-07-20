# Анти-DPI модуль

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
| Honeypot | `/var/log/hydra-honeypot.log` | подключение к порту-ловушке |

## Защита от ложных блокировок

Отдельный слабый сигнал не банит адрес. Score имеет half-life 5 минут. Kernel
SYN можно подделать, поэтому высокая частота одного порта сама по себе не даёт
права на бан. Блокировка разрешается, когда за 60 секунд замечены минимум
четыре destination port, сетевой burst коррелирует с ошибкой протокола либо
получен сильный decoy/honeypot-сигнал.

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
