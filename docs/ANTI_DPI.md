# Анти-DPI модуль

Анти-DPI отделён от Fail2ban: Fail2ban остаётся журналным механизмом для
аутентификационных ошибок (SSH/AWG), а `antidpi` анализирует поведение на L4 и
использует собственные ipset `hydra_antidpi{,6}`.

## Что фиксируется

Сигналы намеренно слабые по отдельности и объединяются score-моделью:

- некорректный TLS ClientHello/первый пакет и protocol mismatch;
- не-TLS данные на TLS-маршруте;
- неизвестный SNI;
- повторные ошибки рукопожатия;
- burst TCP-подключений и QUIC retry-бурст;
- аналогичные события от UDP/TCP адаптеров (поле `kind` нормализуется).

Один сбой не банит адрес. Порог по умолчанию — 8 баллов. Score имеет
экспоненциальный half-life 5 минут, бан сохраняется на 24 часа и
восстанавливается после перезапуска. Поддерживается IPv4/IPv6 whitelist.

## Матрица покрытия

| Поверхность | Источник | Подтверждённые сигналы |
|---|---|---|
| Caddy L4 TCP/443 | JSON logger `layer4` | unknown SNI/certificate, malformed ClientHello, TLS handshake/EOF |
| HTTP(S) decoy | Caddy access JSON | CONNECT/TRACE и активный поиск `.env`, WordPress, CGI, actuator |
| AmneziaWG | kernel dynamic-debug journal | invalid MAC, invalid/unknown handshake |
| Sing-Box transports | `sing-box.service` journal | handshake/protocol/authentication failures с публичным peer IP |
| Hysteria2/QUIC | service journal | invalid packet/QUIC handshake с публичным peer IP |
| Mieru/Snell/Telemt | service journal | доступные implementation-specific handshake failures |

Покрытие называется доступным только если конкретная версия сервиса пишет
публичный peer IP. Зашифрованный протокол без такого источника нельзя безопасно
приписать адресу за локальным reverse proxy; модуль в таком случае не делает
вид, что сигнал существует.

## Caddy L4

При наличии записей в `/var/lib/hydra/antidpi.json` генератор Caddy добавляет
первый маршрут `remote_ip` с handler `close`. Это отбрасывает адрес до SNI,
TLS-терминации и проксирования. Такой matcher и close-handler предоставляются
официальным caddy-l4 ([remote IP matcher](https://caddyserver.com/docs/caddyfile/matchers),
[close handler](https://pkg.go.dev/github.com/mholt/caddy-l4/modules/l4close)).
Сборка Caddy явно подключает `modules/l4close` и проверяет наличие
`layer4.handlers.close` через `caddy list-modules`.

## Ограничения покрытия

Зашифрованные протоколы нельзя надёжно классифицировать по одному отпечатку:
ECH, NAT и мобильные сети создают ложные совпадения. Поэтому модуль использует
только наблюдаемые до расшифровки свойства (первый пакет, SNI, ошибки, частоту)
и требует повторные/комбинированные сигналы внутри временного окна. Формат TLS ClientHello и обязательность
проверки структуры определены [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446).
