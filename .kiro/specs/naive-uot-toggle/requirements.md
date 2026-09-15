# Requirements: opt-out for Naive UoT (UDP over TCP)

**Type:** Quick Spec candidate (approach still open — see «Открытое решение»)
**Date:** 2026-09-15

## Intent (What + Why)

Naive сейчас собирается **только** с форком `aUsernameWoW/forwardproxy`, который умеет sing UoT
v1/v2, и Caddyfile безусловно несёт `passthrough_uot`. Пользователь с роутером сообщает:
на телефоне (Shadowrocket) всё нормально, а sing-box на роутере «через день-два подвисает», и
непонятно, дело в форке или в sing-box — данных мало. Форк помечен EXPERIMENTAL.

Нужен **серверный** способ выключить UoT-путь, чтобы администратор мог:
(1) убрать неоттестированный UoT-код из обслуживания трафика,
(2) получить чистый диагностический A/B: с UoT и без него,
не собирая и не выбирая сборки вручную.

## Что уже проверено фактом (исследование 2026-09-15)

- В форке **нет флага «выключить UoT»**. Опции хендлера: `pac_path`, `hide_ip`, `hide_via`,
  `disable_insecure_upstreams_check`, `hosts`, `probe_resistance`, `dial_timeout`,
  `max_idle_conns(_per_host)`, `upstream`, `passthrough_uot`, `acl`, `allowed_ports`,
  `auth_credentials`, `udp_uri_template`. Ни одной «uot off».
- UoT-ветка в `dialContext` срабатывает **безусловно** на magic-адрес
  (`sp.v2.udp-over-tcp.arpa`, `sp.udp-over-tcp.arpa`): либо passthrough в socks5-upstream,
  либо локальный `uot.NewServerConn`.
- При заданном `upstream` **ACL и `ports` не применяются**: обход `h.aclRules` для CONNECT
  выполняется только в ветке `h.upstream == nil`; README прямо пишет
  «Upstream is incompatible with `acl` and `ports` subdirectives». Заблокировать magic-адрес
  через ACL при текущем upstream нельзя.
- MASQUE / CONNECT-UDP сервер активен **только когда upstream не задан**. Значит при текущей
  схеме (Caddy → `socks5://127.0.0.1:1080`) **единственный UDP-путь — UoT**.
- Пин сборки (sni_router_install): `github.com/caddyserver/forwardproxy@caddy2=` +
  `github.com/aUsernameWoW/forwardproxy@c55724423ecd39402624538071f198036be79c25`.
  Содержимое файлов на пине и на ветке `naive` идентично (33 173 байта).
- Проверка «в сборке именно форк» живёт в пробном Caddyfile инсталлятора
  (`hydra/plugins/naive/installation.py::_download_binary`, строка `passthrough_uot`).

Источники: README и код форка (raw.githubusercontent.com/aUsernameWoW/forwardproxy), доки
sing-box по shared `udp-over-tcp` (таблица совместимости: Shadowrocket — UoT v1, v2 — нет).

## Requirements

### R1 — Серверное отключение UoT

- WHEN администратор выключает UoT для Naive THEN ни один UoT-запрос клиента SHALL не
  обслуживаться: magic-адрес не декодируется локально и не уходит passthrough в sing-box.
- Режим SHALL задаваться одним переключателем и SHALL NOT требовать ручного выбора сборки,
  ручной правки Caddyfile или ручной сборки Caddy.

### R2 — TCP не деградирует

- WHEN UoT выключен THEN обычный CONNECT-трафик (HTTP/HTTPS через Naive) SHALL продолжать
  работать через sing-box без потери маршрутизации, авторизации и probe_resistance.

### R3 — Согласованность клиентских артефактов

- WHEN UoT выключен THEN клиентские артефакты HYDRA SHALL NOT предлагать UoT: ссылки
  Shadowrocket для TCP/HTTP2 SHALL NOT содержать `uot`, документация SHALL называть рабочую
  схему для sing-box-клиентов.
- WHEN UoT включён THEN поведение SHALL совпадать с текущим (ссылки с `uot=2`, `passthrough_uot`).

### R4 — Обратимость и транзакционность

- Переключение SHALL выполняться существующим транзакционным путём применения плагина
  (snapshot → apply → проверка здоровья → commit) с возвратом рабочей конфигурации при сбое.
- Default SHALL сохранять текущее поведение (UoT включён): молчаливое изменение поведения
  существующих установок запрещено.
- Состояние SHALL быть видимым в статусе/TUI без секретов.

### R5 — Диагностируемость

- WHEN UoT выключен и клиент всё равно шлёт magic-адрес THEN сервер SHALL отвечать предсказуемой
  ошибкой, пригодной для лога (не «тихим» зависанием и не утечкой UDP напрямую из процесса).

## Открытое решение (design, требует выбора владельца)

| Вариант | Что делаем | Цена | Риск |
| --- | --- | --- | --- |
| A. Сборка по настройке | «выкл» = сток `caddyserver/forwardproxy@caddy2` без UoT-кода; Caddyfile без `passthrough_uot`; проба без него | единственный гарантированный off; HYDRA пересобирает Caddy при переключении (минуты, Go на сервере) | смена сборки — то, что владелец считает нежелательным; требует проверки установки на живом хосте |
| B. Блокировка magic-адреса в Caddy | тот же форк, но перед `forward_proxy` матчер `host sp.v2.udp-over-tcp.arpa sp.udp-over-tcp.arpa` → `respond 403` | без пересборки, мгновенно, обратимо | наш хак поверх форка, не фича; **не проверено живьём**, зависит от того, что Caddy доводит CONNECT до матчеров |
| C. Только клиентская сторона | сервер не трогаем; убираем `uot=2` из ссылок и документируем | нулевые изменения сервера | сервер продолжает принимать UoT от чужих клиентов; изоляция неполная |

## Out of scope

- Замена форка на другой форк/проект и любые правки самого форка.
- Отключение UDP как класса: QUIC-транспорт Naive (`naive+quic`/`http3`) остаётся как есть.
- Автовыбор режима по поведению клиента.

## Acceptance

- Переключатель виден администратору и меняет поведение сервера без ручной сборки.
- TCP-трафик после выключения UoT проверен (happy path + авторизация).
- Клиентские ссылки и документация согласованы с режимом.
- Тесты: рендер Caddyfile в обоих режимах, проба установки, ссылки Shadowrocket, валидация
  настройки, откат при сбое применения.
- Живая проверка на Linux-хосте обязательна перед объявлением готовности (в текущем Windows
  worktree её выполнить нельзя — фиксируем честно).
