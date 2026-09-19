# Bugfix: единый XHTTP Host и изоляция имени VLESS CDN

## Current behavior

1. На HU Caddy принимает CDN-origin запрос, находит XHTTP-путь и проксирует h2c на inbound, но
   передаёт `Host: cdn.gr33nimax.online`. В том же живом конфиге inbound `vless-cdn-in` ожидает
   `transport.host: gr33nimax.online`. После устранения TLS-ошибки это даёт `Not Found` от
   XHTTP-цепочки.
2. Переименование CDN-профиля сохраняется UI и читается HydraBox под каноническим plugin key
   `vless_cdn`, поэтому HydraBox показывает заданное оператором имя (например, `Обход БС`).
   Общий pipeline URI-ссылок распознаёт тот же CDN-профиль по `extra.uplinkHTTPMethod=GET`, но
   резолвит другое имя — `vless:cdn`. Throne и NekoBox не находят override `vless_cdn` и получают
   fallback `<email> VLESS Яндекс CDN`.

## Expected behavior

- WHEN HYDRA формирует VLESS CDN inbound и Caddy-прокси THEN оба SHALL использовать одно публичное
  CDN-имя как XHTTP `Host`; путь и локальный порт остаются общими для Caddy, inbound и клиента.
- WHEN HYDRA формирует или тегирует ссылку VLESS CDN THEN её protocol identity и отображаемое имя
  SHALL оставаться `VLESS Яндекс CDN` и SHALL NOT наследовать ключ или suffix обычного VLESS XHTTP.
- WHEN включается, выключается, переустанавливается или удаляется VLESS CDN THEN lifecycle SHALL
  изменять только состояние, inbound, маршрут, таймеры и артефакты VLESS CDN; обычный VLESS XHTTP
  и его клиентские имена SHALL остаться без изменений.

## Unchanged behavior

- `origin_host` остаётся именем origin SNI, сертификата и L4-маршрута; он не становится адресом
  клиента и не должен попадать в публичный клиентский профиль.
- Caddy L4 продолжает владеть `:443`; обычный VLESS XHTTP и все чужие SNI-маршруты не меняются.
- Не добавляются новый lifecycle-сервис, абстракция тегирования или новая схема состояния: фикс
  использует существующие контракт, plugin lifecycle и subscription pipeline.

## Regression evidence

1. Unit-тест сверяет XHTTP `host` в inbound, Caddy `Host` и клиентском профиле для CDN-сценария.
2. Unit-тест прогоняет VLESS CDN и обычную VLESS XHTTP ссылку через общий тегировщик: CDN остаётся
   `vless_cdn` / `VLESS Яндекс CDN`, обычная сохраняет прежнюю идентичность.
3. Lifecycle-тесты проверяют enable/disable/reinstall/uninstall CDN и подтверждают отсутствие
   изменений в состоянии и конфиге обычного VLESS XHTTP.
4. На HU после применения: Caddy admin API и `/etc/sing-box/config.json` показывают один `Host`;
   реальный XHTTP-клиент проходит CDN без `502` и `Not Found`.

## Requirements amendment — cross-client CDN profile name (2026-09-19)

**Status:** requirements written; design D13–D14 и TSK-016–TSK-017 готовы, реализация не начата.

### Expected behavior

- WHEN оператор переименовывает VLESS CDN через существующий интерфейс THEN система SHALL
  сохранять и резолвить это имя под одним каноническим ключом `vless_cdn` во всех форматах:
  URI-подписке для Throne/NekoBox и HydraBox v2.
- WHEN точного global или user override `vless_cdn` нет THEN каждый формат SHALL сохранить свой
  текущий встроенный default; расхождение default-ов между форматами не является дефектом.
- WHEN оператор переименовывает обычный VLESS/XHTTP под ключом `vless` THEN CDN-профиль SHALL
  не изменить имя; обратное также верно.

### Unchanged behavior

- Механизм распознаёт CDN по `extra.uplinkHTTPMethod=GET`, а обычный VLESS XHTTP — по своему
  профилю; два профиля не сливаются.
- Формат ссылки, публичный label `VLESS Яндекс CDN`, структура HydraBox v2 и ключ плагина
  `vless_cdn` не переименовываются.

### Regression evidence

1. Один global override `vless_cdn: "Обход БС"` даёт `Обход БС` в URI fragment и в HydraBox
   profile name; проверка охватывает CDN VLESS, а не только mock plugin.
2. Один user override `vless_cdn` имеет тот же результат и не затрагивает другого пользователя.
3. Override `vless` изменяет только обычный VLESS/XHTTP; `vless_cdn` — только CDN.
4. Отсутствие override даёт в URI прежний default с email пользователя, в HydraBox — прежний
   `subscription_profile_name`; оба обязаны остаться неизменными.
5. Ни один формат SHALL NOT требовать persisted-миграции: ключ `vless_cdn` уже используется
   записью переименования в UI и JSON-профилем, поэтому меняется только читатель URI-подписки.
