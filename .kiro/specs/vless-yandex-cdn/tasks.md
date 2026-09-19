# Tasks: VLESS через Яндекс CDN (XHTTP, packet-up, uplink GET)

## Progress

| Область | Статус | Чем подтверждено |
| --- | --- | --- |
| Требования | готовы | `requirements.md` |
| Дизайн | готов | `design.md`, решения D1–D9 |
| Реализация | не начата | — |
| Живая проверка | не начата | гейт D9 |

## Dependency graph

```text
TSK-001 → TSK-002 → TSK-003 → TSK-004 → TSK-005
TSK-003 → TSK-006 → TSK-007
TSK-006 → TSK-008
TSK-003 + TSK-006 → TSK-009
TSK-005 + TSK-009 → TSK-010
TSK-002 → TSK-011
```

## Задачи

- [ ] **TSK-001 — Каркас плагина `vless_cdn` и состояние протокола**
  - **Requirement:** R1, R4, R8
  - **Deliverables:** новый плагин рядом с `vless_xhttp/`, регистрация в каталоге и реестре, поля состояния из дизайна (домены, путь, порт, uuid, ключи шифрования, регион, источник изображения), миграция и валидация схемы.
  - **Files:** `hydra/plugins/vless_cdn/`, `hydra/plugins/catalog.py`, `hydra/plugins/registry.py`, `hydra/core/state_*.py`, тесты.
  - **Acceptance:** плагин появляется в списке и в установке; установка и удаление не меняют другие протоколы; состояние читается после перезапуска; миграция покрыта тестом; расхождение пути/порта/доменов между состоянием и конфигами невозможно по построению.

- [ ] **TSK-002 — Установка: CDN-домен, origin-имя и сертификат origin**
  - **Requirement:** R1, R2
  - **Depends on:** TSK-001
  - **Deliverables:** шаг установки, который спрашивает CDN-домен и origin-имя, проверяет их, выпускает сертификат origin существующим сервисом (certbot, HTTP-01, временный :80) и показывает итог: домены, путь, порт ядра, срок сертификата.
  - **Files:** `hydra/services/vless_cdn_install.py`, `hydra/plugins/vless_cdn/` (значения и проверки), `hydra/services/certificates.py` (переиспользование), UI/CLI-рендеры, тесты. Установка живёт в слое сервисов, а не в плагине: плагинам запрещено импортировать `hydra.services`, и архитектурный тест это проверяет.
  - **Acceptance:** при пустом/некорректном имени установка останавливается до изменений; при ошибке certbot маршрут не публикуется; после успеха файлы сертификата на месте, а итог показывает всё, что нужно оператору.

- [ ] **TSK-003 — Маршрут origin в SNI-документе: h2c и PROXY v2**
  - **Requirement:** R2, R3
  - **Depends on:** TSK-002
  - **Deliverables:** backend с `route_kind: http_path_proxy` для origin-имени; явное объявление ALPN `h2` и `http/1.1` на L4-маршруте; внутренний Caddy HTTP server с `protocols: ["h1","h2c"]` и PROXY v2; отсутствие кеша/буферизации и малого лимита тела на XHTTP-маршруте; существующие SNI-маршруты не изменяются.
  - **Files:** `hydra/core/sni_router_planning.py`, `hydra/core/sni_router_document.py`, `hydra/core/sni_router_http.py`, тесты.
  - **Acceptance:** сгенерированный документ проходит валидатор Caddy; тест утверждает наличие `h1+h2c`, PROXY v2, отсутствие кеша на XHTTP и неизменность остальных маршрутов; в логах доступен согласованный ALPN.

- [ ] **TSK-004 — Inbound VLESS + XHTTP packet-up + VLESS Encryption**
  - **Requirement:** R4, R8
  - **Depends on:** TSK-003
  - **Deliverables:** генерация inbound'а ровно по таблице D3 (реальные поля ядра, отказ от `hKeepAlivePeriod`, `scStreamUpServerSecs` и h3-полей), свободный локальный порт, генерация X25519-пары, `decryption` на сервере, `encryption` для клиента, режим `1rtt`.
  - **Files:** `hydra/plugins/vless_cdn/inbound.py`, `hydra/plugins/vless_xhttp/tuning.py` (переиспользование), тесты.
  - **Acceptance:** ядро принимает сгенерированный конфиг; тест сверяет каждое поле с таблицей D3; приватный ключ не попадает в логи и в клиентский профиль; при отказе ядра изменение откатывается.

- [ ] **TSK-005 — Клиентский профиль и share-данные**
  - **Requirement:** R5
  - **Depends on:** TSK-004
  - **Deliverables:** native JSON клиента и share-данные; адрес — публичный CDN-домен и `:443`, SNI — публичный домен, параметры XHTTP и шифрования совпадают с серверными; IP origin не попадает в профиль.
  - **Files:** `hydra/plugins/vless_cdn/client.py`, переиспользование `vless_xhttp/client.py`, тесты.
  - **Acceptance:** тест сравнивает серверный и клиентский наборы параметров и падает при любом расхождении; в профиле нет origin-адреса; share-данные выдаются только если корректно выражают профиль, иначе честно помечаются как недоступные.

- [ ] **TSK-006 — Динамический сайт: генератор и таймер**
  - **Requirement:** R6
  - **Depends on:** TSK-003
  - **Deliverables:** генератор страницы (регион, столица, изображение, погода, часы по зонам, дата, подвал) и systemd-таймер каждые 10 минут; запись в существующий decoy-каталог; живые часы считаются в браузере по IANA-зонам; регион берётся из того же провайдера, что и флаг в меню, заголовком идёт город сервера.
  - **Files:** `hydra/plugins/vless_cdn/site/`, шаблоны, unit-файлы таймера, `hydra/services/security_intel.py` (расширение выборки полей), тесты.
  - **Acceptance:** страница отдаётся как обычный сайт и не выглядит заглушкой; при недоступной погоде страница не падает и показывает нейтральное состояние; часы идут без внешних API; метаданные региона берутся из состояния, при отсутствии — значения по умолчанию.

- [ ] **TSK-007 — Погода: клиент, кеш, фолбэк**
  - **Requirement:** R7
  - **Depends on:** TSK-006
  - **Deliverables:** клиент Open-Meteo с таймаутом, кеш 10–15 минут, сохранение последнего удачного ответа, нейтральный вывод при отказе.
  - **Files:** `hydra/plugins/vless_cdn/weather.py`, тесты.
  - **Acceptance:** тесты на таймаут, ошибку, пустой ответ и повторный запрос из кеша; при отказе страница формируется за время в пределах таймаута.

- [ ] **TSK-008 — Изображения региона: загрузка и обновление раз в 12 часов**
  - **Requirement:** R7
  - **Depends on:** TSK-006
  - **Deliverables:** загрузка из источника с пригодной лицензией, локальное хранение, обновление раз в 12 часов отдельным заданием, фиксация источника и атрибуции, запасной встроенный файл.
  - **Files:** `hydra/plugins/vless_cdn/assets.py`, каталог ассетов, тесты.
  - **Acceptance:** повторное обновление не ломает страницу; атрибуция видна на странице; при ошибке остаётся прошлая копия, при первом запуске — встроенный файл; тест фолбэка.

- [ ] **TSK-009 — Маршрутизация путей и защита от перехвата**
  - **Requirement:** R3, R6
  - **Depends on:** TSK-003, TSK-006
  - **Deliverables:** порядок маршрутов из D8: XHTTP-путь → ядро, `/assets/*` → статика с кешем, всё остальное → страница; запрет правила «любой путь в туннель»; проверка, что путь сайта не пересекается с XHTTP-путём.
  - **Files:** `hydra/core/sni_router_http.py`, `hydra/plugins/vless_cdn/`, тесты.
  - **Acceptance:** тест падает, если XHTTP-путь может быть отдан сайтом или если сайт перехватывает туннель; `/assets/*` кешируется, XHTTP — нет.

- [ ] **TSK-010 — Живая проверка варианта A (гейт D9)**
  - **Requirement:** R9
  - **Depends on:** TSK-005, TSK-009
  - **Deliverables:** прогон на выделенном сервере с реальным клиентом нашего же ядра: `packet-up`, uplink `GET`; подтверждение ALPN `h2` и приёма `h2c` внутренним сервером; проверка PROXY v2 (реальный адрес клиента доходит до ядра и до страницы); проверка сайта и недоступности страницы по XHTTP-пути; наблюдение за длительными соединениями и переподключением.
  - **Files:** отчёт о прогоне, скрипты проверки.
  - **Acceptance:** зафиксирован отчёт с фактами и цифрами; при провале `h2c` или PROXY v2 вариант A отклоняется и отдельно обосновывается переход к варианту B.

- [ ] **TSK-011 — Операторская документация и статус**
  - **Requirement:** R1, R6
  - **Depends on:** TSK-002
  - **Deliverables:** шаги на стороне Yandex CDN (`origin_protocol=https`, origin SNI, A-запись origin), описание того, что видит оператор, и обновление справочника и статуса протокола.
  - **Files:** `docs/`, рендеры статуса, тесты.
  - **Acceptance:** по документу можно настроить CDN без чтения исходников; в статусе видны домены, путь, порт, срок сертификата и время последних удачных обновлений погоды и изображения.

## Bugfix extension — один ключ имени для CDN-профиля (2026-09-19)

**Status:** design D13–D14 ready, awaiting implementation.
**Requirements:** `bugfix.md` → «Requirements amendment — cross-client CDN profile name».

### Dependency graph

```text
TSK-016 → TSK-017
```

- [x] **TSK-016 — Согласовать ключ резолвера URI-подписки с каноническим именем плагина**
  - **Requirement:** `bugfix.md` — один канонический ключ `vless_cdn` во всех форматах.
  - **Deliverables:** `_configuration_name_key()` в `hydra/services/subscriptions/links.py`
    возвращает `vless_cdn` для распознанного CDN VLESS; `vless:cdn` исчезает из production-кода
    вместе с условием `base_key = "" if key == "vless:cdn"`, которое переезжает на новый ключ
    (иначе family-override обычного VLESS снова начнёт накрывать CDN).
  - **Files:** `hydra/services/subscriptions/links.py`, `tests/test_configuration_names.py`,
    `tests/test_hydrabox_subscription.py`.
  - **Acceptance:** global и user override `vless_cdn` дают одинаковое имя в URI fragment и в
    HydraBox profile name; override `vless` по-прежнему меняет только обычный VLESS XHTTP; без
    override оба формата сохраняют свои прежние default; `resolve_configuration_name()`,
    `configuration_name_key()` и схема state не изменены.
  - **Red-first:** тест `test_a_cdn_vless_link_is_not_named_like_an_ordinary_xhttp_one` остаётся
    зелёным (различие профилей не отменяется), а новый сквозной тест на override `vless_cdn`
    обязан падать до правки.

  - **Факт:** красное зафиксировано — `3 failed` (`test_an_exact_cdn_override_does_not_rename_ordinary_vless`,
    `test_the_cdn_override_uses_the_plugin_key_every_client_reads`,
    `test_a_user_cdn_override_beats_the_global_one`); диагностика подтверждена живым вызовом:
    `_configuration_name_key()` → `'vless:cdn'`, override `vless_cdn` не находился. Фикс — обе
    строки (`key` и `base_key`) в одном диффе. После: `13 passed` в
    `test_configuration_names.py`, `110 passed` по шести файлам подписок/CDN.

- [x] **TSK-017 — Проверка, документация и закрытие**
  - **Requirement:** `bugfix.md` — regression evidence.
  - **Depends on:** TSK-016.
  - **Deliverables:** `pytest -q tests/test_configuration_names.py tests/test_hydrabox_subscription.py
    tests/test_subscriptions.py`, архитектурные guard'ы, `ruff`; обновлённые `docs/` и `CHANGELOG.md`,
    если наблюдаемое поведение меняется для оператора.
  - **Files:** существующие тесты VLESS CDN и подписок, `docs/`, `CHANGELOG.md`.
  - **Acceptance:** все выполненные команды завершаются `0`; в `tests/` не осталось обращения к
    ключу `vless:cdn`; живая проверка Throne/NekoBox отмечена как непроверенная локально, если
    клиент недоступен.

  - **Факт:** `2128 passed` по полному suite; ruff `All checks passed!`; архитектурные guard'ы
    `32 passed`; compileall OK. `vless:cdn` остался только в комментариях, объясняющих причину
    замены, и в докстроке регрессионного теста — ни одного обращения в коде. Живой прогон
    подтвердил паритет: URI fragment и HydraBox profile name дают одно имя при override
    `vless_cdn`; family-override `vless` в CDN-имя не протекает; без override оба формата
    сохраняют прежние default. `CHANGELOG.md` описывает смену ключа.
  - **Не проверено:** живые Throne/NekoBox — клиентов в этой среде нет. Импорт подписки в
    реальном клиенте остаётся за владельцем.

### Progress

| Задача | Статус | Факт |
| --- | --- | --- |
| TSK-016 | готова | красное→зелёное: `3 failed` → `13 passed`; `_configuration_name_key()` → `vless_cdn` |
| TSK-017 | готова | `2128 passed`; ruff чист; паритет ключа подтверждён живым прогоном |

## Completion criteria

- Протокол устанавливается по вводу CDN-домена и выдаёт рабочий клиентский профиль.
- Трафик идёт через CDN, uplink — методом `GET`, h2 до origin подтверждён живой проверкой.
- Обычный HTTPS-запрос отдаёт настоящий сайт о регионе, XHTTP-путь никогда не отдаёт страницу.
- Существующие протоколы и SNI-маршруты не изменились.

## Bugfix extension — Host, lifecycle и identity (2026-09-18)

### Dependency graph

```text
TSK-012 ─┐
TSK-013 ├─→ TSK-015
TSK-014 ┘
```

- [x] **TSK-012 — Унифицировать XHTTP Host CDN-цепочки**
  - **Requirement:** `bugfix.md` — единый XHTTP Host.
  - **Deliverables:** `VlessCdnPlugin.configure()` передаёт `cdn_domain` в server-side XHTTP transport; `origin_host` остаётся только TLS/SNI-значением.
  - **Files:** `hydra/plugins/vless_cdn/plugin.py`, `tests/test_vless_cdn_plugin.py`, `tests/test_vless_cdn_route.py`.
  - **Acceptance:** inbound, Caddy route и client profile содержат одинаковый CDN Host; origin остаётся в L4/certificate-маршруте; обычный VLESS XHTTP не меняется.

- [x] **TSK-013 — Убрать наследование имени CDN от обычного VLESS**
  - **Requirement:** `bugfix.md` — изоляция имени VLESS CDN.
  - **Deliverables:** `tag_client_link()` резолвит CDN только по точному ключу; family fallback
    `vless` остаётся для обычного VLESS, но не применяется к CDN.
  - **Files:** `hydra/services/subscriptions/links.py`, `tests/test_configuration_names.py`.
  - **Acceptance:** override `vless` меняет только обычный VLESS XHTTP; exact override меняет
    только CDN; встроенное имя CDN — `VLESS Яндекс CDN`.
  - **Примечание:** ключ, выбранный в этой задаче (`vless:cdn`), заменён на канонический
    `vless_cdn` в TSK-016; механика изоляции без family fallback сохранена.

- [ ] **TSK-014 — Собрать lifecycle CDN в application operation**
  - **Requirement:** `bugfix.md` — lifecycle boundaries.
  - **Deliverables:** TUI вызывает только `ApplicationService`; существующий сервис VLESS CDN владеет snapshot, provision/apply/timer/page/uninstall и компенсациями.
  - **Files:** `hydra/services/vless_cdn_install.py`, `hydra/services/application.py`, production wiring, `hydra/ui/_menus/extended_protocol_vless_cdn.py`, lifecycle tests.
  - **Acceptance:** сбои apply, timer, page и удаления восстанавливают desired state/runtime/timer; non-TUI removal не оставляет timer; plugin не импортирует services и не мутирует runtime в query hooks.

- [ ] **TSK-015 — Проверить конфиг и живую CDN-цепочку**
  - **Requirement:** `bugfix.md` — regression evidence.
  - **Depends on:** TSK-012, TSK-013, TSK-014.
  - **Deliverables:** узкие unit/architecture tests и операторские команды проверки live-конфига.
  - **Files:** существующие тесты VLESS CDN, `docs/` при изменении операторского lifecycle.
  - **Acceptance:** полный suite и ruff зелёные; Caddy Admin API и `/etc/sing-box/config.json` показывают один CDN Host; реальный XHTTP тест не возвращает `502` или `Not Found`.

### Progress

| Задача | Статус | Факт |
| --- | --- | --- |
| TSK-012 | готова | inbound/Caddy/client host сверены тестами |
| TSK-013 | готова | family override VLESS не меняет CDN-имя |
| TSK-014 | частично | TUI → ApplicationService и rollback provision/timer; generic low-level uninstall остаётся отдельной границей |
| TSK-015 | частично | 2123 pytest + ruff; live XHTTP после обновления HU ещё нужен |
