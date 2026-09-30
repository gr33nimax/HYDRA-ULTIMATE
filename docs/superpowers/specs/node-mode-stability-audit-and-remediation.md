# Режим ноды: технический и UX-аудит и ТЗ на стабилизацию

## 1. Решение по готовности

Статус реализации: **R1, R2, R3, R4 и остаток R5 выполнены**, R6 — частично: сквозной тест основы и ноды есть и входит в Linux integration, но он не покрывает SSH-установщик и две физические машины (это остаётся за существующими integration-скриптами и проверкой на живой паре). Коммиты: `1f8c60b` (R1), `62df46c` (R2), `0b87b4e` (R3 + F19), `cf0dcd5` (R4), `cad9e00` (R5-остаток), далее R6 (F20 + причина apply).

Режим ноды нельзя считать доказанно стабильным по текущим CI. Проверенный пользовательский результат должен быть «установил → получил рабочие профили в подписке», а не «службы запущены / API доступен / тесты зелёные».

База аудита: исходники dev `d4230566a791a2ab699b7cefea65ce5623e2ccb0`, предоставленный пользователем экран и прежняя диагностика двух VPS. В рамках этого аудита удалённые команды не выполнялись, production-код и VPS не менялись. Старые данные gen=2/pub=0 и DNS не являются свежей диагностикой после обновления. Причина текущей пустой подписки на VPS ещё не установлена.

Просмотрены: base/node TUI, поля протоколов, NodeManager, обе стороны reconciliation, HTTP/mTLS transport, immutable snapshot store, subscription node-profile reader, sync orchestration, AWG/VLESS/MTProto владельцы команд и существенные regression tests. Это аудит критического пути режима ноды, не обещание найти каждый дефект во всём репозитории. Отдельно ниже перечислены проверки, для которых нужна изолированная Linux integration или свежие runtime-данные.

## 2. Подтверждённые дефекты

Приоритеты: P0 — нарушает готовность/публикацию; P1 — эксплуатационная надёжность и восстановление; P2 — ясность интерфейса. Подтверждение кодом не означает воспроизведение на конкретной VPS.

### F01 · P0 · Предыдущий фикс не восстанавливает уже повреждённый AWG

**Закрыто.** Готовность режима теперь определяется материалом (`_paddings_below_floor` + `mode_readiness`), а подготовкой занимается владелец (`prepare_node_config`); регрессия воспроизводит именно повреждённое состояние «режим 3.1 записан, `S3=0` в профиле» на настоящем плагине.

В `hydra/services/nodes/reconcile.py::_apply_owned_transitions` подготовка AWG выполняется только если desired mode отличается от сохранённого. `protocol_mode=3.1` при отсутствующих profiles пропускает и создание профиля, и команду владельца.

Локальный изолированный эксперимент: AppState с installed AWG, config={protocol_mode:3.1}, desired 3.1; вызов transitions → ни rotate_obfuscation, ни set_protocol_mode не вызываются. Это не исправленный случай «режим совпадает, материал отсутствует». Регрессия с настоящим плагином проверяет config={}, но не повреждённый config с уже записанным 3.1.

Исправление: readiness определяется валидностью локального материала и effective configuration, не только равенством строк. Идемпотентная подготовка через владельца должна восстанавливать отсутствие/некорректность материала, не ротируя исправные ключи. Проверить и installed=false путь: install тоже может заполнить режим по умолчанию.

### F02 · P0 · Слияние уничтожает результат команды VLESS

**Закрыто.** Подготовка VLESS вынесена в `hydra/plugins/vless_xhttp/preparation.py` и вызывается после слияния, после неё слияния нет; тест на настоящем плагине проверяет handshake, passthrough-маршрут, tombstone decoy, сохранение ключей и переходы reality↔tls↔reality без ротации здорового материала.

`vless_xhttp/security.py::apply_reality_mode` записывает reality_handshake, _tls_passthrough_route и tombstone _tls_http_decoy_route=None, удаляет domain/cert_file/key_file. Последующее `_merge_local_settings` заменяет публичный config и не сохраняет эти три поля, так как их нет в NODE_LOCAL_MATERIAL_KEYS. Desired domain при этом возвращается.

Изолированный эксперимент с настоящей apply_reality_mode и фиктивными ключами: все три owner-поля отсутствуют после merge. Реальный handshake/routing результат команды не сохраняется. Для TLS аналогично нельзя терять metadata decoy route.

Исправление: сначала нормализовать публичное намерение, затем дать владельцу сформировать effective config целиком; не перекрывать его результат последующим generic merge. Не лечить только добавлением ещё трёх строк в реестр: в следующем протоколе ошибка повторится. Regression: настоящий VLESS owner, оба направления TLS↔Reality, повторное применение, изменение handshake при неизменном режиме, routing plan и клиентский SNI.

### F03 · P0 · Публикация не означает наличия требуемых профилей

**Закрыто на основе.** `NodeSnapshotReconciler._coverage` отказывает в публикации пустого экспорта и сообщает неполное покрытие предупреждением; `NodeSyncResult` несёт `coverage` и `warnings`. Осознанное решение: node-сторона остаётся терпимой к непустому, но неразбираемому клиентскому конфигу, потому что часть плагинов отдаёт клиентский материал не в JSON; обещание даётся там, где его читают — на основе.

`NodeReconciler._export_state` принимает пользователя с profiles=(); некорректный JSON client_config `_singbox_documents` превращает в пустой tuple. `_validate_export` основы проверяет schema/id/generation, но не ожидаемое покрытие UUID/протоколов/форматов. Поэтому structurally valid пустой экспорт может получить статус published.

Исправление: для каждого eligible пользователя и выбранного протокола вычислять ожидаемую поверхность по capabilities; объяснять отсутствие каждого профиля. Пустой экспорт допустим для ноды без eligible пользователей/с выключенными протоколами, но это не «готовые профили». Ошибка генерации JSON — typed artifact error, а не незаметное отсутствие документа. Неподдерживаемый формат клиента — отдельное штатное состояние, не ошибка всей ноды.

### F04 · P1 · Реальная ошибка теряется в нескольких слоях

**Закрыто частично.** Ответ ноды на неудачный apply содержит этап и редактированную
причину, и основа показывает её в ошибке операции. Остальные пути (export, publish,
upgrade) всё ещё возвращают обобщённые сообщения — это остаток пакета.

Transport `/apply` возвращает только snapshot apply failed, `/export` — export is not current. `reconcile_all` оставляет лишь имя exception. `traffic_reports` глотает все ошибки. В `nodes.py` пользователь видит лишь «операция не выполнена (NodeControlError)», установка — «Операция не завершена (RuntimeError); проверь диагностику».

Кроме того diagnostics возвращает только application.apply_error: исключение preparation/export/save может не быть ошибкой ConfigurationApplier и не объясняться этой строкой.

Исправление: безопасный typed operation result: stage, code, bounded redacted message, retryable, operation_id. Сохранять последний outcome на обеих сторонах независимо от источника исключения, связывать rollback failure с исходным failure. Не выводить str(exc) без redaction.

### F05 · P1 · Состояние связи одноразовое и смешано с ошибками операций

**Закрыто.** `hydra/services/nodes/observation.py` — рантайм-проекция вне desired state; `NodeManager` пишет результат каждой операции (check/refresh/update/remove), TUI показывает возраст проверки, этап и причину. Фоновая сверка Sync Agent обновляет наблюдения без ручного действия.

`node_card` каждый раз начинает observation с «не выполнялась (пункт 4)», не делает автоматическую проверку; list_nodes показывает только desired config. Любое исключение rename/cookie/upgrade/refresh заменяет observation, даже если это не ошибка связи. `check` не хранит результат и timestamp.

Исправление: отдельная runtime observation store, не desired NodeConfig; connection health, apply state, export availability, software version — разные оси. Отображать время и freshness. Непроверенная/устаревшая связь не называется «недоступна»; ошибка настройки не называется сетевым обрывом.

### F06 · P1 · API health ошибочно легко прочитать как готовность сервера

`transport.py::do_GET /health` отдаёт ok=True, node id, generation и contract. Ядро, listeners, plugin health, export coverage, версия программы туда не входят. `NodeManager.check` даёт ok=True даже при непустом last_error.

Исправление: назвать это control connectivity и отдельно возвращать operational readiness. Нельзя выдавать «готова», пока не подтверждены apply, требуемые listeners и profile coverage. Статус службы Sing-Box не доказывает доступность клиентских протоколов.

### F07 · P1 · Автосинхронизация есть, но её результат почти невидим

Нельзя утверждать «вообще нет автоматизации»: sync_cycle.node_accounting_cycle вызывает collect_node_traffic и reconcile_nodes. Но reconcile_all возвращает failed outcomes, а cycle не обрабатывает возвращённый отчёт; внутри best-effort ошибок нет единой observation истории. Неизменный опубликованный digest в refresh возвращает unchanged до health: это не автопроверка доступности.

Исправление: отдельный bounded наблюдатель связи + отчёт reconciliation. Сохранять outcomes, показывать последнюю попытку/успех/следующий retry. Accounting не должен быть единственным источником проверки связи. Сетевые вызовы вне state lock, не на каждом запросе подписки.

### F08 · P1 · Недоказанная recovery подсказка после частичной установки

`add_node` после install и provisioning failure предлагает retry with the same node ID, но это не resume protocol. До register нет managed node record; повторная обычная установка не обязана быть разрешена bootstrap на уже установленной VPS. После register/initial refresh failure запись остаётся, но generic UI не показывает этап/способ продолжения.

Исправление: persisted provisioning operation с checkpoints либо минимальная явно реализованная команда «Продолжить подключение существующей ноды». Повтор проверяет identity/SSH pin и принадлежность установки, не перезапускает blind bootstrap. Не удалять установленную VPS в качестве обычного recovery.

### F09 · P1 · Поддержка протоколов объявлена шире доказанного reconcile контракта

`protocol_choices` выводит transports по subscription capabilities, а не по node readiness. `_apply_owned_transitions` знает AWG и VLESS; MTProto set_web_settings/set_cover_domain владеют routing metadata и подтверждением смены домена, но wizard передаёт web_mode/web_domain/domain как сырые поля. `NODE_LOCAL_MATERIAL_KEYS` — вручную составленный неполный список.

Исправление: явный контракт node support/preparation/public settings у канонического владельца. Предлагать только проверенные на ноде режимы. Проверить каждый transport отдельно: fresh install, config update, repeat, failure rollback, export. Не обойти подтверждение изменения уже выданных ссылок.

### F10 · P1 · Обновление заканчивается на scheduled

`_upgrade` честно пишет «это не подтверждение завершения», но нет дальнейшего пользовательского результата. NodeUpgradeScheduler планирует systemd worker; health не содержит actual revision; NodeConfig.revision меняется до завершения update. Карточка «Ветка/SHA» не отделяет target от installed.

Исправление: target/installed revision, состояние операции scheduled/running/succeeded/rolled_back/failed, безопасный прогресс и retry. Успех определяется readback actual revision и readiness, не scheduling response.

### F11 · P1 · Неизменный desired не восстанавливает отсутствующий опубликованный файл

**Закрыто частично.** Чтение подписки больше не рвётся из-за одной сбойной ноды (нода исключается, причина передаётся через `on_error`), а покрытие видно в наблюдении. Автоматическая перепубликация при отсутствующем локальном снимке при неизменном desired ещё не реализована — это остаётся в R3-остатке.

`_reserve_generation` при совпадении digest и наличии published_digest может вернуть unchanged, не проверяя snapshot. `snapshot_store.load` бросает при отсутствующем/повреждённом файле; node_profiles_for_user не изолирует такую ошибку по ноде. Карточка считает наличие указателя публикацией, не проверяя доступность материала.

Исправление: отдельно проверять local publication integrity и покрытие; автоматический republish новой generation после безопасной сверки. Ошибка одной ноды не должна убирать работоспособные локальные/другие профили. Нельзя принимать повреждённый материал: quarantine/omit affected node + redacted diagnostic, не ослабление hash checks. HTTP реакцию проверить integration-тестом.

### F12 · P2 · Пустые подписи в emergency TUI подтверждены

`node_emergency._runtime_lines` выводит plugin.meta.display_name напрямую. Для пустой display_name получается « : работает». На основе уже есть protocol_label fallback, на ноде он не используется. Экран пользователя подтверждает проблему.

Исправление: единая функция отображения protocol name через application/catalog или существующий pure UI helper, с fallback. Snapshot/render tests для пустого display_name всех доступных transports.

### F13 · P1 · Аварийный экран не отвечает на главный вопрос

На ноде только identity, ядро, enabled/running protocols и отдельный пункт ошибки. Нет результата последнего snapshot, времени, generation/digest, числа пользователей/профилей, control readiness, версии, причин неготовности. Пользователь не может понять, управляема ли нода и почему её нет в подписке.

Исправление: read-only сводка сразу показывает последнюю ошибку и этап, applied generation, профильное покрытие и actual version. На ноде нельзя объявлять «опубликовано в подписках основы», если основа этого не подтверждала. Не добавлять локальный второй writer пользователей/desired state.

### F14 · P2 · Меню основы устроено по внутренним операциям

Карточка показывает 9 действий одновременно: check, refresh, upgrade, removal, cookies и detach равноправны. Пользователь должен различать API connectivity и публикацию generation. VK cookies видны даже когда Calls не используется; опасные операции не отделены от обычных. «Сверка: published» требует знания внутреннего англоязычного enum.

Исправление: основной экран — статус/профили/проблема и одно контекстное действие. Обычные действия: настройки, обновление, подробности. Cookies только в настройках Calls. Removal/detach — в разделе опасных действий с сохранением существующих подтверждений.

### F15 · P2 · Поля мастера не зависят от сценария, hint не выводится

`NodeField.hint` задан, но `_ask` не использует его. Hysteria2 всегда спрашивает Mbps даже для BBR; MTProto — WEB-domain даже при off; VLESS Reality использует поле domain с TLS-подписью. Значение enum 0 значит «Оставить как есть», а text 0 — «отмена». При редактировании весь набор полей проходится заново. collect_protocol_config не удаляет прежний текстовый ключ, если получен пустой value.

Исправление: условные поля, единая отмена, выбор конкретного изменяемого параметра; short contextual hints лишь при необходимости. Reality handshake и собственный TLS domain — разные понятия. Явный reset к default/удаление optional value, без неоднозначного пустого ввода.

### F16 · P1 · Preflight не доказывает выполнимость выбранной конфигурации

Мастер проверяет форму данных и required fields, но не выполняет общий plan для node-specific конфликтов SNI/UDP owner, режимов, prerequisites. DNS/сертификат/cover host не проверяются им на соответствие типу поля до remote mutation. Прежнее локальное getaddrinfo failure не доказывает актуальный authoritative NXDOMAIN.

Исправление: server-side pure validation/plan до mutation, доступность проверять с ноды для локальных TLS prerequisites. DNS mismatch возвращает точную проблему, разрешает повторную проверку; не требовать A→node для borrowed Reality/FakeTLS/CDN всех типов подряд. Не выдавать network probe за гарантию выдачи сертификата.

### F17 · P1 · Нода блокирует редактирование desired settings при потере связи

`_protocols` и NodeManager.change_protocol сначала вызывают check. Имя можно менять офлайн, но для исправления desired config/выключения неисправного протокола нужна работающая связь.

Исправление: сохранить валидное desired независимо от reachability, явно показать «сохранено, ожидает применения». Online apply — попытка с подтверждённым outcome, не ложный rollback желаемой конфигурации из-за недоступной ноды. Для операций, которые инвалидируют выданные профили, показывать специальное подтверждение и ограничение офлайн.

### F18 · P1 · Тесты не соответствуют заявленной готовности

Новый тест VLESS имитирует set_security и создаёт только ключи, не настоящие routing/handshake metadata, поэтому F02 пропускается. AWG real-plugin case проверяет mode отсутствует, но не тот же mode при повреждённом материале. Много reconcile tests используют MagicMock enabled_subscription_names=set(), то есть не проверяют появление профилей после apply. Generic Linux integration не доказывает two-host node path.

Исправление: regression fixtures прежнего runtime, настоящие protocol preparation/client exporters, двухсторонний контроль API, публикация и загрузка подписки для того же UUID. В CI отдельно показывать node-e2e результат, а не ссылаться на общий suite.

### F19 · P1 · Маскирование секретов покрывало не все формы

**Закрыто.** `redact_text` теперь скрывает значение `Authorization` вместе со схемой, cookie-заголовки целиком, блоки приватных ключей и учётные данные в URL. Найдено при работе над R3: наблюдения и диагностика начинают показывать текст ошибок, и токен после `Bearer` попадал бы в вывод как есть.

### F20 · P0 · Ссылка AmneziaWG не проходила контракт экспорта

**Закрыто.** Плагин подставлял тег ссылки сырым и кодировал только разделяющий пробел; остальные транспорты кодируют тег целиком. Контракт экспорта отвергает ссылку с пробелом, поэтому нода с включённым AmneziaWG не могла опубликовать ни одного профиля — независимо от того, исправлены ли переходы режимов. Найдено сквозным тестом основы и ноды (R6), который теперь входит в Linux integration.

## 3. Риски, не объявляемые доказанными авариями

- Reconcile/traffic выполняются по нодам последовательно; общий reconciler lock сериализует запросы. Client timeout=10s на запрос, а apply может требовать установки/сертификата дольше. Нужны измерения задержек, deadline всего цикла и тест slow/offline node, чтобы не задерживать локальные квоты.
- Node snapshot выполняет последовательные user/protocol lifecycle операции и затем best-effort rollback. Есть отдельная защита Calls pool. Нужно failure injection для host artifacts после каждого side effect, revision conflict, save failure и rollback failure: равенство state не доказывает восстановление host.
- `/health`, `/export`, `/traffic` читают state отдельно от apply lock. Проверить согласованность reads при apply, upgrade и user reset; не принимать mixed generation.
- HTTP server ThreadingHTTPServer имеет bounded body, но в просмотренном transport нет явного read/handshake deadline или лимита concurrent requests. Проверить Slowloris/slow authenticated base и TLS handshake stalls в изолированной среде. Это hardening review, не утверждение о подтверждённой эксплуатации.
- NODE_LOCAL_MATERIAL_KEYS означает ownership только при merge, не полноценную allowlist публичных config. Проверить path-like параметры, вложенные объекты и локальные material overrides; base trust не отменяет входную валидацию.
- Подписки используют последнее подтверждённое состояние, в reader нет нового фильтра по текущему user.disabled_protocols. Проверить политику показа устаревших профилей, истечение/block и degraded indication отдельно от неизбежного задержанного отключения на офлайн VPS.
- Реальное состояние VPS, текущая revision, DNS, last operation error, published file, UUID coverage и фактический HTTP subscription response требуют свежей read-only диагностики. Не назначать повторную установку как проверку гипотезы.

## 4. ТЗ: пользовательский контракт

### 4.1 Главный сценарий

Пользователь выбирает сервер и протоколы → видит понятный preflight → подтверждает установку → видит стадии → получает «Готова: N профилей для M пользователей» либо конкретное «Нужен домен / настройка не применена / нет связи». Нельзя заканчивать зелёным сообщением на регистрации, старте ядра или scheduled upgrade.

Автоматическое reconciliation и publication — обычный путь. Ручной «обновить экспорт» не обязательный шаг успешной установки/настройки. Контекстное «Повторить» остаётся для восстановления; force-generation спрятана в диагностику.

### 4.2 Модель наблюдения

Отдельный injected runtime store: node_id, checked_at, last_success_at, control status, observed revision/contract/applied generation, operation stage/code/message/id, publication integrity/age, coverage counts, retry_at. Это runtime-проекция вне desired state; записи не увеличивают desired revision. Хранить ограниченную историю, atomic writes, permissions и redaction.

Состояния интерфейса: «Подключается», «Готова», «Применяются изменения», «Нужна настройка», «Нет связи — используются последние профили», «Ошибка обновления», «Не проверялась / проверка устарела». Несколько осей хранятся отдельно; summary status выводится детерминированно. «Готова» запрещена при отсутствующем требуемом материале или публикации.

### 4.3 Автопроверка

Предлагаемые проверяемые defaults: первый refresh observation при входе в раздел запускается асинхронно, cached view появляется не позднее 1s; индивидуальная network deadline 3s для health; health interval 30s, stale threshold 90s. Reconcile имеет отдельный deadline и single-flight per node; не отменять host transaction HTTP timeout без согласованного результата. Retry transient failures 5/15/30/60s, затем до 5min с jitter; configuration errors ждут изменённого desired либо осознанного retry. Параметры централизованы и тестируются fake clock.

Локальные операции и квоты не ждут всей серии недоступных нод. Subscription endpoint читает только локальные подтверждённые snapshots и runtime metadata, не ходит к нодам.

### 4.4 Экран основы

```text
Ноды
  Великобритания   Нужна настройка · профили не опубликованы
  Второй сервер   Готова · 6 профилей · проверка 12 с назад

[1] Добавить сервер
[2] Великобритания
[3] Второй сервер
[0] Назад
```

```text
Великобритания
Нужна настройка: AnyTLS не удалось подготовить
Связь: доступна · проверка 12 с назад
Подписки: 0 профилей · причина: применение не завершено

[1] Исправить настройки        (если known action)
[2] Протоколы и профили
[3] Обновление программы
[4] Подробности                (ошибка, стадии, версии, журнал)
[5] Опасные действия
[0] Назад
```

Показанные числа — пример layout, не данные VPS. Основное действие меняется по состоянию: «Повторить подключение», «Повторить применение», «Проверить домен»; не обещает автоматического исправления неизвестной ошибки. Скрыть SSH/API/branch/SHA из обычной карточки в подробности. Имена региона/ноды не обязаны быть UK.

### 4.5 Экран ноды

```text
Нода uk-1 · управляется основой
Ядро: запущено
AmneziaWG: не готов · нет материала профиля
AnyTLS: готовность не подтверждена
Последнее применение: не выполнено · этап «протоколы»
Пользователи: 11 · доступных локальных профилей: 0
Основа: адрес · последняя команда: время

[1] Подробности и журнал
[2] Обновить сведения
[0] Выход
```

Без локальных mutations. Если данных нет — «неизвестно», не «работает». Показ applied generation, actual revision и время в подробностях. Не писать «основа подключена» только по сохранённому base URL, не писать «подписки опубликованы» только по локальному export.

## 5. Пакеты работ и критерии приёмки

### R1 · P0 · Исправить preparation и восстановление damaged state (F01/F02/F09)

Владельцы: nodes/reconcile.py, contracts/node_snapshot.py, канонические protocol owners, при необходимости узкий ProtocolService порт подготовки. Не прямые вызовы private helper из TUI и не бесконечный новый реестр исключений.

- [ ] RED: прежний AWG state с mode=3.1, без profiles/с invalid paddings; VLESS owner metadata пропадает после merge.
- [ ] Подготовка публичного desired → effective node config, с сохранением необходимых secrets и idempotent repair.
- [ ] GREEN: true AWG/VLESS preparation + routing/client export; повтор 3 раза не меняет исправные ключи/short IDs.
- [ ] Все заявленные node protocols проверены либо временно помечены недоступными для добавления с конкретной причиной.
- [ ] Failure before/after material preparation восстанавливает state и owned host artifacts, не cookies.

### R2 · P0 · Подтвердить профили до объявления готовности (F03/F11/F18)

Владельцы: nodes/reconcile.py, nodes/reconciler.py, node_export contract, snapshot_store.py, subscriptions/node_exports.py.

- [ ] RED: empty/malformed artifact при eligible UUID; отсутствующий snapshot file; mismatched UUID/generation; повреждённая нода рядом с рабочей.
- [ ] Coverage validation с reason per missing artifact и форматной capability; immutable storage и pointer остаются атомарными.
- [ ] GET настоящей subscription для UUID содержит expected node profiles в поддерживаемых base64/Sing-box/Throne/HydraBox форматах; endpoint адрес принадлежит ноде, SNI/keys соответствуют effective config.
- [ ] Независимый сбой ноды не рушит локальные профили и последнюю валидную публикацию.

### R3 · P1 · Наблюдаемость и автоматический reconciliation (F04–F07/F17)

Владельцы: NodeManager, sync_cycle/sync_ports, control transport, новый injected observation store и typed operation contracts.

- [ ] RED: last result пропадает при закрытии TUI; failed outcome теряется; unchanged неправомерно используется как health.
- [ ] Persist observations отдельно от desired; report every operation stage with redaction.
- [ ] Offline rename/desired edit сохраняются и показывают pending, после возвращения связи автоматически применяются.
- [ ] Один offline/slow node не блокирует local quota цикл и остальные node jobs; bounded retry/backoff; fake-clock tests.
- [ ] Секреты/полные client configs не входят в публичную диагностику.

### R4 · P1 · Resume установки и завершение upgrade (F08/F10)

Владельцы: NodeManager, bootstrap/provision/installer, upgrade scheduler, наблюдение операций.

- [ ] RED: provisioning прерван после install/identity/register/apply; restart основы; update scheduled, но завершился rollback.
- [ ] Resume доходит до публикации без reinstall, без обхода pinning/identity и без удаления VPS.
- [ ] Actual revision readback отличен от desired target; terminal upgrade outcome и rollback отображаются.
- [ ] SSH credentials не в argv/log/state; destructive cleanup всегда отдельно подтверждается.

### R5 · P1/P2 · Пересобрать UX двух TUI (F12–F16)

Владельцы: nodes.py, node_emergency.py, nodes_setup.py, node_protocol_fields.py, existing protocol-label helper.

- [ ] RED render/interaction tests для пустых display_name, 80×24 и narrow terminal, unknown/stale/offline/apply failed/zero profiles/upgrade pending.
- [ ] Обычный экран не требует понимания generation/digest/SHA и не показывает все служебные операции равноправно.
- [ ] Conditional protocol fields, единая отмена, явный reset optional fields, targeted editing и before/after summary.
- [ ] Safe preflight до remote mutation: pure config conflicts; relevant domain probe с правильной семантикой; предупреждение об инвалидировании старых ссылок.
- [ ] Errors видимы до следующего clear, сохранилась цифровая навигация и read-only политика ноды.

### R6 · Release gate · Linux двухсторонний сценарий и migration

- [ ] Изолированная основа + нода: AWG 3.1, AnyTLS, VLESS Reality, реальные host/runtime owners, controlled TLS/DNS fixture.
- [ ] New install и upgrade fixture старого повреждённого state заканчиваются подтверждённым export и GET subscription с профилями.
- [ ] Offline → base user block/reset/edit → online recovery; counters не удваиваются, прежние epochs не возвращают usage.
- [ ] Failures на install/provision/apply/export/store/pointer/save/upgrade rollback не теряют последний рабочий snapshot/доступ к host.
- [ ] Node TUI не изменяет state/host. API не принимает неверную identity/contract/pinning. Concurrent reads не выдают mixed generations.
- [ ] CI явно содержит node-e2e job. Локальные compileall/Ruff/targeted tests, architecture guards и verify.py проходят; docs/NODES.md/CLI/reference/changelog согласованы с поведением.
- [ ] Финальная read-only проверка реальной установки: actual base/node revision, last outcome, listeners, UUID coverage, local published snapshot, subscription HTTP response. Отдельный согласованный runtime smoke, не автоматическое изменение рабочей VPS.

## 6. Очерёдность и запрет ложного завершения

Сначала R1+R2: не делать красивый интерфейс поверх отсутствующих профилей. Затем R3, R4, R5. R6 — обязательный gate, часть сценариев должна начинаться уже в R1/R2. Каждый пакет — отдельный проверяемый diff; никаких коммитов «всё исправлено» по mocks и общей Linux smoke.

Работа принята только когда восстановленная нода сама публикует требуемые профили, пользователь видит проверенное состояние без обязательного ручного check/force refresh, и деградация/ошибка имеет понятный путь восстановления. Полная проверка не заявляется, если node-e2e или фактическая подписка не проверены.
