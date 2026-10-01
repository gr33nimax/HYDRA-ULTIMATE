# Режим нод v2: план перехода к рабочему управлению

> **For agentic workers:** реализация только после рассмотрения архитектурного проекта.
> Для последовательного исполнения использовать `executing-plans`; делегирование
> требует отдельного разрешения владельца. Ниже — пакеты с независимой приёмкой,
> не разрешение начинать host-операции.

**Goal:** оператор получает один проверенный клиентский профиль каждого фактического
endpoint и понятный завершённый результат установки/настройки/обновления ноды.

**Architecture:** сохранить один authority на основе, plugin-owned preparation и
автономный runtime ноды. Разделить intent, applied receipt, наблюдения/операции и
публикуемые артефакты. Reconciler проверяет свежесть экспорта независимо от изменения
настроек; UI читает service report, не объявляет scheduling или API health готовностью.

**Tech Stack:** существующий Python 3.10–3.13, ApplicationService, HostBackend,
atomic protected files, pinned SSH/mTLS, systemd transactional updater, pytest.
Без нового broker, БД, UI framework и глобального registry.

**Spec:** `../specs/2026-09-30-node-mode-v2-audit-and-design.md`.
**Baseline:** `d70fd4a`; этот план и дизайн пока не реализованы.

**Актуальный операторский сценарий:**
[`node-tui-implementation-spec.md`](../specs/2026-09-30-node-tui-implementation-spec.md).
Установка IP/user/password/ID/name → отдельные protocol menus → plan/consent/log/report;
постоянные 1–5; existing пятиминутный sync; display ID без смены technical identity;
три режима удаления, включая withdraw с remote purge. Эта карта/семантика заменяет
старые UI proposals M3, которые нельзя исполнять буквально.

## Global Constraints

- Рабочие VPS не изменять в аудите; host acceptance только в разрешённой изолированной среде.
- Не терять UUID, URL подписки, ключи, личные имена, начисленный трафик и прежний rollback.
- State только через save/update с revision conflict; секреты не в argv/логах/публичном status.
- GET подписки не общается с нодами; обычный просмотр TUI не выполняет host mutation.
- Нода read-only для оператора, один authority пользователей/desired на основе.
- Offline continuity и eventual quota не заменять строгим fail-closed lease без решения владельца.
- Production modules ≤500 строк, функции проектировать ≤100, учитывать более строгие guards.
- По требованию владельца не плодить версии схем: базовый план сохраняет
  contract_version=5 и state format=1. Не вводить отдельный version counter для
  каждой операции, observation, manifest или профиля.
- Сначала использовать существующие поля/расширения и совместимые defaults;
  strict validation не ослаблять. Если пакет требует реальной несовместимости,
  остановиться и отдельно согласовать переход. Для согласованной смены state
  остаются обязательными +1, миграция и fixture.
- Тесты/expected values/архитектурные guards не ослаблять для зелёного результата.
- `HYDRA_NODE_E2E=1` — opt-in; обычный unit suite не открывает сокеты.

## Review Focus

1. Нода обновилась, desired прежний: свежий документ должен попасть в публикацию без ручной сверки.
2. AWG desktop+mobile или основа+нода: не спутать endpoint identity с разными URI одного endpoint.
3. Сбой после remote apply, до publication pointer: старый bundle остаётся, retry не повторяет ключи.
4. Потерянный HTTP ответ/рестарт/rollback: known operation outcome не заменяется ложным success.
5. Реальный client importer/core может отвергнуть то, что Python сериализовал успешно.
6. Персональные overrides/disable/UUID scopes и quota/reset не должны ухудшиться от изменения каталога.

## Порядок: сначала замкнуть результат, потом расширять управление

### M0. Заморозить факты и воспроизводимую матрицу

**Files:** диагностические материалы вне git (`.pi/`); новый audit/design;
`tests/test_node_e2e.py`, `tests/test_node_subscriptions.py` — только при начале реализации.

- [ ] Записать текущие installed revisions основы/ноды, applied/published generation,
  producer старого bundle и формы AWG-артефактов без credentials.
- [ ] Уточнить версии HydraBox, Throne и их cores; определить HB input type без вывода URL/key.
- [ ] Сопоставить каждый AWG-пункт клиента с `(server, port, variant)`, а не назвать его дублем по имени.
- [ ] Подготовить санитизированные fixtures прежнего и свежего экспорта с детерминированными тестовыми ключами.
- [ ] Не включать лабораторные prints/ложный anytls assertion в production regression.
  E2E fixture должна действительно содержать AnyTLS перед проверкой его сохранения.

**Gate:** есть before fixtures и точный статус каждой границы. Неизвестные версии/handshake
отмечены как acceptance blockers, не зафиксированы по догадке.

### M1. Обновление ноды автоматически доводит экспорт до публикации

**Canonical owners:** `hydra/services/nodes/reconciler.py`, `manager.py`, `observation.py`,
`snapshot_store.py`; добавить integrity/producer metadata у immutable bundle без новой версии схемы,
не заполнять NodeConfig observed-полями. Tests: `test_node_sync.py`, `test_node_manager.py`,
новый `test_node_export_lifecycle.py`.

**Consumes:** existing v5 health revision, desired snapshot, legacy generation/pointer.
**Produces:** независимое решение apply-required / export-required / observe-only и
свежий manifest `(generation,digest,producer_revision)` для подтверждённого bundle.

- [ ] RED: одинаковый desired, старый опубликованный links-only AWG, новая installed revision;
  обычный refresh обязан обновить bundle и перестать быть unchanged до readback.
- [ ] RED: identical target, но worker не выполнил cutover; не помечать экспорт новым из-за target SHA.
- [ ] RED: missing/corrupt snapshot при неизменном desired; старый материал не считается целым,
  другая нода/основа сохраняются в подписке, восстановление не ослабляет hash проверки.
- [ ] Убрать глобальный ранний выход до observation/integrity. Не делать network под state lock.
- [ ] Для совместимого v5 перехода новый материал публиковать под новым поколением с
  идемпотентной подготовкой здорового runtime. Не перезаписывать immutable файл текущего
  поколения другим телом. Проверить, что replay не ротирует ключи/не переустанавливает протокол.
- [ ] Сохранить producer manifest только после подтверждённого export/store/pointer;
  отсутствие legacy metadata инициирует безопасную переоценку, а не вечную re-export петлю.
- [ ] Background reconciliation выполняет тот же путь; force остаётся диагностикой, не обязательным шагом.
- [ ] Contact timestamp обновляется только реальным успешным contact. Отказ diagnostics/health
  не превращается в `control=ok` вызовом `succeeded` для локального unchanged.

**Run:** `python -m pytest -q tests/test_node_sync.py tests/test_node_manager.py tests/test_node_export_lifecycle.py`

**Gate:** обновление при прежних настройках → fresh AWG document в реальной HB handler/JWE
проекции; next cycle → unchanged без rotation; broken file восстанавливается; exact installed
revision получена без требования ручного check. Это первая самостоятельная поставка.

### M2. Клиентские профили — каталог, а не общий мешок ссылок

**Canonical owners:** `hydra/contracts/node_export.py`, `node_validation.py`,
`hydra/plugins/amneziawg/client_links.py`, `hydra/services/protocols.py`,
`nodes/reconcile.py`, `subscriptions/node_exports.py`, `links.py`, `client_configs.py`,
`hydrabox.py`, `profile_names.py`.
**Tests:** `test_awg_plugin.py`, `test_awg_endpoint_projection.py`,
`test_node_export.py`, `test_node_subscriptions.py`, `test_hydrabox_subscription.py`,
новый `test_node_client_artifacts.py`, расширенный opt-in E2E.

**Consumes:** logical `(node,user,protocol,variant)` и plugin-owned material.
**Produces:** typed artifact catalogue + client-format coverage + stable resource/profile identity.

- [ ] RED: published AWG URI-only → HB coverage missing, не готовность по protocol name.
- [ ] RED: desktop+mobile: у каждого logical profile ровно собственный endpoint,
  не два целых документа со всеми endpoint в каждом.
- [ ] RED: rename сохраняет resource/profile ID и keys; только display меняется.
- [ ] RED: `+`, `/`, `=`, IPv6, range fields, boolean31 roundtrip сохраняют exact bytes/значения.
- [ ] Проверить, какие metadata/представления совместимы с текущим контрактом 5.
  Если существующего контракта недостаточно — описать конкретную несовместимость
  и согласовать отдельное решение; не включать автоматический bump в этот пакет.
  Не менять strict v5 молча. Mixed-version upgrade и downgrade smoke обязательны.
- [ ] Один transport owner сообщает variants, typed representations и required features.
  Invoker не игнорирует variant, рендерер не восстанавливает секреты из URI.
- [ ] Throne выбирает одно доказанное representation на logical endpoint; Amnezia vpn
  не добавляется рядом как второй сервер. Два разных endpoint остаются разными серверами.
- [ ] HB получает exact endpoint31, resource/entrypoint/permission, оба booleans и
  client/core requirements. Отказ клиента не называется «нет связи с нодой».
- [ ] Проверить публикацию old/unsupported client mode с точной причиной, без silent downgrade31.
- [ ] E2E содержит настоящие AWG31 + AnyTLS + VLESS и проверяет конечные артефакты,
  а не подстроку `amnezia` или count `://`.

**Run:** узкие указанные export/subscription/AWG tests; opt-in
`set HYDRA_NODE_E2E=1&& python -m pytest -q tests/test_node_e2e.py` (Windows cmd);
`HYDRA_NODE_E2E=1 python -m pytest -q tests/test_node_e2e.py` (Linux).

**Gate:** фиксированная версия HB и Throne импортируют нужные endpoint без потери fields;
AWG31 выполняет UDP handshake и передачу трафика в изолированном client↔VPS acceptance.
Если клиент недоступен, маркировка «imported/working» запрещена; renderer-only тест не закрывает gate.

### M3. Истинные состояния и TUI уже на существующих операциях

**Canonical owners:** service-level report/policy в `hydra/services/nodes/`, query port
ApplicationService; UI `nodes.py`, `node_emergency.py`, новый `node_details.py`.
**Tests:** `test_node_observation.py`, `test_nodes_menu.py`, `test_nodes_numeric_navigation.py`,
`test_node_role.py`, новый `test_node_status_report.py`, render fixtures.

**Consumes:** отдельные факты contact / applied / publication integrity / format coverage / software.
**Produces:** единая семантика ready/degraded/offline/unknown/pending + bounded reason + next action;
UI-only русские подписи, цвет и числовая навигация.

- [ ] RED: published pointer + offline → «нет связи, последние профили», не «готова».
- [ ] RED: AWG links ready, HB doc missing → HB 2/3 и точная причина.
- [ ] RED: local unchanged / queued update / failed diagnostics не освежают last actual contact.
- [ ] RED: remote apply отказ виден как apply failure; exception transport не определяет этап домена.
- [ ] Список показывает display ID+имя, IP, healthy/warning и возраст реального опроса;
  карточка имеет постоянные 1 protocols / 2 appearance / 3 full sync / 4 update / 5 delete.
  SHA/generation/API plumbing не входят в основной экран.
- [ ] Пользователь/client scope остаётся в backend artifact policy; не добавлять новый
  обязательный раздел «Профили» или выбор UUID перед обычным управлением нодой.
- [ ] Нода: current software, last committed apply, last base contact, протоколы/порты,
  последняя ошибка сразу; publish на основе неизвестен без подтверждения. Только чтение.
- [ ] Все labels через fallback; `0` назад/отмена без вызовов изменений;
  render при 60/80 колонках, длинные причины безопасно укладываются.

**Run:** узкие указанные menu/observation/role/status tests + архитектурные boundaries.

**Gate:** оператор без «Подробностей» понимает, работает ли сервер, какие профили выдаются
его клиенту, что не завершено и что нажать. UI не делает обещаний без данных.
Ранние макеты в дизайне используют примерные числа, не утверждают результат live-пары.

### M4. Долгие операции и committed receipts

**Canonical owners:** `contracts/node_snapshot.py`, `node_export.py`, `node_validation.py`,
`nodes/control_client.py`, `transport.py`,
`reconcile.py`, `upgrade.py`, `manager.py`; durable operation journal без отдельного schema counter и
existing apply transaction/journal. Tests: `test_node_reconcile.py`, `test_node_upgrade.py`,
`test_node_control_security.py`, новый `test_node_operation_receipts.py`.

**Consumes:** intent + immutable operation ID; negotiated protocol; scoped trust.
**Produces:** durable outcome/phase/receipt, single-flight apply/update, coherent reads.

- [ ] RED: same generation с другим payload digest → reject; exact retry → same receipt.
- [ ] RED: lost response после host commit → status по ID, не второй apply/rotation.
- [ ] RED: restart в queued/running/cutover → восстановленный outcome либо explicit unknown;
  `--collect` не уничтожает единственный факт failure.
- [ ] RED: concurrent update/apply/export → single-flight/coherent committed receipt,
  не смешение прошлой generation с новым material.
- [ ] Структурированный error `(operation,stage,code,message,retryable)` доходит через mTLS,
  persisted observation и TUI; исходная ошибка сохраняется при rollback failure.
- [ ] HTTP scheduling answer быстро возвращает ID; progress query read-only.
  Deadline HTTP не означает отмену worker или завершение runtime.
- [ ] Post-upgrade workflow: actual installed → readiness → fresh catalogue → outcome.
  Already-installed target не запускает updater повторно.
- [ ] Per-node serialization вместо глобального lock всех нод; observer/accounting не
  заблокированы длительной установкой другой ноды. Deadlines/retry — bounded и тестируются fake clock.

**Run:** узкие control/reconcile/upgrade/receipts tests, затем isolated Linux failure injection.

**Gate:** перезапуск/обрыв не теряет результат операции, не повторяет host side effects;
одна slow node не задерживает локальные квоты; фактическая версия и publication
достигают результата без открытого терминала оператора.

### M5. Полная публичная конфигурация у владельца протокола

**Canonical owners:** `hydra/plugins/base.py` и канонические владельцы transports,
config contracts/query; `nodes_setup.py`, `node_protocol_fields.py`,
`NodeManager.change_protocol`, соответствующие ApplicationService ports.
**Tests:** `test_node_protocol_fields.py`, `test_node_protocol_ports.py`,
`test_plugin_purity.py`, protocol-specific happy/failure tests.

- [ ] Inventory ноды сообщает поддерживаемые режимы, prerequisites и client artifacts;
  выбор не строится только по plugin list установленной основы.
- [ ] Публичные schema/defaults/validation/preflight происходят из одного owner,
  не отдельного неполного словаря remote UI. Secrets/material не входят в writable settings.
- [ ] Offline validated intent можно сохранить: UI явно «сохранено, ожидает применения».
  Попытка runtime apply и её result отделены от сохранения.
- [ ] Редактирование одного параметра не запускает заново весь wizard;
  отмена и optional reset однозначны, conditional fields убирают устаревшие значения.
- [ ] DNS/TLS/SNI/UDP conflict preflight проверяется на нужном хосте и по типу поля;
  Reality cover и собственный ACME domain не смешиваются.
- [ ] Изменение, ломающее уже выданные profiles, показывает impact и требует подтверждения;
  owner prepare не ротирует здоровый материал от replay.

**Gate:** локальное/удалённое управление одним поддерживаемым режимом имеет одну семантику,
включая failure/rollback/export; unsupported mode назван, а не просто отсутствует в меню.

### M6. Enrollment, recovery, release acceptance

**Canonical owners:** `nodes/onboarding.py`, `bootstrap.py`, `operations.py`, credentials,
upgrade/uninstall services; docs/NODES.md, UPGRADE.md, ARCHITECTURE.md, CHANGELOG.md;
изолированный Linux integration node scenario.

- [ ] Durable enrollment checkpoint до первого побочного эффекта; restart показывает
  конкретное «продолжить», не generic offer reinstall после любого RuntimeError.
- [ ] Recovery повторно проверяет SSH/control identity и принадлежность установки,
  сохраняет локальные secrets, исправляет только Hydra-owned scope.
- [ ] Read-only emergency остаётся отдельной ролью; missing/corrupt identity не открывает
  обычное меню пользователей на ноде.
- [ ] Uninstall/removal outcome отличен от local detach/withdraw; offline revoke limitation
  и оставшийся remote runtime явно показаны, quota contribution не теряется.
- [ ] Two-host acceptance: fresh install → user → AWG31/AnyTLS/VLESS → client import/traffic
  → update без desired изменений → offline → reconnect → block/reset → cleanup.
- [ ] Fault injection до/после side effect: remote host, save/revision conflict,
  export/store/pointer, upgrade rollback, control trust; проверять и runtime, не только Python state.
- [ ] Проверить mixed versions и previous-runtime rollback, schema migration при необходимости.
- [ ] Удалить устаревшие публичные заявления «публикация = любой клиент увидит профиль»;
  документировать observed/unknown/verified client surface и limitations.

**Gate:** самостоятельный node-specific Linux smoke и клиентская приёмка проходят;
общие integration и 2891 unit не объявляются заменой two-host сценария.

## Проверки каждой поставки

1. Узкий набор изменённой области и regressions before/after.
2. Layer/size guards при изменении owners/imports; Ruff для затронутого production/tests.
3. Opt-in E2E для control/apply/export/publication; test результат отличать от skip.
4. `python verify.py` для законченной существенной поставки, не после каждой строки.
5. CI + Linux integration + отдельные client/two-host gates по риску.
6. Явные git paths; не включать AGENTS.md, `.pi`, посторонние VLESS планы и реальные credentials.

## Как поставлять без очередного «планы когда-нибудь»

M1 — закрывает несходимость update→publication на текущем v5 и имеет самостоятельную проверку.
M2 — закрывает клиентскую поверхность и cardinality, требует реальных версий клиентов.
M3 — даёт первые честные рабочие экраны, опираясь на данные M1/M2.
M4 — меняет lifecycle длинных операций; миграционный риск выделен в отдельную поставку.
M5 — снимает обрезанность protocol management.
M6 — приёмка безопасного обслуживания и recovery всей модели.

Не объединять всё в один большой commit и не объявлять режим готовым после M1.
После принятия этого дизайна каждый этап доводится до своего gate и отдаётся как
самостоятельный проверяемый результат. Календарный срок нельзя честно обещать до
фиксации client versions, доступности изолированной two-host среды и бюджета внедрения.
