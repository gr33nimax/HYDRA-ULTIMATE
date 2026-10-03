# Новые управляемые ноды HYDRA — implementation plan

> **Для исполнителей:** выполнять этот план по задачам с RED/GREEN regression checks. План и инженерные решения подготовлены основной сессией. Luna-агенты реализуют назначенные компоненты, не перепроектируют продукт и не запускают других агентов. Нужные навыки: test-driven-development, verification-before-completion; для исполнения — executing-plans.

**Goal:** с существующей основы установить лёгкую ноду, добавить рабочие конфигурации всем пользователям в прежние подписки, управлять нодами через честный TUI и создавать одноимённые двухсерверные каскады.

**Architecture:** новая подсистема `managed_nodes` вместо старой `nodes`. Основа владеет desired state; нода применяет его через bounded mTLS API. SSH используется только для bootstrap/rescue/uninstall. Прямые и каскадные профили выдаются из защищённого подтверждённого локального store без сетевых обращений из subscription GET.

**Tech Stack:** Python 3.10–3.13, существующие ApplicationService/HostBackend/state storage/ConfigurationApplier, cryptography и stdlib ssl/http/socket, systemd/nftables на изолированном Linux. Не добавлять orchestration framework или новые зависимости без доказанной необходимости.

**Spec:** `docs/superpowers/specs/2026-10-01-managed-nodes-v2-design.md`.

## Global Constraints

- Новая реализация нод; никаких old-node API, aliases, adapters, migration или fallback.
- Сохранить основной движок, пользователей, действующие URL/секреты подписок и остальные протоколы основы.
- SSH/22 — установка и восстановление; HTTPS — отдельный ручной или случайный один раз сохранённый порт.
- main/dev выбирается до протоколов; показанная ревизия фиксируется на всю установку.
- До подтверждения не менять host; обнаруженная HYDRA переустанавливается только после согласия, CLI uninstall и подтверждения удаления.
- Опрос/плановая синхронизация через существующий пятиминутный Sync Agent, без второго timer.
- TUI: HH:mm; `Пользователи n/N`; `SUB : ✅SYNC`, `SUB : ⏳WAIT`, `SUB : ❌ERROR`; без «контакт/публикация/проверено N назад».
- Только двухсерверные каскады одноимённых протоколов; выбор нескольких протоколов создаёт отдельные профили, название редактируется.
- Нет silent direct fallback на первом hop; транзит не удваивает quota usage.
- Пароли не сохранять; host effects через HostBackend; desired writes только save_state/update_state; no process-global dependencies.
- Production module ≤500 строк, method/function ≤160; более строгие доменные guards сохраняются.
- Не исполнять bootstrap.sh/upgrade.sh/updater.sh локально, не запускать root/systemd/nftables/SSH на рабочей VPS.
- Никаких commits/push и запуска дополнительных агентов. Windows green не является доказательством Linux onboarding.

## Review Focus

1. Timeout после удалённого побочного эффекта: повтор сначала выясняет operation result, не запускает второй install/apply/uninstall.
2. Одинаковые 24/24 с другими UUID/flags: пользовательская сверка не даёт ложный SYNC.
3. Отказ control при рабочем transport: Offline управления не превращается в выдуманную остановку ядра.
4. Отказ выхода каскада: исходящий адрес не меняется на первый hop, прямые профили продолжают работать.
5. Прежний dirty diff и старые записи nodes: ни то ни другое не принимается за подтверждённые новые операции и не уничтожает данные основы.

---

## 0. исходная точка и последовательность владельцев

Проверенный HEAD перед остановленными воркерами: `b8db71a`, ветка `dev`.
Tracked tree содержит ~100 KiB незавершённых прежних исправлений. Перед подготовкой
плана основная сессия сохранила их, не меняя source:

- patch: `C:/Users/user/AppData/Local/Temp/hydra-node-v2-before-2ku6ornu/tracked.patch`;
- SHA-256: `9c615e1e02434b104337cce9a8c964b4cf1431091a9afaae353f3ae7e5da08f3`;
- рядом `status.txt`; patch не включает untracked файлы.

Не выполнять git reset/restore/stash всего tree. Предыдущие node-правки разрешено
заменять новым кодом только в назначенных файлах; не выдавать их за выполненные пункты.
Не трогать VLESS-документы от 2026-09-29 и untracked `nul`.

**Три исполнительных агента, все `openai-codex/gpt-6-luna:max`, последовательно в одном cwd:**

1. Installation/management/contracts owner — задачи 1–3.
2. Apply/sync/diagnostics/subscriptions owner — задачи 4–6.
3. Cascades/TUI/integration owner — задачи 7–9.

Последовательность намеренная: нет writer races, worktree требует чистой исходной точки,
а компонент 2 зависит от типов/agent компонента 1. Следующий writer запускается только
после verified handoff предыдущего. У первого writer нет права менять TUI/cascade logic;
у второго нет права менять transport API самовольно; третий получает integration ownership
общих seam-файлов только после завершения первых двух. Parent проверяет каждый handoff.

Handoff каждого владельца: actual changed/deleted files, public signatures/JSON examples,
добавленные tests, команды с exit/output, оставшиеся blockers, отсутствие secrets и
незапущенные Linux проверки. Отчёт сохраняется через runtime output binding, не scratch в repo.

## 1. новый state и контракты — владелец 1

**Создать:**
- `hydra/contracts/managed_node_models.py`: чистые network/operation DTO, validation и документная сериализация.
- `hydra/core/state_managed_nodes.py`: typed desired namespace и semantic validators без imports из services/plugins.
- `hydra/services/managed_nodes/records.py`: desired/operation access через injected state_reader/state_updater.
- `tests/test_managed_node_contracts.py`, `tests/test_managed_node_records.py`.

**Общие seam-файлы:** `hydra/core/state_models.py`, `state_validation.py`, `state_format.py`.

Текущая схема — **State Format v1**, `STATE_FORMAT_VERSION=1`, SCHEMA_VERSION alias;
в `state_format.py` уже есть сохранение неизвестных `feature_extensions`. Использовать
новое пространство `feature_extensions['managed_nodes']` с собственной `version=1`:
`definitions`, `cascades`, `operations`. Это не смена envelope; глобальную version
не повышать без фактической смены envelope. Validation нового namespace обязателен.
Если реализация действительно меняет глобальную schema — отдельное согласованное
обоснование, +1 и настоящая последовательная migration с fixture и upgrade checks.

Убрать старый typed AppState.nodes/NodeConfig и активное чтение старого feature `nodes`.
Не переносить прежние NodeConfig в новые definitions. Старые неизвестные namespaces
могут остаться нетронутыми в сохранённом документе/backup по общему unknown-preservation
правилу, но новый node subsystem их не интерпретирует и не выдаёт их профили. Это архивные
байты, не legacy API. Общие users/core/feature поля при read/save round-trip не меняются.

Минимальные DTO/поля, общий vocabulary для всех владельцев:

```python
# hydra/contracts/managed_node_models.py; dataclasses + explicit validators
# Никаких imports core.User: contracts описывает чистую проекцию.
NodeDefinition(id, name, address, ssh_user, ssh_port, branch, revision,
               control_port, protocols, identity_ref)
ProtocolAssignment(name, parameters)
UserAssignment(uuid, email, blocked, expiry_date, traffic_limit_gb,
               disabled_protocols, reset_epoch)
NodeDesired(node_id, revision, users, protocols, cascades)
Operation(id, kind, target_id, desired_digest, state, completed_steps, error, receipt)
ApplyReceipt(operation_id, desired_revision, desired_digest, runtime_id,
             users_digest, profiles_digest)
CheckResult(kind, target_id, outcome, checked_at, duration_ms, stage, reason)
# outcome: ok / error / unknown / not_applicable
CascadeDefinition(id, name, entry_id, exit_id, protocols)
InstallPlan(definition, existing_installation, steps, warnings)
TrafficSample(node_id, runtime_id, samples)
# Each traffic sample: uuid, context_id, kind(direct/cascade_entry/transit/probe),
# reset_epoch, counter_epoch, used_bytes. Only validated business usage is credited.
NodeSample(node_id, receipt, runtime, users_applied, users_digest, metrics, traffic)
ConfirmedProfiles(node_id, receipt, profiles, sha256)
# Each profile: stable_id, user_uuid, protocol, route_id, links, client_configs.
NodeView(definition, management_check, users_applied, users_total, sub_state,
         runtime, protocol_checks, metrics, operation)
DiagnosticReport(management, runtime, users, subscription, protocols)
SyncReport(nodes, local, errors, pending_operations)
ProtocolOption(name, supported, reason)
```

Эти классы — dataclasses с явными `to_document/from_document/validate`, не positional
словари и не dynamic field access. Observation fields допускают None для неизвестного.
`Operation.receipt` — ApplyReceipt или None; `NodeDesired.users_digest` — вычисляемое
свойство canonical hash всех UserAssignment, включая blocked/expiry/reset_epoch.
`DiagnosticReport.protocols[name]` содержит независимые configuration/connection
CheckResult; `SyncReport.nodes[id]` содержит подтверждённый users_digest и outcome.
Installation/profiles wire не включает внутренние host handles или ApplicationService.
Тестовые snippets ниже используют strict fake host/remote и real-storage fixtures,
которые их владелец создаёт в соответствующем test-файле; это не общая permissive Mock.

`revision` desired — монотонная node-assignment revision, не source SHA; source SHA —
`NodeDefinition.revision`. Digest считает canonical serialised projection, не секретные
поля или volatile metrics. `runtime_id` связывает квитанцию с действительно проверенным
применением, не простой записью desired в файл.

Operation state: pending/running/succeeded/failed/recovery_required. Это operation lifecycle,
не health. Unknown result после разрыва транспорта требует reconciliation/receipt lookup.
SSH password, PEM private keys и probe credentials в DTO desired/operations не входят.

- [ ] Написать RED: invalid IP/port/duplicate IDs/control chars, password-like keys,
      same op ID + different digest, unsupported namespace version.
- [ ] Написать RED: round-trip основной state с users/subscription/network/unknown fields
      сохраняет их; populated старый `nodes` не создаёт новых definitions.
- [ ] Реализовать explicit validation, canonical digest и records через update_state.
- [ ] Проверить:

```python
# test_managed_node_records.py; helper делает реальный storage в tmp_path
before = main_state_with_users_and_subscription()
store.update_definition(new_definition('DE-1'))
after = store.read_main_state()
assert after.users == before.users
assert after.network == before.network
assert after.revision > before.revision
assert store.list_definitions()[0].id == 'DE-1'
```

Команда: `python -m pytest -q tests/test_managed_node_contracts.py tests/test_managed_node_records.py`.

## 2. ограниченный agent/HTTPS — владелец 1

**Создать:**
- `hydra/services/managed_nodes/transport.py`, `client.py`, `identity.py`;
- `hydra/services/managed_nodes/agent.py`: dispatch injected local operations, не бизнес-apply;
- `hydra/entrypoints/managed_node.py`;
- `tests/test_managed_node_transport.py`, `tests/test_managed_node_identity.py`.

**Заменить deploy wiring:** `deploy/hydra-node-control.service`, node-specific sections
`bootstrap.sh`, `upgrade.sh`; общие install/upgrade guarantees не переписывать.
Имя systemd unit не является обещанием совместимости старого wire API.

Новый API `/v1` (старые paths не обслуживаются):

- GET `/v1/state`: consistent локальный status sample; management identity, apply receipt,
  runtime/process facts, user digest/count, resources, traffic sample; без export secrets.
- POST `/v1/apply`: validated operation ID + desired DTO; bounded acceptance/result,
  длительная работа не удерживает request handler/health lock.
- GET `/v1/operations/{id}`: durable конкретный результат операции.
- GET `/v1/profiles`: только pinned основа, protected персональные конфигурации с receipt.

Принять raw socket, проверить IP, выполнить bounded TLS вне accept-loop, pinned client
fingerprint и корректный server identity. Reject incompatible version/identity/invalid JSON,
transfer-encoding, excessive body, invalid path/id. Limiting включает TLS/HTTP/client requests,
а не только объявленные constants. Клиент имеет общий deadline с elapsed budget на фазы.

Клиентские signatures:

```python
client.state(deadline: float) -> NodeSample
client.submit(operation_id: str, desired: NodeDesired, deadline: float) -> Operation
client.operation(operation_id: str, deadline: float) -> Operation
client.profiles(deadline: float) -> ConfirmedProfiles
```

Deadline — absolute monotonic deadline. Public error содержит kind/stage/reason с redact;
TCP/TLS/HTTP timeout не превращаются в одинаковый безымянный TimeoutError.

- [ ] RED с реальным loopback mTLS (`tests/node_mtls.py`): pinned peer accepted,
      wrong cert/identity rejected, plaintext rejected.
- [ ] RED: idle raw TCP не мешает второму `/v1/state`; partial HTTP body ограничен;
      request saturation не создаёт unlimited threads; shutdown освобождает ресурсы.
- [ ] Реализовать transport/client/agent dispatch и inject status/apply providers.
- [ ] GREEN и concurrent apply/status test без unrestricted mock-service methods.

Команда: `python -m pytest -q tests/test_managed_node_transport.py tests/test_managed_node_identity.py`.

## 3. установка/resume/удаление — владелец 1

**Создать:** `hydra/services/managed_nodes/installation.py`, `ssh.py`, `enrollment.py`,
`removal.py`, `credentials.py`, `operations.py`; при необходимости разделить чистые
validation/command-generation helpers в короткие тематические файлы.
**Общие seams:** `hydra/bootstrap.py`, `hydra/services/application.py`, node-role selection
в `main.py`/`hydra/ui/tui.py`, existing uninstall service/CLI registry.
**Тесты:** `tests/test_managed_node_enrollment.py`, `test_managed_node_removal.py`,
`test_managed_node_application_boundary.py`.

Не копировать старую services/nodes целиком. Реализовать installation command generation
через HostBackend, pinned known_hosts, scope-limited password askpass до explicit close.
Non-root: sudo запускает конкретный исполняемый entrypoint, не `sudo cd`; получать PUBLIC
certificate через ограниченный privileged read, не ослаблять root private-key directory.

До first effect сохранить enrollment plan. `plan` resolves explicit branch/source SHA,
выбирает port, проверяет prerequisites и возвращает предупреждение existing install.
`install` требует подтверждение; existing install требует отдельное reinstall consent.
Удаление через документированный CLI `hydra uninstall --yes` без `--keep-data`, проверить
реальный return/result и host-owned remnants. Не предполагать несуществующий `--full`.
CLI unavailable/uninstall failure останавливает цепочку. Password не переносить в receipt.

Новые ApplicationService node operations (операционный порт, не новый global service):

```python
nodes.plan(request, ssh_auth) -> InstallPlan
nodes.install(plan, ssh_auth, confirmed, reinstall_confirmed, progress) -> Operation
nodes.resume(operation_id, ssh_auth, progress) -> Operation
nodes.list() -> list[NodeView]
nodes.remove(node_id, confirmed, progress) -> Operation
# Владелец 2 добавляет sync/check, владелец 3 protocol/cascade editing.
```

Специализация службы node-role не создаёт второй подписочный сервер, не пытается
поднять протоколы основы и не получает root-infrastructure напрямую из TUI.
При initial installation удостоверение управления и rescue-access проверяются, а не
отмечаются ready по выходу bootstrap. После setup нужен handoff к apply owner 2.

- [ ] RED: idle > askpass interval, второй password request succeeds, close terminates.
- [ ] RED: existing/no consent -> zero mutations; consent -> uninstall→confirm→install;
      uninstall failure -> install call отсутствует.
- [ ] RED: process restart после каждого completed step; resume не запускает install заново.
- [ ] RED: non-root argv и certificate read, passwords absent in argv/state/log.
- [ ] RED: offline remove -> no local record deletion; remote success/local conflict ->
      resume completes local part без второго удалённого uninstall.
- [ ] Реализовать operation journal и scoped cleanup, сохранить причину каждого failure.
- [ ] GREEN с настоящим ApplicationService boundary, не permissive Mock.

```python
result = service.remove('DE-1', confirmed=True, progress=events.append)
assert result.state != 'succeeded'  # strict fake remote is offline
assert records.find_definition('DE-1') is not None
assert remote.uninstall_calls == 0
```

Команда: `python -m pytest -q tests/test_managed_node_enrollment.py tests/test_managed_node_removal.py tests/test_managed_node_application_boundary.py`.
Handoff 1 обязателен до запуска владельца 2: typed contracts, new API loopback proofs,
records/install/resume/remove fixtures и working production wiring для status transport.

## 4. node-side apply и подтверждённые профили — владелец 2

**Создать:** `hydra/services/managed_nodes/apply.py`, `runtime.py`, `profiles.py`, `profile_store.py`.
**Общие seams:** ConfigurationApplier/user/plugin lifecycle paths только для durable
node transaction integration; existing plugin APIs переиспользуются, не обходятся.
**Тесты:** `test_managed_node_apply.py`, `test_managed_node_profiles.py`.

Node application consumes NodeDesired, создаёт локальный материал штатными transport
owners, применяет полный user/protocol projection с preservation node-local secrets.
Snapshot и durable pending marker до первого сохранения/побочного эффекта. Confirmation
после реального apply/health/export; одинаковый persisted desired не означает runtime success.
Смена port учитывается наравне с параметрами протокола. Нельзя подавить revision conflict.

GET profiles содержит только проверенное соответствие receipt/digest/user UUID, immutable
bundle и protected storage pointer. Pointer меняется атомарно после validation, digest,
coverage и сохранения. Previous confirmed profiles остаются при apply/export failure.
Empty legitimate user set допускается без выдуманного failure из-за отсутствия клиентов.
Technical probe account отдельно от business-user count/exports/quotas.

- [ ] RED: port-only change invokes real apply owner.
- [ ] RED: crash после desired users save до runtime apply; restart/retry не даёт receipt
      без apply; same operation id successful -> no duplicate mutation.
- [ ] RED: failure до/после эффекта, rollback priority/owner, original + rollback errors visible.
- [ ] RED: same count/different UUID or blocked/expiry params -> digest mismatch.
- [ ] RED: malformed export/path traversal/symlinks/hash mismatch -> no pointer switch.
- [ ] GREEN для no-users, blocked/deleted users, expiry и direct profiles supported formats.

```python
pending = app.simulate_crash_after_user_save(desired)  # failure injection seam
restarted = application_from_persisted_state()
result = restarted.apply_operation(pending.id)
assert result.state == 'succeeded'
assert restarted.runtime_apply_count >= 1
assert result.receipt.users_digest == desired.users_digest
```

Команда: `python -m pytest -q tests/test_managed_node_apply.py tests/test_managed_node_profiles.py`.

## 5. пятиминутный sync и traffic — владелец 2

**Создать:** `hydra/services/managed_nodes/sync.py`, `accounting.py`, `observations.py`.
**Modify:** `hydra/services/sync_agent.py`, `sync_cycle.py`, `sync_ports.py`,
`traffic.py`, `traffic_accounting.py`, `admin_infrastructure.py`, `hydra/bootstrap.py`.
**Тесты:** `test_managed_node_sync.py`, `test_managed_node_accounting.py`.

Убрать old node_accounting wrapper/reconcile finally duplicate contacts. Один coordinator:
local accounting → node samples → quota recompute → latest desired delivery → receipt/profiles
→ checks. Per-node failures агрегируются, не маскируются local success. Общий sync результат
отличает local failures и node failures. Таймер основы остаётся пятиминутным.

Traffic representation carries node/runtime counter epoch/user reset epoch/context kind.
Quota sums business direct + cascade entry; transit/probe samples не добавляют business usage.
Основные локальные счётчики не считаются импортированным remote contribution второй раз.
После node removal уже начисленные байты сохраняются. Offline не списывает известное usage.

```python
nodes.sync(node_id: str | None, progress) -> SyncReport
# None только global sync; concrete ID не вызывает maintenance/all-node update.
# SyncReport: per-node outcomes, local outcome, errors, pending operations.
```

Per-node op locking across processes; timed-out running apply interrogated через operation ID.
No state lock across network. Small bounded concurrent pool for independent nodes; no overlap
on same node. Manual pending signal не запускает duplicate global sync.

- [ ] RED: node traffic causes block, latest assignment in SAME cycle carries blocked=True.
- [ ] RED: duplicate/reordered samples/reset/restart -> no double credit.
- [ ] RED: node down/local ok -> report partial failure; next nodes still processed.
- [ ] RED: targeted DE-1 doesn't contact UK-2 or trigger certificates/update maintenance.
- [ ] RED: node remote runtime behind/mismatched receipt -> reapply/recovery, not unchanged.
- [ ] GREEN and stable public JSON errors in existing CLI sync paths.

```python
report = service.sync('DE-1', progress=events.append)
assert remote.calls_by_node == {'DE-1': remote.calls_by_node['DE-1']}
assert main_maintenance.calls == []
assert report.nodes['DE-1'].users_digest == expected_latest.users_digest
```

Команда: `python -m pytest -q tests/test_managed_node_sync.py tests/test_managed_node_accounting.py`.

## 6. реальные diagnostics и subscriptions — владелец 2

**Создать:** `hydra/services/managed_nodes/checks.py`, `probe_clients.py`, `status.py`.
**Rewrite seams:** `hydra/services/subscriptions/node_exports.py` -> confirmed new profile
reader (можно переименовать в `managed_profiles.py`, убрать старые imports),
`client_configs.py`, `links.py`, `singbox_config.py`, `hydrabox.py`, `server.py`.
**Тесты:** `test_managed_node_checks.py`, `test_managed_node_subscriptions.py`.

```python
nodes.check(node_id: str, deep: bool, progress) -> DiagnosticReport
# Management, runtime, user sync, SUB, per-protocol client checks independent.
# Client engine reused later by cascades; no caller claims installed==connected.
probe_client(profile, credential_ref, deadline) -> CheckResult
```

Каждый source собран via ApplicationService monitoring/runtime/plugin_queries, не TUI shell.
CPU из counter deltas; не задерживать state request sleep-измерением. Missing values None,
не 0. Uptime VPS vs service separate; wire samples coherent with runtime marker.
Online/Offline относится к management result. Failure management => local checks unknown,
независимые real protocol probes могут работать. Два пропущенных пяти-минутных цикла =>
no data, не ложный Offline. Checked_at измеряется основой.

Probes запускают настоящих compatible clients с protected technical credentials,
small expected response, isolated local listeners, no production default-route changes.
RealAnyTLS/RealVLESS clients choose installed existing engines after checking capabilities;
unsupported transports show not checked, никогда simulated success. Failed target-control
probe yields unknown path result, а не fleet-wide failures. Certificate checks по mode:
TCP/UDP/TLS/Reality не заменяют друг друга.

Profiles merge сохраняет main links, ordering/names/user overrides и личные ограничения.
SUB confirmed independently of current transport availability. Token/public HTTP endpoints
используются без secrets-in-log. Ordinary GET no sockets to nodes.

- [ ] RED: runtime on/config missing -> protocol local check error, Online remains true.
- [ ] RED: same count wrong users -> not SYNC; failed export leaves previous confirmed.
- [ ] RED: HTTP target down -> transport unknown, not all-node Offline.
- [ ] RED: fake process/port alone can't set real client check success.
- [ ] RED: subscription GET accepts direct/new-node profiles, deleted/blocked user rejected,
      no secrets in diagnostics and no remote calls.
- [ ] GREEN loopback real client tests where local engines available; Linux CI proof mandatory.

```python
report = checks.evaluate(sample=runtime_running_without_anytls_inbound())
assert report.management.outcome == 'ok'
assert report.protocols['anytls'].configuration.outcome == 'error'
assert report.protocols['anytls'].connection.outcome != 'ok'
```

Команда: `python -m pytest -q tests/test_managed_node_checks.py tests/test_managed_node_subscriptions.py`.
Handoff 2: applied snapshot+profiles full direct path, stable sync/check interface and per-context
accounting semantics. Отдельно указать каждый protocol real-client verified/not executable.

## 7. одноимённые каскады — владелец 3

**Создать:** `hydra/services/managed_nodes/cascades.py`, `cascade_runtime.py`, `cascade_profiles.py`.
**Modify:** plugin client/config generation canonical owners (`anytls/plugin.py`,
`vless_xhttp/client.py`, `vless_xhttp/plugin.py`) и core route plan owner при доказанной
необходимости; не добавлять host effects в plugins/бизнес-операции в UI.
**Тесты:** `test_managed_node_cascades.py`, `test_managed_node_cascade_accounting.py`.

Два разных participants, same protocol + validated compatible mode. Entry = per-cascade
inbound/context; egress = same-protocol outbound на exit с отдельным transit identity.
Exit direct-egress transit context не проходит через cascading default-route первого/второго
узла. Client auth on entry maps business user; node-to-node credentials защищены, не global
unrestricted service principal, нужны scoped per-route/user authorization и enforce block/expiry.

Protocol capability table вычисляется из действительно реализованных same-protocol
client/server/runtime/probe возможностей. VLESS/AnyTLS required targets; AWG/others не
появляются selectable без реализации. Нельзя закончить фичу пустой capability table.
Прямые endpoints/keys при создании каскада не меняются. Base participant использует тот же
ConfigurationApplier с route-specific snapshot, не remote bootstrap на собственной VPS.

```python
nodes.cascade_options(entry_id, exit_id) -> list[ProtocolOption]
nodes.save_cascade(definition, confirmed, progress) -> Operation
nodes.rename_cascade(cascade_id, name) -> None
nodes.remove_cascade(cascade_id, confirmed, progress) -> Operation
# entry/exit ID reserved 'base' for the main host; new-node IDs cannot equal 'base'.
```

Создание durable multi-participant operation: prepare snapshots → apply both → real path
check → confirmed profile switch. Partial failure rollback/recovery каждого participant,
не distributed atomicity promise. Rename only subscription labels, no key turnover.
Removal of participant lists cascade consequences before confirmation; pending cleanup
of peer context can't become completed node-removal success.

- [ ] RED: same participant/>2 hops/mixed protocols rejected before mutations.
- [ ] RED: base→DE-1, UK-2→DE-1, DE-1→base compile correct entry/outbound/direct exit.
- [ ] RED: route isolation allows A→B and B→A without transit loop.
- [ ] RED: exit failure no fallback through entry; direct profile not changed.
- [ ] RED: route rename preserves transport materials and only updates names.
- [ ] RED: exact observed entry bytes charged once, exit transit excluded, direct exit-user
      bytes still charged; duplicate sample/restart/reset scenarios.
- [ ] GREEN using real client end-to-end fixtures in Linux isolation.

```python
usage = account([entry_usage(user='u', bytes=100), transit_usage(user='u', bytes=100)])
assert usage['u'] == 100
assert direct_profile_digest_before == direct_profile_digest_after
```

Команда: `python -m pytest -q tests/test_managed_node_cascades.py tests/test_managed_node_cascade_accounting.py`.

## 8. TUI и чистка старого node subsystem — владелец 3

**Rewrite:** `hydra/ui/_menus/nodes.py`, `nodes_setup.py`, `node_details.py`,
`node_emergency.py`, `node_protocol_fields.py`, `node_removal.py`; разделить длинные
controllers на маленькие новые тематические modules вместо compressed lines.
**Создать:** `hydra/ui/_menus/node_cascades.py`, `node_diagnostics.py` и pure presentation helpers.
**Тесты:** `test_managed_node_tui.py`, `test_managed_node_wizard.py`, `test_managed_node_role.py`.

Numeric stable navigation, all actions ApplicationService. Setup form ID/IP/account/password,
branch before protocol forms, management-port selection, confirm plan. Strict typed service
boundary tests with real app/records; no permissive MagicMock masking absent methods.
Progress events have step started/succeeded/failed/skipped, cached old failure never hides new.
Exit/Enter keeps report/error until user navigates. No added secret fields in ordinary forms.

Card user n/N, SUB, exact HH:mm, metadata labels via protocol_label. Tables/control glyphs
don't claim online data fresh when old. Resources per VPS, traffic source label. Card targeted
sync, diagnostics per report source. Cascades custom name/protocol multiselect and direct
profile preservation. Node emergency read-only: no user edits/independent config state.

Delete old active services/nodes package and old contracts/node_{snapshot,export,traffic,validation},
core/state_nodes, core/node_identity and old entrypoint node_{control,provision,cookies}/ssh_askpass
once new owners replace their genuine responsibilities. No compatibility exports or modules
that silently dispatch to old logic. Cookie-requiring transports use dedicated new protected
installation input/import validation if offered; не скрывать их unsupported requirements.
Удаление старых public node-only commands allowed by explicit owner no-legacy decision;
main CLI/ApplicationService/public non-node symbols remain stable.

Old tests targeting removed node DTOs/UI/contracts заменяются новыми tests с таблицей
переноса проверяемого требования. Не сохранять fake backwards compatibility ради oldtest.
Не удалять/ослаблять тесты с ещё действующими security/state/host/architecture guarantees.
Old-only removal/withdraw/detach fixtures retired именно как отвергнутый product contract;
остальные failures исправляются в реализации. Обоснование приложить к handoff.

- [ ] RED: wizard input order, port/branch preservation, cancel->no mutation, existing
      reinstall exact consent, failure visibility, resume after restarting UI.
- [ ] RED: clock -> HH:mm, empty plugin display_name falls back, real users digest mismatch
      doesn't paint SYNC, stale check no fake Offline.
- [ ] RED: offline remove record retained; same menu action IDs regardless status.
- [ ] RED: cascade labels/editing, unavailable protocol not offered, error stage preserved.
- [ ] GREEN then scan imports/references for removed modules and node-only CLI dead paths.

```python
text = render_node(view(checked_at='2026-10-01T22:34:00', users_applied=24, users_total=24))
assert '22:34' in text
assert 'Пользователи 24/24' in text
assert 'SUB : ✅SYNC' in text
assert 'контакт' not in text and 'публикация' not in text and 'назад' not in time_label(text)
```

Команда: `python -m pytest -q tests/test_managed_node_tui.py tests/test_managed_node_wizard.py tests/test_managed_node_role.py`.

## 9. интеграция, документация, gates — владелец 3 и parent

Владелец 3 получает integration ownership только после остановки writers 1/2.
Свести bootstrap/application/subscription/sync bindings к новым production services,
без old-node fallback. Исправить boundary wiring самим, не перенести решение на reviewer.

**Docs:** полностью заменить obsolete node sections `docs/NODES.md`; обновить
`docs/CLI.md`, `docs/REFERENCE.md`, `docs/ARCHITECTURE.md`, README/CHANGELOG по реальному
реализованному поведению. Поддержанные cascade/probe возможности перечислить явно.
Ничего не обещать за неподтверждённые реальные Linux проверки.

**CI:** новые изолированные Linux integration scripts под `.github/scripts/` и node job
в `.github/workflows/integration.yml`. Раздельные environment setup и test actions:
real SSH/password/non-root deploy, arbitrary/manual control-port firewall path, real
clients direct/cascades, node restart/failure injections/uninstall without host collateral.
Не запускать эти scripts на Windows/local working host и не трогать пользовательские VPS.
CI должен доказать, что subscription profile именно тот, которым пользуется test client.

Перед окончательным handoff:

```bash
python -m pytest -q tests/test_managed_node_*.py
python -m pytest -q tests/test_architecture_graph.py tests/test_architecture_audit.py tests/test_architecture_size_limits.py
python -m ruff check main.py hydra tests
python -m compileall -q main.py hydra
python verify.py
git diff --check
```

Glob first command requires shell expansion; при Windows cmd выполнить явный список новых
test files или `python -m pytest -q tests -k managed_node`, подтвердив выбранное число tests.
Не использовать -k как финальный полный suite gate. Каждый failure имеет классификацию:
implementation defect / explicitly changed old-node contract / environment limitation.
Обход skip/assertion/architecture budgets без решения владельца запрещён.

Parent после handoff проверяет фактический diff, meaningful tests, hidden global effects,
removed legacy imports, source sizes и новые docs; повторяет ключевые runnable checks.
Не добавляет четвёртого LLM-reviewer в бюджет трёх agents без разрешения.

### итоговые критерии

- [ ] Рабочий direct node path + unchanged main subscriptions/users.
- [ ] SSH install/reinstall/resume/removal и bounded pinned HTTPS с настоящими failure proofs.
- [ ] Honest HH:mm/Online/Offline/warnings/n/N/SUB и пятиминутная auto sync.
- [ ] Independent real runtime/client diagnostics; no fake supported-protocol success.
- [ ] Same-protocol two-hop cascades всех трёх направлений с именами и single-count quotas.
- [ ] Нет живых legacy node paths и старых DTO exports; общие security/state guards сохранены.
- [ ] Документация соответствует фактическому состоянию; Linux evidence или явный blocker.
- [ ] Не выполнены VPS операции/commits/push; нет unrelated diff/секретов/generated repo artifacts.

Письменный план ожидает проверки владельца. Начало реализации — отдельный следующий шаг;
остановленные старые воркеры не возобновляются автоматически.
