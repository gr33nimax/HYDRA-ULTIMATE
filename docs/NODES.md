# Managed nodes v2

HYDRA управляет удалёнными серверами через `ApplicationService.nodes` и namespace
`feature_extensions.managed_nodes`. Текущая модель не использует `AppState.nodes`
или старый mTLS control protocol. Старые node-only API, entrypoints и subsystem
удалены по контракту владельца; старые node records не импортируются и не становятся
новыми definitions. Неизвестные поля state сохраняются общим механизмом round-trip,
но HYDRA их не интерпретирует и не публикует.

## Enrollment и transport

TUI открывается пунктом `9 Ноды`. Мастер запрашивает идентификатор, имя, IP-адрес,
SSH-учётную запись, SSH-порт, параметры протокола и ветку исходного кода. SSH host
key показывается до подтверждения; source branch разрешается в точный commit SHA и
фиксируется в плане установки. Пароль SSH передаётся через одноразовый канал и не
попадает в persisted operation. Установка, удаление и управление credentials идут
через application service и injected SSH/backend owners. После выхода из мастера
экран с результатом или ошибкой остаётся до Enter; меню не очищает его сразу.

Удаление доступно и после незавершённой установки: используется её сохранённый
план с закреплённой SSH identity. Подтверждённое удаление атомарно заменяет
незавершённые install/apply операции; их больше нельзя возобновить. Запись ноды
и credentials сохраняются до подтверждения очистки VPS по SSH. Если установка
не успела создать ресурсы, чистое состояние VPS подтверждается без запуска
отсутствующего uninstall. Повторный выбор «Удалить ноду» продолжает сохранённую
операцию удаления, включая локальную очистку после успешного remote uninstall.

Рабочая management surface — ограниченный mTLS `/v1` agent с закреплённой identity
ноды. Она предоставляет состояние, durable operation lookup, apply и подтверждённые
профили; это не публичная административная панель. Дополнительные typed cascade endpoints
`/v1/cascades/{snapshot,prepare,material,status,apply,rollback,finalize}` принимают только
operation/plan/route/protocol/receiver-bound DTO. Server принимает только закреплённую base
client identity; receiver ID берётся из локального protected identity, не из запроса. Route
seed и transit outbound передаются только по этому каналу и сохраняются как protected
operation-scoped material; произвольные config/path/command RPC не предоставляются.
Локальная роль ноды определяется маркером `/etc/hydra/managed-node/identity.json`; роль
открывает только аварийную read-only диагностику и ограниченный CLI.

## Apply, recovery и sync

Изменение протокола сначала выполняет один state update/CAS, который записывает
новую `NodeDefinition`, неизменяемый `NodeDesired` в frozen operation plan и pending
operation. Только после commit вызывается sync и начинаются сетевые действия. Если
CAS конфликтует или падает, ни новое определение, ни операция не видны. Если процесс
падает после commit, тот же operation ID и payload восстанавливаются из persisted
state; неизвестный результат отправки сверяется через operation endpoint и не
переигрывается вслепую.

Node-side apply сохраняет snapshot до host effects, подтверждает runtime и локально
сохранённые profile bundles до выдачи `ApplyReceipt`; при ошибке использует rollback
и durable recovery state. Обычный Sync Agent использует тот же per-node coordinator
раз в пять минут. Синхронизация конкретного node ID не запускает base-wide maintenance.
Обычный production apply сверяет актуальные persisted cascade-операции до preflight и
держит локального base/node participant вне изменений до освобождения lease; отдельный
participant apply идёт через canonical configuration owner и sealed operation-bound
авторизацию. Participant snapshots и transaction receipts защищены checksummed storage и
остаются до подтверждённого rollback/finalize; неизвестный результат не переигрывается.

Apply proof и учёт трафика используют разные идентификаторы:

- `apply_generation` привязан к process identity и digest наблюдаемой runtime-конфигурации.
  Изменение config инвалидирует старый receipt, даже если PID не изменился.
- `runtime_id` отражает только epoch работающего процесса и служит billing baseline.
  Поэтому config-only change с теми же absolute counters не создаёт повторное списание;
  перезапуск и явный reset сохраняют отдельную учётную семантику.

Управление квотами остаётся ограничено доступностью и достоверностью данных самого
транспорта; строгая мгновенная глобальная квота при разрыве связи не обещается.

## Subscriptions и checks

`ConfirmedProfiles` читаются локально, сверяются с успешной operation receipt и
пользовательской identity. Обычный GET подписки не открывает сетевое соединение к
удалённой ноде. Main users, их локальные профили и URL подписок продолжают идти через
существующие subscription owners; credentials ноды не выдаются в статусе или логах.

Diagnostics разделяют management response, runtime/apply proof, user coverage,
subscription bundle и transport checks. Отсутствующая возможность показывает
`unknown`/`not_applicable`, а не simulated success.

## Ограничения

Production participant runtime теперь подключает локального owner и удалённых участников
через существующий закреплённый mTLS transport; remote nodes не требуют копии base inventory
и не открывают management-доступ друг к другу. Это подтверждает только transaction protocol:
production capability reporting пока намеренно пуст, real installed-engine auth-user
capability и whole-path proof не предоставлены, поэтому двух-hop activation остаётся
недоступна. Final profile publication и единственный cascade billing/accounting owner тоже
не реализованы. Unit/loopback TLS проверки не доказывают реальную маршрутизацию. Нужны
отдельные Linux integration/client tests; локальные Windows unit-тесты их не заменяют. Не
выполняйте setup, installer, systemd или firewall-команды на рабочем VPS ради проверки.

Сопоставление удалённых legacy-тестов и сохранённых гарантий: [legacy retirement map](superpowers/specs/2026-10-01-managed-nodes-v2-legacy-retirement-map.md).
