# Режим нод: повторный аудит и целевая модель управления

Статус: архитектурный проект для рассмотрения, не реализован.
База кода: `dev`, `d70fd4af7821c40a70aad8ef59b4adc227927df2`.
Дата: 2026-09-30 UTC. Аудит не разрешает изменения рабочей VPS.

**Уточнение владельца:** операторские сценарии/карта TUI и cadence определены
[`node-tui-implementation-spec.md`](2026-09-30-node-tui-implementation-spec.md).
Они имеют приоритет над прежними макетами этого проекта: постоянные 1–5,
полный sync по существующему таймеру раз в 5 минут, изменяемый видимый (не technical) ID,
withdraw с очисткой users/protocols и сохранением управления, detach без очистки.
Подтверждённые code findings ниже остаются аудитом, а не реализацией этих требований.

## 1. Что исправляет этот проект

Запрос владельца: режим нод воспринимается как обрезанный, сырой и архитектурно
непроработанный; AWG 3.1 отсутствует в HydraBox, в Throne два неработающих AWG-профиля;
управление на основе и диагностика на ноде не объясняют результат действий.

Проверка владельца: «anytls и vless + xhttp есть, авг 3.1 нет».
Она не заменяется противоположным выводом из лабораторной fixture.

Цель — не новый набор кнопок. Оператор задаёт серверу конфигурацию и получает
подтверждённый результат до выбранного клиентского формата либо точный незавершённый
этап. Нода сохраняет самостоятельную работу при потере основы. Подписка основы
остаётся единственной; её URL и UUID пользователей не меняются.

Предыдущие утверждения о готовности были чрезмерными:
- наличие AWG endpoint в локальном экспорте не доказывает обновление опубликованного снимка;
- слово `amnezia` в JSON не доказывает импорт/подключение клиента;
- отсутствие AnyTLS в E2E ничего не говорит о живой подписке: fixture включает лишь AWG и VLESS;
- два пункта AWG в клиенте нельзя заранее назвать дублями: сначала нужны host, port и variant каждого;
- отсутствие ошибки в `/health` не доказывает рабочий runtime.

## 2. Метод и пределы аудита

Исходники прочитаны по критическому пути: NodeManager, обе стороны reconciliation,
transport/client, upgrade scheduler, onboarding, export contract/store, подписочные
рендереры, TUI основы/ноды, текущие тесты и прежний дизайн.

Локальный граф предшествует реализации нод и не используется как доказательство её поведения.
Сверены `hydra/__init__.py`: версия `3.0.0`, `state_format.py`: схема state `1`,
wire contract `5`. Это разные оси версионирования.

Удалённый пробник выполняет только чтение через pinned SSH и mTLS GET health,
diagnostics, export. Рендер использует сам handler `_subscription` и JWE
encrypt/decrypt, но НЕ вызывает `do_GET`: публичный GET регистрирует устройство и
может записывать состояние. Пробник не вызывает check/refresh/apply/save/update,
не записывает экспорт и не изменяет host. В отчёт не включаются пароли, UUID/URL
подписки, приватные ключи, полные ссылки, cookies или payload с credentials.

В локальном соседнем репозитории HydraBox прочитан импортёр и fetcher
(`7634a32` на момент просмотра). Это reference-код, а не доказательство версии,
установленной у владельца. Клиентские версии, входной формат, ошибки импорта и
UDP-подключение должны быть проверены отдельно. Для Throne источник каждого
профиля и совместимость его импортёра нельзя заменить подсчётом ссылок.

### Свежая диагностика

Новых удалённых результатов пока нет. Два запуска пробника завершились до SSH:
сначала синтаксическая ошибка локального скрипта, затем отсутствие PI_SESSION_FILE
в окружении background runner. Исторические gen=8 и даты снимка — гипотеза для
повторной проверки, не свежий вывод аудита.

## 3. Подтверждённые конструктивные дефекты

| ID | Приоритет | Доказательство | Следствие |
|---|---|---|---|
| A01 | P0 | `nodes/reconciler.py:56,88`: unchanged возвращается до client health/export; desired digest включает пользователей/протоколы, но не producer/exporter version | Новое ПО не вызывает новый экспорт при неизменных настройках. Старый артефакт может пережить исправление экспортёра |
| A02 | P0 | `reconciler.py:189`: coverage считает наличие protocol у пользователя, не артефакт по клиентскому формату | AWG с одними ссылками считается покрытым, хотя HB нужен endpoint; нельзя говорить «все профили опубликованы» |
| A03 | P1 | `manager.py::update` и `upgrade.py` завершают запрос на scheduled; unchanged не читает installed revision | Не замкнут lifecycle «обновить → убедиться в версии → проверить runtime → перепубликовать». На экране бесконечно запланировано |
| A04 | P1 | `observation.py::record_sync` вызывает succeeded и обновляет checked_at даже при unchanged; `record_current_apply_error` глотает сбой diagnostics | Свежая запись об успешной сверке не обязательно является свежим успешным наблюдением связи |
| A05 | P1 | `nodes.py::_node_summary` возвращает «готова» по одному published pointer даже для offline/apply failure | Список и карточка противоречат друг другу; зелёный — не readiness |
| A06 | P1 | `NodeControlClient` оборачивает remote rejection в NodeControlError; `describe_failure` относит любой такой тип к connect | Отказ apply/export легко называется проблемой связи; реальные причины размываются |
| A07 | P1 | `_node_custom_documents` пропускает AWG document, если у профиля есть links; Throne берёт общий мешок wg/vpn/sn | Есть коллекция представлений, но нет политики одного подходящего артефакта для конкретного клиента |
| A08 | P1 | `amneziawg/client_links.py::export_capabilities`: wg/vpn ready для 3.1, другие импортеры unverified; HB gate основан на ядре сервера | Поддержка экспорта, импортёра клиента и клиентского ядра смешаны. Серверная версия не доказывает клиентскую |
| A09 | P1 | `ProtocolService.singbox_client_config` принимает profile, но не передаёт его владельцу; AWG hook рендерит все profiles при каждом вызове | При desktop+mobile документ может повториться в нескольких logical profiles; однопрофильная fixture этот случай не ловит |
| A10 | P1 | `NodeReconciler.apply`: равная generation сразу already_applied без проверки digest тела; export не использует apply lock | Idempotence не привязана к точному запросу; согласованность чтения с текущим host apply требует отдельной защиты |
| A11 | P1 | `NodeManager.change_protocol` и TUI сначала требуют check; NodeField в UI содержит ограниченный отдельный словарь | Desired-настройки нельзя готовить офлайн; поверхность удалённого управления не эквивалентна поддержке плагина |
| A12 | P2 | Emergency `_runtime_lines` печатает display_name без fallback, только enabled/running; ошибка спрятана во второй экран | Нет ответа, какой снимок применён, когда была основа, готов ли конкретный профиль и что восстановить |
| A13 | P1 | `reconciler.py` unchanged не читает local snapshot; reader молча исключает плохую ноду, callbacks из рендереров не подключены | Повреждённая публикация не восстанавливается обычной сверкой и её отсутствие плохо видно |
| A14 | P2 | HB profile ID хеширует runtime tag; node reader сначала переименовывает tag под display name | Переименование способно изменить profile identity и потерять клиентский выбор, хотя endpoint не менялся |
| A15 | P1 | Installer не имеет durable операции/checkpoints до регистрации; wizard предлагает resume по generic RuntimeError | Восстановление зависит от того, какой шаг предположит оператор, а не от установленного состояния операции |

Это подтверждение кодом, НЕ утверждение, что все дефекты одновременно воспроизведены
на данной паре. A10 (generation/payload) и A14 (rename/identity) дополнительно
воспроизведены локально; конкурентное чтение A10 и multiprofile A09 ещё требуют
специальных regression/failure-injection tests.

### Локальный read-only эксперимент

При одинаковом desired digest и published gen=8 вызов reconciler.refresh:
`status=unchanged`, вызовов client factory=0, installed_revision='', проверок
snapshot store=0. Сохранённый published pointer даёт list label «готова · поколение 8»
как при offline, так и при apply failure. Remote apply rejection типа NodeControlError
классифицируется как `(connect, control_unavailable)`.

Дополнительные воспроизведения на существующем коде:
- изменение node profile name меняет HB profile ID (`True`);
- apply same gen=8 с другим набором пользователей → already_applied=True,
  локальный набор пользователей остался прежним;
- AWG31 profile с одной URI и без документов → coverage={amneziawg:1}, warnings=[],
  хотя документов для HB ровно ноль.

### Пока не доказано

- почему именно установленный Throne считает оба профиля кривыми;
- какие HB URL/format, версия приложения/ядра и отказ импортёра используются владельцем;
- успешный UDP handshake/передача трафика AWG с реального клиента;
- точный host rollback при каждом failure point многопротокольного apply;
- сквозной SSH install/update/uninstall двух VPS в изолированной integration;
- согласованность export/traffic во время host apply и рестарта;
- задержки нескольких offline/slow nodes и их влияние на локальные лимиты.

## 4. Архитектурное решение

### 4.1 Сохранить хорошую основу, заменить модель завершения

Сохраняются: desired state основы, автономный runtime ноды, plugin ownership,
полные снимки, pinned SSH только для bootstrap/recovery/cleanup, mTLS обычного
управления, transactional apply и локальный immutable publication store.
Не вводятся брокер сообщений, очередь дельт, общий registry, произвольный remote shell,
новый writer пользователей на ноде или сетевые вызовы из GET подписки.

Альтернативы:
1. Только дорисовать TUI — дешевле, но показаний о завершении всё ещё нет; отвергнуто.
2. Reconciliation по intent + operation receipts + artifact catalogue — выбранный путь;
   переиспользует существующих владельцев и исправляет end-to-end контракт.
3. Полная перепись в отдельный распределённый scheduler/broker — неоправданный риск и стоимость.

### 4.2 Владение и три вида состояния

**Intent (основа, AppState):** node ID, SSH/control locator и доверие, отображение,
публичные настройки протоколов, ветка/immutable software target, политика публикации,
проекция разрешённых пользователей. Только изменение намерения повышает desired revision.

**Applied receipt (нода, долговечный локальный commit):** exact generation+desired digest,
результат host-транзакции, software/core revision, material revision, exporter revision.
Это доказательство применения и основа idempotence, не зелёная runtime-лампочка.
Локальные ключи/материал остаются у протоколов. Серверные private keys и cookies не экспортируются.
Клиентские private credentials AWG неизбежно нужны подписке; они передаются по UUID и
хранятся только в защищённом export store, не в публичном статусе или отчётах.

**Observed/operations (отдельные stores):** последний реальный contact, reachability,
readiness, pending/running/failed operation, installed revision, timestamps, retry.
Они не являются desired state. Durable operation outcome нужен для восстановления
после рестарта; потеря диагностической проекции не отменяет committed applied receipt.

**Published artifact bundle (основа):** immutable материал с manifest и hash,
связан с receipt и producer/exporter/material revisions. Legacy publication pointer
в NodeConfig сохраняется на переходе. Не переносить сразу все поля state в новый store
и не ломать прежний rollback runtime.

### 4.3 Четыре независимых вопроса вместо одного health

1. Связь: ответила ли конкретная нода по доверенному каналу, когда?
2. Применение: совпадают ли receipt и текущее намерение; прошёл ли host apply?
3. Публикация: цел ли локальный bundle; свеж ли он для подтверждённых producer/material?
4. Клиентские форматы: какой artifact доступен данному UUID и конкретному клиенту/версии?

`ready` не означает, что каждый телефон уже импортировал и подключился.
Статусы «артефакт подготовлен», «совместимость проверена на клиенте X версии Y» и
«сейчас работает UDP/данный пользователь подключён» различаются.

## 5. Цикл сходимости

```text
сохранён intent
  → observer: contact + installed/core capabilities + receipt
  → planner: отличия intent / applied / published
  → node operation: preflight → prepare → transactional apply → readiness → commit receipt
  → export для committed receipt
  → validate UUID + logical profile + artifact + client coverage
  → atomic store bundle → publication pointer
  → outcome для оператора
```

Независимо вычисляются:
- нужно применить новое намерение;
- нужно экспортировать заново (ПО/материал/exporter изменился, нет bundle, hash неверен);
- нужно только показать свежие наблюдения.

Равный desired digest не является ранним выходом из всего цикла.
Export refresh после update НЕ должен заново ротировать ключи или переустанавливать
протокол. Изменение target до реального cutover не означает изменение producer.
Нельзя «починить» это одним включением target SHA в desired digest: оно может заставить
старое ПО экспортироваться до обновления и опять оставить старый bundle.

Idempotence: равный generation+digest возвращает committed receipt; равный generation
с другим digest отвергается. Одновременные apply/update сериализуются на ноде;
export читает committed snapshot/receipt, не промежуточные host side effects.
Если ответ потерян, основа узнаёт operation/receipt по ID, а не запускает вслепую ещё один apply.

Readiness ноды проверяет требуемые runtime объекты/порты через существующие владельцы.
Это не полный внешний клиентский handshake. При rollback failure исходная ошибка
сохраняется вместе с отдельным фактом неполного rollback.

### 5.1 Долгие операции

После подтверждения UI получает стабильный operation ID и быстро возвращается к
наблюдаемому результату. Фазы: queued, running, succeeded, failed, rolled_back,
interrupted/unknown. Deadline UI/HTTP не считается отменой host-транзакции.
После рестарта worker восстанавливает или выясняет outcome; не повторяет побочный эффект
из-за того, что operator потерял терминал.

Single-flight на ноду; apply и upgrade взаимно исключаются. Одна медленная нода не
удерживает глобальную блокировку всех нод и локального accounting. Health, apply и
artifact export имеют отдельные deadlines. Предлагаемые начальные цели: health 3s,
observe 30s, stale после 90s; это параметры калибровки для isolated integration,
не измеренные свойства текущих VPS. Host operation имеет свой bounded deadline,
согласованный с installer/ACME/updater, и сохраняет outcome независимо от HTTP.

### 5.2 Обновление — операция, а не кнопка systemd-run

```text
цель подтверждена → worker запланирован → выполняется/cutover
  → установленная версия подтверждена → runtime проверен
  → свежие артефакты опубликованы → завершено
```

Если installed target уже совпадает, не запускать updater повторно; проверить readiness
и export freshness. Публикация старого bundle сохраняется при неудачном обновлении;
если после cutover изменилась доступность артефактов — показать degraded, не успех.
Нужны отдельные результаты «ПО обновлено, публикация не завершена» и «откат на прежнюю версию».

## 6. Профиль и его клиентские представления

Logical identity: `(node_id, user_uuid, protocol, variant_id)`.
Название — атрибут, а не identity/tag. Два разных сервера не объединять по похожему имени.
Desktop/mobile — реальные варианты только при отдельном server material; wg/vpn/JSON —
представления одного варианта, а не три независимых VPN-сервера.

Для logical profile каталог несёт typed artifacts: WireGuard INI, wg URI,
Amnezia vpn container, sing-box document/entrypoint. Каждый имеет artifact revision,
список required client/core features, verified compatibility либо bounded reason.
Протокол создаёт материал и проверяет его смысл; subscription adapter выбирает
представление для клиента. Generic layer не восстанавливает AWG31 поля из lossy URI.

**HydraBox:** exact WireGuard endpoint с `amnezia` и обеими 3.1 boolean fields,
корректный resource/entrypoint/permission. JWE не теряет полей; sequence возрастает
при реальной смене публикуемого содержимого, не на каждом health poll.
Required feature/version опирается на клиентское ядро, не только на ядро VPS.

**Throne:** ровно одно проверенное представление на logical endpoint. Если wg importer
данной версии сохраняет все поля 3.1 — wg; если не сохраняет, выбирать full-config
только после проверки реального импортёра/core. Непроверенное представление не
выдавать как рабочее и не незаметно понижать 3.1 до 2.0. Official `vpn://` — для
Amnezia, не автоматический сосед `wg://` в Throne. Generic base64 не задаёт
универсальную политику для всех клиентов.

Codec tests проверяют key bytes и generation fields после decode/import, а не число URI.
`+`, `/`, `=`, percent encoding, IPv6, range fields и отсутствующее optional material
входят в fixtures. Стандартный form decoder и URL decoder имеют разные правила для `+`;
их нельзя путать или на этом основании без проверки обвинять конкретный Throne.

Покрытие: число logical profiles для **выбранного пользователя и клиента**, число
обслуживаемых пользователей отдельно. Нельзя назвать «30 профилей» сумму трёх протоколов
для десяти пользователей, когда у одного пользователя три выбора, а в HB только два.

Стабильные resource/profile IDs не меняются от переименования. Имена включают сервер,
человеческое название протокола и существенный variant; версия AWG видна явно.

## 7. Полноценное управление жизненным циклом

| Действие | Завершение | Без связи |
|---|---|---|
| Добавить чистую VPS | verified SSH → enrolled identity → compatible inventory → applied → published | Не начинать host changes |
| Продолжить подключение | восстановить конкретный checkpoint без reinstall/ротации здорового material | Сохранить план восстановления |
| Изменить публичную настройку | validated intent сохранён → отдельное применено/ожидает | Сохранить намерение, честно pending |
| Включить протокол | preflight/runtime/profile coverage подтверждены | pending, не обещать новые профили |
| Выключить протокол | применение подтверждено, publication согласована | показывать задержанный отзыв доступа |
| Переименовать | local display update с сохранением identity | Работает сразу |
| Обновить | installed + readiness + new artifact bundle | Pending до связи, не фоновой успех |
| Проверить/повторить | observation либо retry конкретной failed operation | Точный bounded failure |
| Убрать из выдачи | локальная publication policy отключена | Старые credentials на VPS продолжают работать |
| Удалить с очисткой | identity-checked pinned SSH cleanup → local record/credentials removed | Не заявлять cleanup |
| Отсоединить | удалена только local binding; объяснён оставшийся remote runtime | Трафик остаётся учтённым |

Протокольная конфигурация должна иметь один schema/validation owner в плагине,
используемый локальным и remote UI. Read-only capabilities/inventory ноды говорят,
какие режимы действительно применимы. Наличие subscription capability у локального
плагина основы не равнозначно поддержке удалённой нодой.

Операции с локальными секретами (VK cookies) — отдельные явно выбранные pinned SSH
сценарии. Не копировать cookies основы, не выдавать import за activation/pool recreate.
Ротация материала, смена домена и подобные действия, инвалидирующие подписанные профили,
обязаны показывать impact/подтверждение и обновлять publication в том же workflow.

## 8. Офлайн, пользователи и квоты

Одна authority пользователей/desired — основа. Нода сама исполняет последний committed
snapshot и известные срок/локальную политику доступа. Новый пользователь не получает
несуществующие node credentials, пока не применён. Offline base не выключает ноду.

Общая квота остаётся eventual: local + absolute node reports по UUID/reset epoch,
без повторного начисления после retry/restart. В интерфейсе — измеренный итог и
свежесть недоступных contributors, не обещание строгого распределённого лимита.
Блокировка/выключение без связи не отзывает немедленно уже скопированные ключи.
Удаление ноды не списывает начисленный трафик. Политика fail-closed lease для офлайна
в этот переход не добавляется: она противоречит выбранной offline continuity.

## 9. TUI как сценарии, не как список низкоуровневых вызовов

Чистый service-level status report объединяет факты и next action; UI отвечает за
русский текст/цвет/ширину. CLI, TUI и Telegram получают одну семантику операции через
ApplicationService. Не класть общий state machine в UI и не выдумывать отсутствующие факты.

### Основа: список и карточка

```text
СЕРВЕРЫ
[1] Добавить сервер
[2] UK · работает частично · HydraBox 2/3
    AWG 3.1: опубликованный документ устарел
[3] FI · нет связи · используются последние профили
[0] Назад
```

```text
UK
Связь: доступна · проверена 12 секунд назад
Настройки: применены
Подписки: HydraBox 2/3 · Throne требует проверки
Обновление: ПО обновлено, профили ещё не обновлены
Причина: экспорт подготовлен прежней версией

[1] Повторить подготовку профилей
[2] Протоколы и параметры
[3] Профили в подписке
[4] Обновление и операции
[5] Диагностика
[6] Опасные действия
[0] Назад
```

Это макет проблемного состояния, не свежие числа VPS. Главное действие следует за
доказанной причиной; неизвестная ошибка ведёт в диагностику, не «исправить всё».
Обычный workflow не требует кнопки «force refresh». «Повторить» повторяет этап
операции, а не ещё одну переустановку. `0` всегда назад/отмена без side effects;
Enter оставляет значение, optional reset задаётся отдельно.

Экран профилей: выбрать пользователя и клиент → увидеть logical profiles,
имена серверов, версия AWG, доступность, причина исключения; нужный формат выдаётся
отдельно, без dump credentials в общей диагностике. Отдельный protocol screen:
включить/выключить, изменить одно поле, preflight, impact, применить, readiness.

### Нода: диагностика, а не второй control plane

```text
НОДА UK · управляется основой
ПО: версия … · управление доступно
Основа: последний контакт …
Настройки: последний успешный снимок …
AmneziaWG 3.1: runtime готов · 10 пользователей
AnyTLS: runtime готов
VLESS + XHTTP: runtime готов
Последняя операция: обновление завершено / ошибка с причиной
Публикация на основе: неизвестна (без отдельного подтверждения)

[1] Проверить локальное состояние
[2] Последняя операция и ошибки
[3] Порты и зависимости
[0] Выход
```

Read-only сохраняется. Нода не обещает «я в подписке», не предоставляет локальные
бизнес-изменения пользователей. Сломанная identity не запускает обычное admin menu;
восстановление pin/control identity — отдельный ограниченный SSH recovery workflow.
Никаких пустых display_name; fallback через общий protocol_label.

## 10. Совместимость и переход

«Wire» здесь означает JSON-контракт обмена основы и ноды, не схему state.json.
NODE_CONTRACT_VERSION=5 находится в contracts/node_validation.py и появился уже
в первом опубликованном node-mode commit df97a8c. История публичного перехода
1→2→3→4→5 в git отсутствует; цифра не доказывает пять миграций.
State SCHEMA_VERSION/STATE_FORMAT_VERSION сейчас равна 1.

Требование владельца: не плодить версии схем. Базовый переход сохраняет контракт 5
и state format 1. Не добавлять собственный schema counter каждому operation,
observation, manifest или client artifact. Producer SHA, digest содержимого и
поколение применения — факты для сверки, а не новые версии схем.

Текущий контракт 5 строго отвергает неизвестные поля. Сначала использовать
существующие поля/расширения и совместимые defaults; strict validation не ослаблять.
Если для пакета требуется несовместимое изменение формы/семантики — остановиться,
описать конкретную причину и отдельно согласовать переход, не повышать версию
автоматически. Нельзя переименовать используемую 5 в 1 или молча дописать к ней поля.
Legacy snapshots не объявляются новыми. Compatibility matrix и rollback smoke обязательны.

Для отдельно согласованной смены persisted schema остаются обязательными
SCHEMA_VERSION строго +1, чистая идемпотентная миграция и fixture. Само добавление
диагностического metadata или операции не является поводом вводить новую схему.

Требуемые client representations и атомарная publication policy внедряются до
массового расширения меню. Старые credentials, snapshots, URL, личные overrides и
счётчики сохраняются. Cutover нового ПО не считается автоматически rotation keys.

## 11. Приёмка архитектуры

1. Update без изменений desired приводит к подтверждённой installed revision и
   свежим артефактам, не требует ручного force; повтор не ротирует ключи.
2. HB/JWE: AWG31 endpoint, оба flags, верный entrypoint и стабильный ID; реальный
   импорт той же fixture через конкретную версию HB/core. AnyTLS и VLESS не теряются.
3. Throne: по одному выбранному representation каждого фактического endpoint,
   полный decode/импорт AWG31 без потери fields; разные серверы не дедуплицируются.
4. Полный acceptance включает UDP handshake/трафик клиента; без клиента это явно не проверено.
5. Offline и failed apply никогда не называются «готова» по старому pointer.
6. Snapshot missing/corrupt автоматически восстанавливается безопасно, не ослабляя hash проверки.
7. Long operation переживает HTTP timeout и restart; известен outcome/rollback/retry.
8. Same generation+different digest отвергается; concurrent apply/update/export дают coherent committed data.
9. Переименование не меняет profile identity, выбранный клиентом сервер или его ключи.
10. Partial onboarding продолжается без reinstall; remove/detach различаются и не теряют квоту.
11. Экран на ноде остаётся read-only; UI/CLI/Telegram не обходят ApplicationService/HostBackend.
12. Windows unit и opt-in mTLS E2E отдельно от Linux two-host/SSH/host-failure acceptance.

## 12. Решения, которые нельзя принять молча

Нужна фиксация реальных версий HB/Throne и client core, а также используемой HB ссылки:
зашифрованная Hydra subscription и обычная share-link subscription — разные входы.
Не публиковать секретный URL в отчёт. Выяснить это по версии/безопасному журналу,
а не просить переслать весь конфиг с приватными ключами.

Этот проект сохраняет текущий read-only режим ноды и offline continuity.
Если владелец хочет независимое локальное редактирование ноды или строгие офлайн-квоты,
это отдельное изменение authority/политики, не скрытый пункт косметического TUI.

План перехода: `../plans/2026-09-30-node-mode-v2-remediation.md`.
