# ТЗ реализации режима нод: сценарий владельца

Статус: проект для письменного согласования; код по этому ТЗ не реализован.
Исходники: `dev`, `d70fd4a`. Дата: 2026-09-30 UTC.

Этот документ переписан по явному сценарию владельца и заменяет прежнюю редакцию
этого файла и карту `../plans/2026-09-30-node-tui-screens.md`.
Не переносить из старого проекта отдельные разделы «профили пользователя»,
«диагностика», «обслуживание» в основное меню ноды.

Владелец отдельно подтвердил: изменяется **видимый ID**, техническая идентичность
ноды неизменна. Новые версии persisted/wire схем не вводятся: state format=1,
node contract=5. Ниже — изменения поведения и полей расширений, не новые схемы.

## 1. Точный пользовательский сценарий

### Установка

```text
Меню нод
  → 1. Установить
  → Введите IP
  → Введите имя пользователя SSH
  → Введите пароль SSH (скрытый ввод)
  → Введите ID
  → Введите имя ноды
  → Меню протоколов
      → Отдельное меню каждого протокола
      → Настроить / донастроить параметры
      → Вернуться к выбору протоколов
  → Готово
  → Итоговая карточка предполагаемой ноды
  → Подтверждение / Отмена
  → Аккуратный лог процесса установки
  → Отчёт о выполнении
```

Это основной путь. Не спрашивать обязательно region, manual SHA, mTLS port,
профиль пользователя, формат подписки или дополнительный выбор вида установки.
SSH/control ports и канал имеют существующие defaults; изменение нестандартных
параметров доступно из итогового плана, не усложняет обычную установку.

### Уже установленная нода

В списке каждая нода занимает три смысловые строки:

```text
[2] uk-1 · Великобритания
    194.147.35.112
    healthy · проверена 2 минуты назад
```

`healthy` — последний подтверждённый полный цикл исправен. `warning` — есть ошибка,
ожидающее изменение, недостоверные/устаревшие данные либо незавершённая операция.
Это статус сервера/синхронизации, не заявление об импорте на каждом клиенте.

Основной sync agent опрашивает ноды **раз в 5 минут**. Отдельный node daemon/poller
не создаётся. Локальный учёт трафика пользователей не замедляется до пяти минут.

```text
uk-1 · Великобритания
194.147.35.112
warning · причина · время последней проверки

[1] Настройки протоколов
[2] Внешний вид
[3] Синхронизировать
[4] Обновление
[5] Удаление
[0] Назад
```

В сообщении владельца номер 3 использован дважды. В ТЗ сохранён пункт 4 «Обновление»,
а «Удаление» получает 5: у каждого действия один постоянный номер.

### Удаление

```text
[1] Удалить HydraULT Node с VPS
    Полная очистка принадлежащей HYDRA установки
[2] Убрать из подписки
    На ноде удаляются пользователи и протоколы
[3] Отсоединить
    Очистки нет, VPS продолжит работать
[0] Назад
```

Пункт 2 — НЕ просто фильтр ссылок на основе. Пункт 3 обязательно предупреждает
об отсутствии очистки до подтверждения, а не только в конце отчёта.

## 2. Нормативные требования

Номера `N.M` — критерии для тестов/приёмки и пакетов реализации.

### Requirement 1: установка и ввод

1.1. Мастер следует порядку IP → SSH username → password → видимый ID → имя → protocols.
Пароль не отображается, не подставляется default и не сохраняется в локальном draft/state.
1.2. Если поле неверно, система сообщает конкретную причину и повторяет только это поле;
не возвращает в начало и не теряет уже введённые публичные значения.
1.3. Enter оставляет допустимый default, `0` отменяет там, где он зарезервирован;
Ctrl-C отменяет текущий ввод, EOF безопасно завершает мастер без host changes.
1.4. До итогового явного подтверждения нет установки/provisioning/импорта/записи
пользователей на VPS. Read-only lookup software target/trust для плана допустим.
1.5. Готовность HTTPS-подписки основы проверяется до host mutation; ошибка службы/cert,
неверный IP и отказ SSH-авторизации имеют разные объяснения.

### Requirement 2: SSH и безопасность

2.1. Введённый username действительно используется backend на всех SSH-этапах;
его нельзя игнорировать и всегда подставлять root. Root либо подтверждённый
`sudo -n` необходимы для установки; password для sudo не предполагается равным SSH password.
2.2. Password не попадает в argv, command strings, state, environment values,
stdout/stderr logs, journal либо diagnostic report. Секрет передаётся контролируемым
одноразовым auth channel; private credentials доступны только scoped backend.
2.3. SSH host fingerprint проверяется/подтверждается до первой мутации. Уже известный
mismatch блокирует действие; auto trust/new-key replacement запрещены.
2.4. После регистрации routine sync/update идёт по pinned mTLS. Для дальнейшей SSH-очистки
создаётся отдельный управляемый SSH key, защищённый на основе, вне state.json.
Добавление такого доступа указано в плане установки; чужие authorized_keys не меняются.
2.5. При отмене/ошибке auth секретный context закрывается. Durable checkpoint не хранит
password; если ключ ещё не выдан, продолжение снова спрашивает password.

### Requirement 3: отдельные меню протоколов

3.1. Выбор протокола открывает привычное отдельное меню его параметров, максимально
близкое к меню этого протокола на основе. Не запускать одинаковый общий опрос всех полей.
3.2. Общие schema/validation/defaults/presets принадлежат владельцу протокола;
base и node UI не содержат два независимых списка правил. Секретные/local material
пункты основы нельзя слепо перенести в remote public settings.
3.3. В установочном мастере параметры остаются transient draft до итогового согласия;
«Готово» только завершает выбор, не запускает VPS side effects.
3.4. У установленной ноды явное сохранение настроек запускает тот же полный node sync,
что кнопка 3. Нет дополнительной обязательной кнопки force refresh/export.
3.5. Если нода недоступна, validated intent сохраняется с явным отчётом pending;
при связи применяется. Ошибка не выдаётся за успех и не стирает сохранённые настройки.

### Requirement 4: список и статус

4.1. Каждая строка содержит видимый ID + имя, отдельный IP и отдельный статус с age.
На обычном экране нет contract/generation/digest/technical key и суммы чужих профилей.
4.2. Healthy означает подтверждённый успешный полный цикл для текущего intent и
всех требуемых публикаций; controller health alone или старый pointer недостаточны.
Если eligible users нет, публикация не требуется: не создавать fake empty bundle
и не ослаблять обычный nonempty export gate ради этого случая.
4.3. Warning показывает короткую причину: нет связи, изменения ожидают применения,
apply/export failure, incomplete update/cleanup, нет достоверного наблюдения и т. п.
Отсутствие активных пользователей само по себе не считается ошибкой.
4.4. Отсутствующее/испорченное/будущее время не считается свежим. Age относится к
реальному контакту/результату, а не времени открытия меню или локальному unchanged.
4.5. Пока кадр открыт, номер строки привязан к immutable node key/identity. Добавление,
удаление, rename или новый порядок списка не меняют цель набранного номера.

### Requirement 5: единый полный цикл синхронизации

5.1. Таймер каждые 300 секунд, ручная кнопка и protocol save используют одного владельца
node sync. Не дублировать бизнес-операцию отдельно в TUI/CLI/agent.
5.2. Цикл получает runtime/status и absolute traffic, начисляет только новый трафик по
UUID/reset epoch, рассчитывает local/global restrictions, применяет нужные блокировки.
5.3. После учёта ограничений формируется актуальный desired snapshot; нода применяет его,
основа проверяет подтверждение, готовность экспорта и публикует подходящие artifacts.
5.4. Один отчёт не начисляется дважды; restart, повторный manual sync и stale report
не теряют/не удваивают трафик. Удаление ноды не списывает уже начисленное.
5.5. Если intent прежний, но ПО/exporter изменился либо bundle повреждён, цикл
обновляет публикацию. Бездействие по desired digest не означает готовности.
5.6. Сбой одной ноды не прерывает локальный учёт/другие ноды. Сеть выполняется вне
state lock, per-node single-flight объединяет одновременные manual/timer/save requests.

### Requirement 6: внешний вид и ID

6.1. Внешний вид позволяет изменить видимый ID и имя. Это offline local intent,
без host apply, certificate rotation или повторного enrollment.
6.2. Immutable technical key сохраняется во всех certificates/credentials/snapshots,
traffic identities и stable client profile/resource IDs. Видимый ID — не technical key.
6.3. Видимые IDs уникальны среди управляемых нод, валидируются и не содержат control
sequences. Старые ноды без alias показывают существующий ID как fallback.
6.4. Rename/сброс имени не меняет keys/UUID/выбор клиента. Legacy API технического
node_id сохраняется; UI разрешает видимый ID в technical key до вызова port.

### Requirement 7: план, лог и отчёт

7.1. План показывает IP, SSH username, видимый ID, имя, протоколы/существенные параметры,
software target, scope и trust/access изменения; password никогда не показывает.
7.2. Подтверждение числовое `1 Подтвердить / 0 Отмена`, default=0. Смена цели/настроек
после плана требует нового плана. Пустой ввод/Ctrl-C/EOF не являются согласием.
7.3. Лог показывает реальные этапы/сообщения, без raw argv/password/private config,
выдуманных процентов/ETA и прокрутки неограниченного stdout. Данные остаются читаемыми.
7.4. Итоговый отчёт различает установлен/подключён/применён/опубликован и partial outcomes;
не исчезает до перехода. Ошибка содержит этап, безопасную причину и следующий шаг.
7.5. Потерянный ответ после возможного side effect — unknown/readback, не blind retry.
Checkpoint/operation outcome переживает закрытие TUI; rollback failure не скрывает исходную ошибку.

### Requirement 8: три режима удаления

8.1. Remote full removal удаляет только scoped HYDRA program/units/config/data и
managed auth access. Локальная запись удаляется после подтверждённой remote cleanup.
Чужие службы, users, authorized_keys и не принадлежащие HYDRA файлы не удаляются.
8.2. Withdraw снимает публикацию и очищает на ноде пользователей, client credentials,
протоколы и их runtime/material; control identity/управление/установленная HYDRA остаются.
Нода остаётся в меню, чтобы её можно было снова настроить.
8.3. Withdraw — durable intent. Следующий timer/manual sync не возвращает пользователей
и протоколы. Возврат в выдачу только отдельным явным решением после новой настройки.
8.4. Detach удаляет local binding/publication/credentials без remote cleanup. До согласия
экран прямо говорит: «Очистка не происходит. VPS и старые клиенты могут продолжать работать».
8.5. Все три режима требуют exact показанного ID/имени и повторного numeric consent;
identity conflict блокирует запуск. Full cleanup/purge сериализуются с host mutations.
Detach прекращает новые local jobs/publication и не отменяет уже принятую remote
операцию: её возможное продолжение также указано в предупреждении. Default безопасен.
8.6. До очистки делается final accounting attempt; недоступная remote часть отмечается
как неполная, уже известный трафик сохраняется. Partial cleanup не называется полной.

### Requirement 9: обновление

9.1. Пункт 4 показывает actual software и immutable target разрешённого канала;
manual SHA не спрашивается. После подтверждения идёт аккуратный лог и отчёт.
9.2. Scheduled не completed. Успех требует actual installed revision, runtime check
и свежей publication; у withdrawn ноды новая публикация/возврат пользователей запрещены.
9.3. Already installed target не запускает updater второй раз. Закрытие UI/restart/lost
response не теряет результат; rollback/full partial outcome отображаются отдельно.

### Requirement 10: общий UX и роль ноды

10.1. Installed menu имеет ровно 1 protocols / 2 appearance / 3 sync / 4 update /
5 delete / 0 back. Назначение клавиш не меняется от healthy/warning.
10.2. Только цифры для выбора, no y/n/внутренних IDs/JSON; 0 назад, unknown key —
ошибка выбора без mutation. Ctrl-C/EOF отличаются от успешного ввода default.
10.3. Основные экраны помещаются в 60×24 и 80×24; при resize следующий кадр адаптируется.
No-color сохраняет смысл, external text очищается от terminal escape/control injection.
10.4. Локальный TUI ноды read-only: identity, actual software, last apply, local readiness,
ошибки; никаких settings/users/update/restart/remove. Missing identity не открывает admin menu.
10.5. UI использует только ApplicationService ports. Privileged commands идут через
injected HostBackend; нет process-global ApplicationService/registry.

### Requirement 11: совместимость и evidence

11.1. State format=1/node contract=5 сохраняются; aliases/management policy размещаются
в уже поддержанных desired extensions с defaults. Никаких version counters на каждый store.
11.2. Больше не поддерживаемый будущий state не corruption: его нельзя заменять backup/default.
Действительная несовместимость — остановка и отдельное согласование, не silent schema bump.
11.3. Presence of artifact/render/JWE не доказывает client import/UDP handshake. Отчёт
содержит только подтверждённые уровни; неподдержанный backend feature не имитируется кнопкой.
11.4. Tests/guards не удаляются и не ослабляются. Изменившиеся owner-approved UI sequences
адаптируются с сохранением consent/cancel/offline/traffic/security assertions.

## 3. Карта и макеты

Макеты — целевые, числа illustrative, не текущая диагностика VPS.

### M1. Меню нод

```text
НОДЫ

[1] Установить

[2] uk-1 · Великобритания
    194.147.35.112
    healthy · проверена 2 минуты назад

[3] fi-1 · Финляндия
    203.0.113.10
    warning · нет связи · проверяли 6 минут назад

[0] Назад
```

Список не делает RPC при открытии. Он читает latest agent report. На странице не
больше четырёх нод (три смысловые строки каждая); 8/9 — предыдущая/следующая при
необходимости. IDs/name могут сокращаться в списке с full value в карточке, IP не
смешивается с control/SSH port. Caption names используются безопасно, mapping неизменен
в течение одного кадра. Отдельные search/filter/diagnostics разделы не добавлять
в обычный сценарий; scaling не превращает экран в новый dashboard.

### M2. Карточка

```text
uk-1 · Великобритания
194.147.35.112
warning · обновление профилей не завершено
Проверена: 2 минуты назад

[1] Настройки протоколов
[2] Внешний вид
[3] Синхронизировать
[4] Обновление
[5] Удаление
[0] Назад
```

Короткая причина видна здесь, полный safe error — в отчёте операции. Отдельного
обязательного пользовательского/клиентского scope перед входом в карточку нет.
При background operation строка сообщает текущий этап. Выбор conflicting host action
не запускает вторую mutation: показать текущую operation/result. Local detach отделён
от remote mutation; старые callbacks не могут восстановить удалённую binding/публикацию.

### M3. Выбор/настройка протоколов

Установка: selectable transport list, выбранные помечены, отдельный «Готово» и 0.
Установленная нода: то же привычное protocol menu, включая configured disabled
transports; их можно донастроить/перенастроить, а не вводить весь config заново.

Меню конкретного протокола использует семантику/labels/defaults/presets основы,
но scope строго node public settings. Нельзя через reuse локально изменить протокол
основы или копировать её secrets. Изменение режима обновляет условные поля; скрытые
устаревшие значения удаляются owner validator с видимым diff.

В install draft выход из protocol sub-menu сохраняет draft, не VPS. В установленной
ноде действие «Сохранить» фиксирует public intent и запускает shared full sync с
логом/отчётом. Online no-op не вызывает extra network/apply/revision.

### M4. План установки

```text
ПРЕДПОЛАГАЕМАЯ НОДА

ID:       uk-1
Имя:      Великобритания
IP:       194.147.35.112
SSH:      выбранный пользователь · порт 22
Пароль:   введён · не сохраняется
Протоколы: AmneziaWG 3.1, AnyTLS, VLESS + XHTTP
ПО:       разрешённый канал · найденная цель
Доступ:   защищённое управление и служебный SSH key

[1] Подтвердить установку
[2] Исправить данные
[0] Отмена
```

Trust fingerprint выводится полностью/переносом строк до первой mutation. Для первого
контакта план/контролируемый trust step требует explicit consent, не AutoAddPolicy.
IP/username/ID/name в плане не заменяются заново загруженным объектом перед запуском.
Нестандартные ports/channel правятся через «Исправить данные», без новых обязательных
вопросов в основном потоке. Channel head фиксируется в SHA до финального согласия.

### M5. Лог и итог

```text
УСТАНОВКА uk-1

[OK] Доступ и доверие проверены
[OK] HYDRA установлена
[OK] Нода подключена к основе
[>>] Настройка протоколов
[  ] Синхронизация пользователей и профилей
```

Этапы меняются по backend events, не по таймеру анимации. Сохраняется последний
подтверждённый этап; до 20 safe event lines, но не больше остатка высоты текущего
терминала после заголовка/кнопок. Длинный log отдельно пагинируется.
После accepted operation выход не считается cancel worker. Не читать SSH/password
и числовую menu navigation одновременно из одного stdin.

```text
ОТЧЁТ ОБ УСТАНОВКЕ uk-1

Установка:       выполнена
Подключение:     выполнено
Настройки:      применены
Подписки:       опубликованы / причина неполноты
Статус:         healthy / warning

[1] Открыть ноду
[0] К меню нод
```

При ошибке: этап+reason, что уже изменено, что не выполнено, rollback, безопасное
«Продолжить с этапа» после readback. Не повторять всю установку по generic RuntimeError.
Не объявлять «ничего не изменилось», если часть host effects уже произошла.

### M6. Внешний вид

Только видимый ID и имя. Открыть поле → изменить → обзор → сохранить/отмена.
Настоящий immutable key не editable и не показывается в обычном меню. Region из старого
state не стирается, но не превращается в новый обязательный вопрос владельца.

Alias uniqueness проверяется атомарно при сохранении. Новый сервер с совпавшим alias
не устанавливается молча. Для новых nodes internal key выбирается независимо от
изменяемой подписи; legacy key сохраняется навсегда. Старые CLI/контракты используют
technical key; TUI всегда разрешает alias до invocation, не переименовывает certificate.

### M7. Синхронизировать

Кнопка 3 немедленно ставит selected node в тот же pipeline, не ждёт таймера. Отчёт:
связь/трафик, учтённые ограничения, applied settings, profiles, healthy/warning.
Полные user credentials/UUID/links не dump-ятся. Empty user set — нормальный scope,
blocked/expired/quota — не ошибка экспорта как такового.

Синхронизация может изменить runtime (включая блокировки) и не называется «только чтение».
Существующее намерение на основе не требует повторного диалога consent для каждого
background apply. Если конкретная дополнительная операция меняет keys/material,
она должна иметь owner impact и отдельный approved plan, не появляться из обычного poll.

### M8. Обновление

Выбор actual channel/target → план → подтверждение → аккуратный log → отчёт.
Не спрашивать manual SHA. Текущий канал сохраняется по умолчанию; его смена — явное поле.
После installation readback запускается full sync/export freshness. Для withdrawn
node full sync сохраняет empty desired runtime и отсутствие publication.
Окончание показывает actual version и publication outcome отдельно.

### M9. Удаление

Постоянные 1 full cleanup / 2 withdraw with purge / 3 detach / 0 back.
План говорит точный scope, target, последствия для старых clients, финального accounting
и remote runtime. Затем exact display ID/name и `1 Выполнить / 0 Отмена`, default=0.

Withdraw сразу устанавливает durable отсутствие выдачи. Если remote недоступна,
показывать «Из выдачи убрана, очистка на ноде ожидается», а не «пользователи удалены».
Следующий sync повторяет безопасную очистку, но не normal active snapshot.

Успешные full cleanup/detach закрывают карточку в список без `_NodeGone` false error.
Withdraw оставляет пустую управляемую ноду: warning/informational reason «Убрана из подписки».
После настройки протоколов explicit «Вернуть в подписку и синхронизировать» снимает policy;
не восстановить оставленные на основе user definitions без этого решения.

## 4. Полный sync: владелец, порядок и таймер

```text
request: timer / manual / protocol-save / post-update
  → per-node admission, dedup
  → actual identity/health/readiness + absolute traffic
  → атомарный учёт прироста на основе
  → существующий расчёт expiry/quota/block restrictions
  → актуальное намерение:
      active    → users + public protocol settings
      withdrawn → empty users/protocol runtime; no publication
  → подтверждённый apply/purge
  → export/integrity/coverage/publication для active
  → report + healthy/warning + actual checked_at
```

Поведение связывается с существующими `sync_cycle.node_accounting_cycle`,
`_sync_user_limits`, `run_sync_cycle` и SyncOperations. Сейчас обёртка получает
node traffic до расчёта лимитов и reconciliation после него — порядок сохранить.
При этом `NodeManager.traffic_reports` сейчас вызывает refresh ДО получения трафика;
это нельзя оставить источником двойного/устаревшего desired push в новом общем цикле.

Manual/save/update path вызывает того же владельца calculation/push, а не собственную
копию quota logic. Трафик selected node складывается с уже известным local/other-node
ledger. Это не fresh poll всех остальных VPS и не обещание strict quota offline.
Новые глобальные блокировки применяются основе и queued другим нодам штатным механизмом.

Пятиминутный таймер уже есть: `admin_infrastructure.configure_sync_agent` устанавливает
oneshot `hydra-sync-agent` с `OnCalendar=*:0/5` и `Persistent=true`. Сохранять его,
не строить новый background poller, не ставить sleep(300) внутри каждого запуска.
Fast local traffic daemon остаётся как был. Первый реально запущенный agent сразу
делает bounded цикл; нет report до него — warning, не фиктивный healthy.

Manual/save requests не ждут timer и не отодвигают очередной плановый запуск.
Одновременный запрос объединяется с active operation; если intent изменился во время
выполнения — один follow-up. Близкие последовательные циклы могут повторно прочитать
traffic, но не начисляют его дважды. Poll/operation deadlines используют monotonic clock;
сохранённые observed_at timestamps используются для отображения age, не как новый timer.

Healthy только при полном подтверждении актуального intent, реальной готовности
требуемых runtime и целой публикации. Unknown client version не объявляется импортом;
частичное отсутствие заявляемого artifact даёт warning с причиной.
Нет актуального full report → warning. Freshness старее двух плановых интервалов
(600s) также warning; future/invalid timestamps не «только что». Running operation
и pending cleanup показываются причинами warning, а не третьим скрытым статусом.

Сеть/host операции bounded, вне state lock, single-flight per node. При lost reply
сначала operation/receipt readback; нельзя повторно начислить traffic, updater,
rotations или destructive cleanup. Сбой одной VPS не задерживает local accounting.

## 5. Desired metadata и режим «убрать из подписки»

Не добавлять новый schema counter либо изменять technical NodeConfig.id.
Использовать один уже поддержанный desired feature-extension namespace для
per-node `display_id` и management policy `active/withdrawn`, ключ — internal node ID.
Валидация/defaults принадлежат core state owner; записи только через save/update.
Старый runtime сохраняет namespace при pack/unpack, неизвестные поля не теряются.

Для legacy nodes отсутствие metadata означает display_id=node.id, policy=active.
UI никогда не использует совпадение имени для поиска credentials/state files.
Alias rename не переименовывает node-exports, SSH directories или traffic maps.
Presentation name/alias не должны сами вызывать transport apply/rotation: rendering
использует актуальные labels основы, а stable profile identity — technical key/UUID/
protocol/variant, не переименуемый runtime tag. Отдельно тестировать current HB name-ID
defect; изменение только UI недостаточно.

Withdraw требует не только policy на основе, но ограниченную node-side очистку:

- final traffic sample по возможности до удаления счётчиков/peer users;
- очистка users и всех связанных client credential/material records;
- удаление transport runtime/config/material через canonical plugin lifecycle;
- очистка HYDRA-owned firewall/routes/public listeners этих transports;
- сохранение программы, node control identity, protected management и service SSH key;
- local publication остаётся исключённой при любой ошибке/рестарте.

Purge должен быть injected scoped operation с snapshot/journal/rollback на каждой
изменяемой границе. Это не arbitrary remote shell через control API. Пустой export
не проходит обычный gate публикации и не является способом обхода его assertions.
Node API capability добавляется совместимо с текущим contract=5; старый runtime
сообщает unsupported и warning, не получает разрушительный fallback command.

Failed/partial purge сохраняет исходную причину, checkpoint и состояние, что ещё
осталось. Retry использует ту же identity и известный outcome. Возврат после purge
готовит новые необходимые credentials, явно сообщает влияние на ранее скачанные профили.
Старая подписка клиента сама собой не отзывает ключи на недоступной VPS.

## 6. SSH credentials: конкретный безопасный путь

Реального password-aware SSH backend сейчас недостаточно: текущие paths во многих
местах формируют `root@address`, а password не входит в API bootstrap.
Username/password поля нельзя добавить только как декорацию TUI.

Требуемое решение — reuse OpenSSH и injected HostBackend, без sshpass -p/-e, shell=True,
password command arguments или plaintext password files. `HostBackend.run` уже
поддерживает env; env содержит только путь контролируемого ASKPASS helper/auth channel,
но не password. Helper получает secret через одноразовый scoped local IPC от auth
context, отвечает OpenSSH, не пишет в общий stdout logger. Бounded retries/timeouts,
доступ только owner, endpoint не принимает произвольные targets/commands.
Generated/entrypoint helper аудитируется, production subprocess остаётся только
в `hydra/utils/commands.py`. Стандартный Python/существующая cryptography достаточны;
новый SSH SDK не добавлять без доказанной необходимости.

После подтверждённого входа проверить `uid=0` либо `sudo -n` для нужного ограниченного
bootstrap. Запрос дополнительных sudo password/prompts не входит в этот сценарий:
отказ до установки с ясным сообщением о привилегиях. Не подменять username root молча.

Для будущей pinned SSH cleanup выдаётся отдельная managed keypair:

- private key и auth locator на основе: per-node trusted directory, root-only;
- public key добавлен только в нужный account, с owner tag/ограничениями и rollback;
- username/auth binding используются всеми installer/provision/import/remove calls;
- чужие key entries не перезаписываются; удаляется лишь tagged managed access;
- full remote removal убирает этот access последним; active cleanup connection
  завершается и outcome сохраняется до local credentials deletion.

Пароль живёт только в accepted auth session до выдачи доступа/конца попытки. Python
не даёт гарантии secure erase immutable strings — не обещать её; не держать secret
в retained object repr, state, durable checkpoint, exception либо log.
Ключи/certificates/SSH bindings — защищённые credentials, не public desired JSON.

Если accepted установка продолжает работу независимо от закрытия UI, её worker
должен реально быть независимым, а password context передан ему через защищённый
ephemeral channel. Thread, который умирает вместе с меню, не является durable worker.
Сервисные start/status/checkpoint ports и auth handoff реализуются до такой надписи
в UI; прежний blocking вызов нельзя выдать за background operation.

Cookie import/creator/auth actions, если нужны конкретному протоколу, находятся в его
отдельном menu и идут через существующий scoped application service. Не создавать
обязательный новый раздел обслуживания и не копировать cookies основы автоматически.
Install draft до подтверждения не активирует pool и не импортирует secret files на VPS.

## 7. Edge cases: обязательная матрица

Это перечисление выявленных классов риска и проверяемых исходов, не заявление,
что все мыслимые distributed failures уже доказанно исключены.

| ID | Ситуация | Требуемое поведение | Критерии |
| --- | --- | --- | --- |
| E01 | Cancel/EOF на каждом поле установки | Нет host mutation, secret context закрыт | 1.3,1.4,2.5 |
| E02 | Неверный IPv4/IPv6/username/ID | Повтор конкретного поля, остальные публичные значения сохранены | 1.1,1.2 |
| E03 | Password с пробелами/Unicode/спецсимволами | Передаётся как secret bytes, не shell escaping/argv | 2.2 |
| E04 | Password неверен / SSH auth timeout | Бounded failure, без бесконечного prompt/helper | 2.2,2.5 |
| E05 | Login не root, sudo -n допустим/недопустим | Реальный username, explicit privilege result, без sudo password assumption | 2.1 |
| E06 | SSH fingerprint изменился | Ни install, ни cleanup, ни auto trust | 2.3 |
| E07 | Managed key setup partial | Checkpoint/rollback, чужие authorized_keys сохранены | 2.4,7.5 |
| E08 | Restart до выдачи key | Password не persisted, повторный ввод только для auth | 2.5 |
| E09 | SSH и progress одновременно требуют stdin | Один контролируемый input owner, нет interleaved consumption | 2.2,7.3 |
| E10 | Нет sub service/cert на основе | Различённая причина до установки | 1.5 |
| E11 | Пустой/1/4/5/64+ список | Bounded pages, по 3 смысловые строки, стабильные keys | 4.1,4.5 |
| E12 | Одинаковые имена, разные alias | ID+IP различают; не искать по имени | 4.1,6.3 |
| E13 | Выбрали строку, список обновился | Старый номер остаётся прежней identity | 4.5 |
| E14 | Нода удалена/заменена перед действием | Явный target conflict, не новая цель | 4.5,7.2 |
| E15 | Healthy только по /health или pointer | Warning до полного результата | 4.2 |
| E16 | Нет report/ошибка observe/old timestamp | Warning с age/причиной | 4.3,4.4 |
| E17 | Clock в будущем/без timezone/скачок wall clock | Недостоверный age; monotonic schedule не ломается | 4.4,5.1 |
| E18 | Agent стартовал | Первичная сверка, local traffic не ждёт 300s | 5.1,5.6 |
| E19 | Manual sync до таймера | Немедленный тот же полный цикл | 5.1 |
| E20 | Timer+manual+save одновременно | Один active/follow-up, без double accounting | 5.4,5.6 |
| E21 | Traffic пересёк quota в этом цикле | Учесть → block → push, не ждать следующего цикла | 5.2,5.3 |
| E22 | Один sample пришёл дважды / reorder | Идемпотентный monotonic ledger/epoch | 5.4 |
| E23 | Counter reset/user quota reset/restart | Не терять прошлое, не начислять старый epoch | 5.4 |
| E24 | Offline нода / другие отвечают | Последние данные retained; остальные/local accounting не блокируются | 5.6 |
| E25 | Manual selected node, остальные offline | Глобальная квота по известным данным, no strict fresh promise | 5.2,5.6 |
| E26 | Protocol menu открыли/отменили | Не меняется ни основа, ни нода | 3.1,3.3 |
| E27 | Изменить одно поле | Остальные параметры/material не затираются | 3.1,3.2 |
| E28 | Mode меняет условные поля | Owner validation/diff, без stale route | 3.2 |
| E29 | TLS/Reality/DNS/UDP/SNI conflict | Правильный owner preflight, не generic error | 3.2,7.4 |
| E30 | Preset provider/schema недоступен | Нет fake supported default, понятная причина | 3.2,11.3 |
| E31 | Catalog основы новее ноды | Unsupported capability, не сырое применение | 3.2,11.3 |
| E32 | Save no-op | Нет revision/rotation/лишнего sync | 3.4 |
| E33 | Save online | Тот же shared full cycle с traffic/restrictions | 3.4,5.1 |
| E34 | Save offline или сеть потеряна после save | Intent сохранён/pending, не ложный success | 3.5 |
| E35 | Concurrent public settings change | Conflict, не silent overwrite | 7.2 |
| E36 | Traffic изменил общую state revision | Persistence guarded, не ложное перезаписывание target | 5.4,7.2 |
| E37 | Alias rename offline | Никаких certificate/SSH/apply calls | 6.1,6.2 |
| E38 | Duplicate alias / alias swap races | Атомарная uniqueness и explicit conflict | 6.3 |
| E39 | Legacy node metadata отсутствует | Fallback ID/active, rollback reader сохраняет extension | 6.3,11.1 |
| E40 | Новый alias совпал с historical technical key | Независимые namespaces; техническая uniqueness сохранена | 6.2,6.3 |
| E41 | Rename/client resource identity | Keys/UUID/profile IDs стабильны | 6.4 |
| E42 | Поля плана изменились после consent | Новый plan, не mutation старой/чужой цели | 7.1,7.2 |
| E43 | Enter/Ctrl-C/EOF на consent | Default cancel, никаких host changes | 7.2,10.2 |
| E44 | Log содержит password/PEM/URL auth | Redaction before log/truncate, no raw argv/config | 2.2,7.3 |
| E45 | Очень длинный/ANSI/OSC log | Safe bounded lines, не сломанный terminal | 7.3,10.3 |
| E46 | Install прошёл, enroll/apply/export упал | Частичный отчёт/checkpoint; не «всё отменено» | 7.4,7.5 |
| E47 | Runtime apply commit, publish failed | Warning, старый bundle не объявляется рабочим | 4.2,5.5,7.4 |
| E48 | Reply потерян после side effect | Unknown/readback, не blind повтор | 7.5 |
| E49 | UI вышел/agent restart | Durable outcome, секрет password не checkpoint | 7.5,2.5 |
| E50 | Rollback также failed | Обе причины и recovery, исходная не потеряна | 7.5 |
| E51 | Runtime остановлен, control healthy | Warning, status не только controller alive | 4.2 |
| E52 | Desired прежний, installed/exporter новый | Fresh export/publication, не shortcut unchanged | 5.5 |
| E53 | Missing/hash-corrupt/oversized bundle | Warning; изоляция плохой ноды, не false ready | 4.3,5.5 |
| E54 | Нет активных users/all blocked | Нормальная причина отсутствия выдачи, не empty-export fake failure | 4.3,5.2 |
| E55 | AWG URI есть, HB document отсутствует | Missing advertised artifact → warning; не client import proof | 4.2,11.3 |
| E56 | wg/vpn/JSON одного endpoint | Подходящее representation, не второй сервер | 11.3 |
| E57 | Full removal consent ошибочный | Ноль remote/local destructive calls | 8.5 |
| E58 | Full remote cleanup successful/local save failed | Partial report, не fake deleted entirely | 8.1,7.4 |
| E59 | Full cleanup затрагивает managed key | Только tagged key, чужие keys/runtime сохранены | 8.1,2.4 |
| E60 | Withdraw online | Отсутствие выдачи + users/protocol purge; management остаётся | 8.2 |
| E61 | Withdraw offline | Нет публикации, purge pending, нельзя заявить cleaned | 8.2,8.3 |
| E62 | Timer/manual/update после withdraw | Не вернуть users/protocols/publication | 8.3,9.2 |
| E63 | Explicit return после новой настройки | Новый approved intent/material; old clients impact объяснён | 8.3,3.2 |
| E64 | Purge failed после удаления части users | Durable checkpoint, warning, safe retry/rollback | 8.2,7.5 |
| E65 | Detach offline | Предупреждение до consent, никакой remote purge | 8.4 |
| E66 | Final accounting недоступен при удалении | Известный ledger сохранён, uncollected tail обозначен | 8.6 |
| E67 | Удаление local cleanup warnings/_NodeGone | Устойчивый partial/success report, не false operation error | 7.4,8.1 |
| E68 | Busy update/apply/remove; detach while running | No duplicate host mutation; detach fences local jobs, remote accepted work не объявлено отменённым | 5.6,8.5 |
| E69 | Update scheduled/actual marker отсутствует | Не completed, проверка реального исхода | 9.1,9.2 |
| E70 | Target уже установлен | Не второй updater, readiness/publication verification | 9.3 |
| E71 | GitHub lookup failed/branch moved | План не начат/фиксированный approved SHA | 9.1,7.2 |
| E72 | Update rollback/partial publication | Различённый actual version/outcome | 9.2,9.3 |
| E73 | Protocol/control feature unsupported старой нодой | Нет вымышленного success, обновление/предсказуемый отказ | 11.1,11.3 |
| E74 | Unknown/leading-zero/non-numeric key | Unknown action, не mutation; trim whitespace | 10.1,10.2 |
| E75 | Ctrl-C/EOF превращались в prompt default | Node input различает interruption/value, no accidental save | 10.2 |
| E76 | 60/80 columns, no-color, resize, CJK | Читаемые 3-line rows/menu/logs, safe width | 10.3 |
| E77 | Non-TTY | Нет interactive/mutation loop, role/root guards сохранены | 10.3,10.4 |
| E78 | Node identity отсутствует/повреждена | Read-only emergency, не normal admin menu | 10.4 |
| E79 | UI напрямую читает files/exec/network | Boundary test fail; только application ports | 10.5 |
| E80 | Будущая неизвестная state schema | Не corruption/backup/default fallback | 11.2 |
| E81 | Root privilege guard/production constraints | Не ослаблять под переносимые unit tests | 11.4,2.1 |
| E82 | Fake renderer/client connection claim | Import/UDP unverified явно, guards не greenwash | 11.3,11.4 |
| E83 | Full cleanup удалил control/auth, reply потерян | Unknown, readback с operator SSH auth; не blind reinstall/access recreation | 8.1,7.5,2.3 |
| E84 | Withdraw intent сохранён до final sample | Учесть sample по pre-purge receipt/epoch; generation change не теряет хвост | 8.6,5.4 |
| E85 | Same generation, другой digest / точный retry | Mismatch отвергнут; exact retry возвращает receipt без второй мутации | 5.3,7.5 |
| E86 | Calls cookies/creator action в protocol menu | Scoped service/secret channel; нет auto import/activation до общего consent | 3.2,3.3,2.2 |

## 8. Внедрение: владельцы и минимальные изменения

Сохраняется направление UI → ApplicationService → domain/service → injected host.
Бизнес sync/quota/purge не дублируется в TUI. Screen/step не требует собственного
класса, версии схемы или отдельного файла.

| Область | Канонические файлы / ответственность |
| --- | --- |
| UI списка/карточки/удаления | `hydra/ui/_menus/nodes.py`: точные M1/M2/M9, existing facade signatures |
| Установочный мастер | `nodes_setup.py`: новый порядок, secret input, plan; никаких direct host calls |
| Protocol menus | `node_protocol_fields.py`, protocol UI owners: reuse public schema/меню с node target, без второго registry |
| Secret/cancel/log helpers | Новый небольшой `hydra/ui/_menus/node_input.py` и `node_progress.py` при необходимости; existing tui renderer |
| Identity/aliases/policy | `hydra/core/state_nodes.py`, `state_validation.py`, `state_format.py`: extension validation/defaults/preservation, без schema bump |
| Full sync owner | `hydra/services/nodes/manager.py`, `sync_cycle.py`, `sync_ports.py`, existing sync agent: shared entry, accounting before push |
| Snapshot/publication | `nodes/reconciler.py`, `reconcile.py`, `snapshot_store.py`, subscription node reader: coherent current artifacts, withdrawn exclusion |
| Presentation/profile identity | `subscriptions/profile_names.py`, `node_exports.py`, `hydrabox.py`: latest display labels на основе, stable technical profile IDs, без name-dependent ID |
| Status/outcomes | `nodes/observation.py` + небольшой pure status/report helper; healthy/warning, timestamps и real stages |
| Password/managed SSH | `nodes/installer.py`, `bootstrap.py`, `credentials.py`, новый scoped `ssh_auth.py`/ASKPASS entrypoint; HostBackend only subprocess owner |
| Purge/cleanup/detach | `nodes/operations.py`, node application/lifecycle owners, limited control capability, transactional purge/final accounting |
| Upgrade/results | `nodes/upgrade.py`, control client/server, existing updater outcome/readback; post-update shared sync |
| Локальная нода | `node_emergency.py` через application read reports; no admin mutations |

Scoped interruption propagation в `tui.menu/prompt` добавляется совместимо, default
для существующих callers не меняется. Новый node path не может отличить EOF от
Enter после прежнего swallowing — это исправляется у input owner, а не догадками.
Numeric confirmation default=0; domain exception handler не ловит navigation signals
как failed business operation.

Новые aliases/policy пишутся через save/update, protected SSH credentials не в state.
Conflict проверяется по captured technical target/public config, а не любой общей
revision смене от traffic accounting; optimistic revision guard всё равно сохраняется.
Операции/durable outcomes instance-owned, без process-global registry.

Production modules ≤500 строк, функции проектировать ≤100, stricter guards сохранять.
При росте существующих manager/bootstrap/helpers выносить конкретного владельца,
не создавать абстрактный command bus или новый UI framework.

## 9. Пакеты реализации и traceability

| Пакет | Проверяемый результат | Требования |
| --- | --- | --- |
| A | Secret/cancel input, настоящий username/password SSH, protected managed auth | 1.1–1.5,2.1–2.5,7.1–7.3,10.2 |
| B | Alias/policy extensions, fallback/atomic uniqueness, list/appearance | 4.1,4.5,6.1–6.4,10.1,11.1,11.2 |
| C | Shared complete node sync, 300s schedule, accounting/restrictions/fresh publication/status | 3.4,3.5,4.2–4.4,5.1–5.6 |
| D | Owner-backed protocol menus и exact install flow, accepted operation logs/reports | 3.1–3.5,7.1–7.5,10.3,10.5 |
| E | Full removal / withdraw purge / detach, final accounting, durable policy/recovery | 8.1–8.6,7.4,7.5 |
| F | Update + post-sync, read-only node, integration/compatibility/security guards | 9.1–9.3,10.4,10.5,11.1–11.4 |

В каждом пакете сначала regression/happy/failure checks. Partial packages не называют
весь режим готовым. Нельзя закрыть A декоративным password field или E фильтром links.
Новый endpoint/capability должен быть additive для текущего contract=5; иначе stop
и отдельное owner решение, не автоматическое повышение версии контракта.

## 10. Тесты и definition of done

Existing guards/UX tests не удалять и не ослаблять. Изменяются input sequences для
согласованного сценария; сохранившиеся бизнес-assertions остаются строгими.

Добавить/расширить:

- wizard tests: точный порядок, getpass/cancel/validation, secret-free plan, final consent;
- SSH auth tests: real username in target, private IPC, no secret argv/env/log/checkpoint,
  managed key ownership/rollback, privilege refusal до install;
- node metadata roundtrip: aliases/policy сохраняются в format=1, legacy defaults,
  concurrent rename, stable certificates/profile IDs/traffic references;
- fake-clock/scheduler tests: existing пятиминутный OnCalendar, unchanged fast local
  accounting, no internal startup sleep, manual/save/update не откладывают timer,
  single-flight/follow-up, два близких цикла и timeout/restart;
- full-cycle tests: traffic→restrictions→snapshot→apply→publish, counter/reset epochs,
  offline isolation, no stale producer shortcut;
- purge failure injection до/после side effect: users, peers/material, transports,
  firewall/routes, final accounting, publication policy; management не очищается;
- navigation/render tests: actual input including EOF/Ctrl-C, fixed keys, 3-line rows,
  60/80 columns/no-color/resize, bounded safe logs и устойчивые outcome screens;
- node role/boundaries: no local admin actions/direct UI I/O, preserved root/CLI guards;
- upgrade/cleanup tests: lost replies, worker restart, partial outcomes, correct same-target
  retry, withdrawn state не реактивируется;
- renderer/artifact tests отдельно от real client import/handshake acceptance.

После появления соответствующего кода — narrow tests, architecture graph/audit/size,
Ruff, для законченной существенной поставки verify.py. Default suite не открывает sockets;
node mTLS E2E opt-in. Host/install/upgrade/uninstall/purge требуют isolated Linux integration.
Не запускать install/upgrade scripts локально или на рабочей VPS из coding-сессии.

Приёмка следует ровно пользовательскому пути §1:

1. IP/user/password/ID/name, настроить два протокола в отдельных меню, Готово,
   проверить карточку, отменить — нет установки; повторить с согласия — log и отчёт.
2. В списке ID+имя/IP/healthy-warning. Изменить ID/имя — technical trust/keys не изменились.
3. Настроить один параметр — full sync сразу, учёт traffic/block и актуальная публикация.
4. Нажать sync до таймера — тот же цикл; следующий timer не дублирует трафик/host mutation.
5. Обновить — log/actual version/report, не scheduled-as-success.
6. Withdraw — пользователи/протоколы очищены; после двух timer cycles и update не вернулись.
   Явно вернуть через настройку — новый approved runtime/профили.
7. Detach — предупреждение до согласия, VPS не очищена; full removal — только HYDRA
   scope/managed auth, полный/частичный outcome различён, начисленный трафик сохранён.
8. На ноде только диагностика, failures/identity/readiness не скрыты.

Реальное подтверждение AWG/HB/Throne требует клиентских версий и import/traffic check.
Этот документ не выдаёт макеты, unit tests или HTTP 200 за такой результат.
