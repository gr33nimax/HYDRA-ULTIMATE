# Hydra VK Tunnel: техническая телеметрия

## Назначение и граница достоверности

Телеметрия предназначена для управляемого эксперимента: оператор запускает
запись, наблюдает единый timeline в реальном времени, размечает смену условий,
в любой момент получает отчёт или очищенный архив и явно останавливает запись.
Автоматического таймера нет. Защитный лимит диска только прекращает добавление
новых данных; существующий timeline никогда не ротируется и не удаляется.

Реализация сверена с Hydracore
[`06c48894`](https://github.com/gr33nimax/hydracore/tree/06c48894c61a88b0ed72156010d239c81f14dec5),
tag `v1.13.16-extended-hydracore.9`. В режиме `multi_user` сервер является
UDP/DTLS endpoint, а клиент получает TURN credentials через VK Calls, создаёт
несколько workers и полосует одну KCP-сессию через них. Поэтому Clash API на
VPS видит соединения и goodput, но сам по себе не видит latency VK auth/TURN,
DTLS handshake, KCP RTT/retransmit/window и потери внутренних очередей.

Отчёт имеет один из уровней:

- `full` — присутствуют все обязательные server и client native groups;
- `partial` — есть часть нативных записей;
- `server_observation_only` — только наблюдения Ultimate/Clash/procfs.

Вывод о настройке KCP, workers или VK/TURN нельзя считать точным при уровне
ниже `full`. Это намеренный fail-closed контракт анализа.

## Управление экспериментом

```bash
sudo hydra calls telemetry start \
  --tester alpha@example.com \
  --tester bravo@example.com \
  --tester charlie@example.com \
  --interval 2 \
  --max-mib 2048

sudo hydra calls telemetry status
sudo hydra calls telemetry tail --lines 100 --follow
sudo hydra calls telemetry mark wifi_baseline
sudo hydra calls telemetry mark mobile_handover
sudo hydra --json calls telemetry report > report.json
sudo hydra calls telemetry export --output hydra-vk-tunnel.tar.gz
sudo hydra calls telemetry stop
```

`tail --follow` завершается по `Ctrl+C` или после остановки сессии. `mark`
принимает короткий ASCII slug и формирует независимые фазы отчёта. `report` и
`export` не останавливают активную запись. Для старого эксперимента указывается
`--session ID`.

## Что реально записывается

Единый timeline содержит четыре типа записей:

- `sample`: goodput, active/attributed connections, opens/closes, short и
  zero-byte sessions, no-progress 5/15/30 s, counter resets, per-tester totals,
  долю постороннего и неатрибутированного Calls-трафика;
- `sample`: CPU/RAM/network VPS; CPU ticks, RSS/peak/swap, threads, faults,
  context switches, I/O, FD и restarts Hydracore;
- `sample`: CPU/memory/I/O PSI, softnet drop/time-squeeze, NIC packets/errors/
  drops, dirty/writeback/swap, conntrack, disk free, UDP SNMP и receive queue/
  drops конкретного Calls listener;
- `event`: безопасная категория journald — auth/session/worker/VK/TURN/relay —
  без сырой строки;
- `mark`: операторская граница фазы;
- `native`: числовой snapshot/event из инструментированного Hydracore.

Report вычисляет distribution min/p50/p95/p99/max, throughput и lifetime,
coverage/gaps, различия фаз, goodput/wire efficiency, а также Pearson correlation
goodput с CPU, concurrency, UDP receive queue, KCP `wait_snd`, KCP RTT и
клиентским loss. Корреляция является указателем для следующего A/B-теста, а не
доказательством причинности.

## Нативный JSONL-контракт Hydracore

VPS core пишет append-only файл `/run/hydra/calls-telemetry.jsonl`. Строка:

```json
{"schema":1,"timestamp":1786400000.25,"scope":"server","kind":"snapshot","session_id":"internal-id","metrics":{"worker_active":12,"kcp_wait_snd":37,"kcp_rtt_ms":82.4}}
```

Client-событие, доставленное на VPS через аутентифицированный control path:

```json
{"schema":1,"timestamp":1786400001.5,"scope":"client","kind":"event","user":"alpha@example.com","session_id":"internal-id","worker_id":2,"event":"worker_reconnect","stage":"dtls","reason":"timeout","metrics":{"worker_reconnect_total":3}}
```

Допустимы только `scope=server|client`, `kind=snapshot|event`, до 128 числовых/
boolean metrics и slug-поля `event/stage/reason`. Максимальная строка — 64 KiB,
за poll читается до 1024 записей. Файл-symlink, неизвестная schema, строки,
неразрешённые metric names, отрицательные/NaN/Inf и повреждённые записи
отклоняются. `user` и `session_id` немедленно псевдонимизируются; исходные
значения в timeline не попадают.

Обязательные server groups:

- DTLS: success/failure totals и handshake latency;
- KCP: `wait_snd`, out/retrans segments и RTT;
- outer: in/out packets и bytes, authentication failures;
- worker: active, attach success, send-queue drops;
- relay: active TCP/UDP и queue drops;
- session: active/created/closed;
- runtime: goroutines, heap и GC pause total.

Обязательные client groups:

- VK anonymous auth: success/failure и latency;
- TURN allocate: success/failure и latency;
- DTLS: success/failure и handshake latency;
- workers: desired/active/reconnect;
- KCP: `wait_snd`, retrans segments и RTT;
- network: loss ratio, jitter и handover;
- runtime: CPU, RSS и thermal state.

Точные metric keys зафиксированы в
`hydra/services/calls_telemetry_protocol_analysis.py`. Текущий изученный
Hydracore `.9` этот JSONL ещё не производит. До добавления instrumentation в
client и VPS core Ultimate собирает полный server-observation слой, но честно
выдаёт critical finding `native_coverage_incomplete`.

## Как читать направления улучшения

| Наблюдение | Вероятная зона | Следующий проверяемый эксперимент |
| :--- | :--- | :--- |
| kernel/NIC/UDP drops растут | VPS, socket buffers, NIC/CPU scheduling | Устранить host loss, затем повторить тот же workload |
| KCP retransmit высокий при высоком loss/RTT | путь client ↔ VK TURN | Сравнить сети/регионы/TURN и только затем KCP policy |
| `kcp_wait_snd` около 2048 | KCP backpressure/window | A/B окна и congestion strategy с контролем latency/RSS |
| worker queue drops/no-worker | striping и внутренние очереди | Профилировать send path, менять workers/queue depth |
| VK/TURN/DTLS latency/failures | control plane/handshake | Разнести p95 по stage, worker и tester |
| goodput растёт вместе с Hydracore CPU до насыщения | CPU/crypto/single UDP loop | Go profile, crypto/alloc/GC и multi-core dispatch A/B |
| frequent reconnect/handover, no kernel loss | client liveness/rebind | Сравнить backoff, heartbeat и network-rebind policy |
| низкий goodput/wire efficiency | overhead/retransmit/heartbeat | Разложить outer bytes по payload/retrans/control |

Сравнивать параметры следует по одинаково размеченным фазам и менять за один
прогон одну переменную. Иначе число workers, тип сети и профиль нагрузки будут
смешаны в одной корреляции.

## Хранение и приватность

Runtime manifest: `/var/lib/hydra/calls/vk/telemetry/`; timeline и exports:
`/var/log/hydra/calls-telemetry/`. Каталоги создаются с `0700`, файлы с `0600`.
Export содержит только `timeline.jsonl`, `manifest.json`, `report.json` и
`SCHEMA.txt`; соль, хэши identity, cursors и raw runtime state исключены.
Email, IP, destination, VK/join links, cookies, tokens, passwords, obfs key,
raw connection/session IDs и сырой journald не сохраняются.

Полный timeline всегда входит в export. Чтобы анализ очень длинной сессии не
исчерпал RAM VPS, report равномерно ограничивает рабочий набор 100000 samples,
100000 native records и 50000 events, сохраняя первый и последний record.
`analysis_input.strides` показывает применённый шаг; исходные данные при этом
не изменяются и доступны для внешнего offline-анализа.

## Операторская сводка и сжатое хранение

`status` теперь строит сводку по последним 5000 записям прямо во время теста,
а `stop` сразу печатает итоговый технический отчёт. Ручной разбор JSONL для
первичной диагностики не нужен. В human-readable вывод входят:

- точный список отсутствующих сущностей и групп вместо одного слова `partial`;
- раздельные `server_process`, `server_session`, `server_worker`,
  `client_session` и `client_worker`;
- непрерывность sequence, пропуски control/records, истечения lease и ротации
  нативного staging-файла;
- направление wire traffic, KCP retransmission ratio, `wait_snd`, RTT, loss,
  очереди, reconnect и непубличный номер выбранного TURN-кандидата;
- фактическая конфигурация KCP и выводы о downstream/uplink bottleneck,
  насыщении окна, перекосе workers и stale server sessions.

Полный timeline не прореживается. Активный хвост остаётся обычным JSONL для
`tail --follow`, а завершённые сегменты по 8 MiB сжимаются в
`*.part-NNNNN.jsonl.gz`. `status` показывает физический объём, логический raw
объём и экономию. Защитный `--max-mib` применяется к реальному занятому месту.
`export` прозрачно объединяет все сегменты обратно в один `timeline.jsonl`.
Отчёт ограничивает RAM стратифицированной выборкой отдельно для каждой
сессии/worker; поэтому периодические записи одной сущности не могут вытеснить
другую и не создают ложные telemetry gaps при прореживании анализа.
