# Hydra VK Tunnel: техническая телеметрия

## Назначение и граница достоверности

Телеметрия предназначена для управляемого эксперимента: оператор запускает
запись, наблюдает единый timeline в реальном времени, размечает смену условий,
в любой момент получает отчёт или очищенный архив и явно останавливает запись.
Автоматического таймера нет. Защитный лимит диска только прекращает добавление
новых данных; существующий timeline никогда не ротируется и не удаляется.

Реализация рассчитана на инструментированный Hydracore из совместимой ветки
`debug`. В режиме `multi_user` сервер является
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

Adaptive diagnostics separate three signals that must not be conflated:
`network_loss_ratio` is authenticated outer RTP loss,
the displayed `Path retry` is the cumulative ratio of failed path attempts,
and
`worker_output_queue_delay_ms` is local residence after KCP output. The
short-lived `worker_path_retry_ratio` EWMA remains available to the scheduler;
older cores without exact attempt counters fall back to that value. The
`worker_path_loss_ratio` field from the first adaptive build remains accepted
only as a compatibility alias for the EWMA. Live `status` hides
historical sessions; `report` keeps them and prints the pseudonymous native
session ID for each worker.

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
`hydra/services/calls_telemetry_native_contract.py`. Совместимый Hydracore
производит process/session/worker snapshots на сервере и передаёт клиентские
snapshots через аутентифицированный control path. Смешивание старого клиента
или сервера с новым контрактом явно понижает coverage и выдаёт
`native_coverage_incomplete`.

## Как читать направления улучшения

| Наблюдение | Вероятная зона | Следующий проверяемый эксперимент |
| :--- | :--- | :--- |
| kernel/NIC/UDP drops растут | VPS, socket buffers, NIC/CPU scheduling | Устранить host loss, затем повторить тот же workload |
| KCP retransmit высокий при высоком loss/RTT | путь client ↔ VK TURN | Сравнить сети/регионы/TURN и только затем KCP policy |
| `kcp_wait_snd` около 2048 | KCP backpressure/window | Проверить dynamic-cwnd flag, RTT/retry и только затем A/B размера окна с контролем latency/RSS |
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
100000 высокочастотных native worker/session records и 50000 events. Для каждого
native source сохраняются первый/последний snapshot и обе стороны каждого reset,
а native events не прореживаются. Поэтому итоговые counter deltas и границы
поколений остаются точными при ограниченном использовании RAM.
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

## Контроль второго прогона

Совместимая версия Hydracore для второго прогона меняет именно измеренные в
первом прогоне узкие места:

- уже заблокированный DTLS read немедленно замечает изменение deadline, поэтому
  timeout освобождает handshake slot и не оставляет `handshake_pending=256`;
- UDP receive/send socket buffers запрашиваются по 4 MiB, а их фактический
  Linux-размер публикуется как `udp_socket_*_buffer_bytes`;
- чтение UDP отделено от unwrap/dispatch bounded ingress-очередью на 4096
  пакетов с автоматическим числом workers и отдельными depth/capacity/drop
  метриками; порядок пакетов одного peer сохраняется;
- peer-read queue составляет 128 пакетов для неизменённого legacy и 256 для
  adaptive, чтобы переживать измеренный краткий burst; worker-send queue — 512;
  `worker_send_queue_drops_total` теперь означает один реально потерянный KCP
  segment, а не число проверенных заполненных worker queues;
- `outer_payload`, `outer_overhead`, KCP output/retransmit bytes и generation
  процесса позволяют разложить wire overhead и отличить перезапуск inbound от
  потери telemetry records.

Полный 1440p-прогон adaptive debug.5 показал следующий независимый предел:
VPS CPU, UDP ingress и socket buffers не были насыщены, но один стандартный
dynamic KCP congestion window управлял четырьмя самостоятельными TURN-путями.
Межпутевая перестановка/потеря уменьшала общее окно, заполняла `WaitSnd` и
ограничивала видео примерно 2–3 Mbit/s. Совместимый debug.6 сохраняет adaptive
chunk affinity и перенос повторов на другой TURN, но использует bounded
local/remote KCP windows без единого dynamic cwnd. Точный
`worker_path_attempt_segments_total` устраняет ложную интерпретацию EWMA, а
анализ KCP retransmit сравнивает только сегменты с сегментами, не байты с
сегментами.

Для промежуточной проверки достаточно `status`; непрерывный поток доступен через
`tail --follow`, полный итог — через `report` или `export`. Ни одна из этих команд
не останавливает запись и не привязана к продолжительности эксперимента.
