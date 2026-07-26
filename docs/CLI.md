# Headless CLI

CLI HYDRA строится вокруг одного рабочего цикла:

```bash
hydra status
hydra check
sudo hydra apply
```

- `status` отвечает на вопрос «что сейчас происходит?»;
- `check` проверяет всё необходимое и показывает будущие изменения;
- `apply` транзакционно приводит сервер к желаемому состоянию.

Внутренние стадии вроде state validation, host doctor, configuration plan и
service reconciliation не являются отдельными пользовательскими сценариями.
Они входят в `check` и не засоряют основную справку.

```text
   что-то не так?                собираетесь менять?            меняете
        │                              │                           │
        ▼                              ▼                           ▼
   hydra status ──────────────▶  hydra check  ─── ok ──────▶  sudo hydra apply
   что происходит сейчас         безопасно ли применять        транзакционно
        ▲                              │                           │
        │                              ╳ найдены проблемы          │
        │                              ▼                           │
        │                     исправить причину                    │
        └──────────────────── и повторить check ◀──────────────────┘
                                                  проверить результат
```

## Дерево команд

```text
hydra
├── status                        желаемое и фактическое состояние
├── check                         полный read-only preflight
├── apply [--dry-run]             транзакционное применение
├── backup
│   ├── create [--output PATH]    создать проверяемый архив
│   ├── inspect ARCHIVE           проверить архив, не восстанавливая
│   └── restore ARCHIVE [--dry-run] [--yes]
├── user (users)
│   ├── list · show               без секретов
│   ├── add · remove              транзакция по всем транспортам
│   ├── rename                    UUID и секреты сохраняются
│   ├── set-device-limit [--reset]
│   ├── block · unblock
│   └── ensure-default
├── plugin (plugins)
│   ├── list [--category ...] · show
│   ├── status · health           runtime-состояние одного плагина
│   ├── install · reinstall · uninstall
│   ├── enable · disable          желаемое состояние
│   ├── command · action          allowlisted mutation / runtime-операция
│   └── query                     allowlisted read-only projection
├── upgrade
│   ├── check                     готовность к обновлению
│   └── migrate-state             атомарная запись миграций схемы
├── uninstall [--yes] [--dry-run] [--keep-data]
└── antidpi
    ├── sync                      установить/обновить телеметрию
    ├── selftest [--full] [--wait N] [--output PATH]
    └── capture [--seconds N] [--output PATH]
```

## Быстрый справочник

| Команда | Root | Назначение |
| :--- | :---: | :--- |
| `status` | — | Желаемое и фактическое состояние |
| `check` | — | Полный read-only preflight и будущие изменения |
| `apply` | ✔ | Транзакционно применить конфигурацию |
| `apply --dry-run` | — | Полный эквивалент `check` |
| `backup create` | ✔ | Создать проверяемый архив |
| `backup inspect` | — | Проверить архив без восстановления |
| `backup restore` | ✔ | Восстановить архив |
| `user ...` | зависит | Управлять пользователями |
| `plugin ...` | зависит | Управлять плагинами |
| `upgrade ...` | зависит | Проверить или мигрировать установку |
| `uninstall` | ✔ | Удалить HYDRA |
| `antidpi ...` | ✔ | Расширенная диагностика AntiDPI |

Глобальные параметры:

```bash
hydra --version
hydra --json status
hydra status --json
hydra --compact status
hydra status --compact
```

В интерактивном терминале CLI показывает короткие сводки, таблицы и понятные
ошибки. При перенаправлении stdout вывод автоматически переключается на JSON,
чтобы pipe, cron и systemd не зависели от терминального оформления.

- `--json` всегда включает формат для автоматизации;
- `--compact` включает однострочный JSON;
- обе опции можно ставить до или после команды;
- стандартная переменная `NO_COLOR` отключает ANSI-цвета.

## Основной цикл

### `status`

```bash
hydra status
```

Возвращает снимок без изменений:

- количество пользователей и версию state;
- желаемые и фактические флаги сети;
- состояние плагинов;
- runtime drift;
- аудит TLS/SNI-маршрутов;
- блок `certificates`: момент последней суточной проверки сертификатов и срок
  каждого из них в днях. Значения берутся из state и не требуют обращения к
  хосту, поэтому `status` остаётся мгновенным.

`status` предназначен для наблюдения. Он не отвечает, безопасно ли сейчас
применять конфигурацию — для этого есть `check`.

### `check`

```bash
hydra check
```

Это единственная команда предварительной проверки. Она выполняет:

1. semantic validation сохранённого state;
2. проверки Python, systemd, зависимостей, каталогов и TLS-маршрутов;
3. сбор и валидацию plugin `ConfigFragment`;
4. preflight конфликтов Sing-Box;
5. расчёт будущих runtime-изменений и service drift.

В терминале результат разбит на три смысловых раздела: configuration, host
checks и pending changes. Машиночитаемый эквивалент можно получить командой
`hydra check --json`:

```json
{
  "ok": true,
  "configuration": {
    "valid": true,
    "schema_version": 4,
    "revision": 12
  },
  "host": {
    "ok": true,
    "required_failures": [],
    "warnings": []
  },
  "changes": {
    "valid": true,
    "conflicts": [],
    "plugins": ["naive"],
    "reconciliation": [],
    "tls_mux": {
      "ok": true,
      "required": true
    }
  }
}
```

Код завершения равен `1`, если обязательная проверка не прошла.

### `apply`

```bash
sudo hydra apply
hydra apply --dry-run
```

Без параметров команда применяет текущее desired state: конфигурацию Sing-Box,
nftables/TPROXY, Caddy L4, plugin runtime, traffic daemon и health checks.
Операция использует snapshots и rollback.

`--dry-run` не имеет отдельной логики и возвращает тот же результат, что
`hydra check`.

Рекомендуемый эксплуатационный цикл:

```bash
sudo hydra backup create --output /root/hydra-before-change.tar.gz
hydra check
sudo hydra apply
hydra status
```

## Backup

```bash
sudo hydra backup create
sudo hydra backup create --output /root/hydra.tar.gz
hydra backup inspect /root/hydra.tar.gz
sudo hydra backup restore /root/hydra.tar.gz --dry-run
sudo hydra backup restore /root/hydra.tar.gz --yes
```

- `create` использует trusted policy ядра и plugin backup declarations;
- `inspect` проверяет manifest, SHA-256, размеры, state и допустимые пути;
- `restore --dry-run` показывает изменения;
- фактическое восстановление требует `--yes` и создаёт safety backup.

Симлинки, path traversal, дубликаты и файлы вне policy отклоняются.

## Типовые сценарии

### Безопасный порядок изменения

```bash
sudo hydra backup create --output /root/hydra-before-change.tar.gz
hydra check
sudo hydra apply
hydra status
```

Команды чтения не требуют `root` и не меняют систему, поэтому `check` и `status`
безопасно вызывать в любой момент, в том числе из мониторинга.

### Если что-то сломалось

```bash
hydra status
hydra check
sudo journalctl -u sing-box -u caddy-l4 --no-pager -n 100
sudo hydra apply                     # повторный запуск — штатный сценарий
```

`apply` идемпотентен: он приводит рантайм к желаемому состоянию и откатывает
частичное изменение, поэтому повтор после устранённой причины — обычный ход.

### Восстановление из архива

```bash
sudo hydra backup restore /root/hydra-before-change.tar.gz --dry-run
sudo hydra backup restore /root/hydra-before-change.tar.gz --yes
sudo hydra apply
```

## Пользователи

Команды чтения:

```bash
hydra user list
hydra user show alice@example.com
```

Credentials и отпечатки устройств не выводятся.

Изменения:

```bash
sudo hydra user add alice@example.com
sudo hydra user add alice@example.com \
  --traffic-limit-gb 100 \
  --expiry-date 2026-12-31 \
  --device-limit 3
sudo hydra user rename alice@example.com alice-new@example.com
sudo hydra user set-device-limit alice-new@example.com 5 --reset
sudo hydra user block alice-new@example.com
sudo hydra user unblock alice-new@example.com
sudo hydra user remove alice-new@example.com
sudo hydra user ensure-default
```

User lifecycle проходит через общий application service и откатывается вместе
с plugin hooks, state и runtime apply.

Лимит трафика и срок действия применяются независимо от ручной блокировки:
исчерпанный лимит отключает доступ без `block`, а `unblock` не вернёт доступ,
пока ограничение действует.

`users` является алиасом `user`.

## Плагины

Просмотр metadata и runtime:

```bash
hydra plugin list
hydra plugin list --category transport
hydra plugin show naive
hydra plugin status naive
hydra plugin health naive
```

Lifecycle:

```bash
sudo hydra plugin install naive
sudo hydra plugin enable naive
sudo hydra plugin disable naive
sudo hydra plugin reinstall naive
sudo hydra plugin uninstall naive
```

Metadata-declared extension API:

```bash
sudo hydra plugin command hysteria2 set_port --param port=8443
sudo hydra plugin command vless set_domain --param domain=xhttp.example.com
sudo hydra plugin command vless set_path --param path=/xhttp
sudo hydra plugin command vless set_mode --param mode=stream-up
sudo hydra plugin command vless set_preset --param preset=low_latency
sudo hydra plugin command vless set_tuning --param padding=500-2000 \
  --param max_post_bytes=500000 --param no_sse_header=true
sudo hydra plugin command vless set_tuning \
  --param 'headers={"X-Requested-With":"XMLHttpRequest"}'
sudo hydra plugin command vless set_tuning --param utls_fingerprint=chrome
sudo hydra plugin command anytls set_decoy_theme --param theme=cafe
hydra plugin query vless get_tuning --with-state
hydra plugin query warp external_sources --with-state
sudo hydra plugin action dnscrypt apply_server_names \
  --param 'names=["cloudflare","quad9-dnscrypt-ip4-filter-pri"]'
```

`--param NAME=JSON` можно повторять. Операция должна быть объявлена в
`PluginMeta.commands`, `queries` или `actions`; произвольные методы вызвать
нельзя. Command/action требуют root, query является read-only.

Для `vless` сначала задайте отдельный домен, DNS-запись которого указывает на
VPS, затем выполните `sudo hydra plugin enable vless`. Certificate preflight
получит сертификат, а общий apply создаст XHTTP inbound, маршрут Caddy и
заглушку. Поддерживаемые mode: `stream-up`, `packet-up`, `stream-one`.
Команда вернёт успех только после проверки активного SNI-маршрута, загрузки
сертификата в Caddy и локального TLS handshake с ALPN `h2`; при ошибке apply
откатит состояние и runtime и вернёт точную причину.

`set_tuning` принимает любое подмножество параметров транспорта XHTTP и
применяет их одной транзакцией; неизвестный параметр или значение вне диапазона
отклоняются до изменения состояния:

| Параметр | Значение | По умолчанию |
| :--- | :--- | :--- |
| `padding` | диапазон байт `N` или `N-M`, 0–65535; `0` отключает паддинг | `100-1000` |
| `max_post_bytes` | размер upload-пакета, 4096–16777216 | `1000000` |
| `max_buffered_posts` | глубина буфера upload-пакетов, 1–1024 | `30` |
| `stream_up_secs` | длительность stream-up, диапазон секунд 0–3600 | `20-80` |
| `max_header_bytes` | лимит заголовков запроса на сервере, 1024–65536 | `8192` |
| `no_sse_header` | не отправлять SSE-заголовок (CDN с буферизацией) | `false` |
| `headers` | до 16 собственных HTTP-заголовков; `Host`, `Connection`, `Content-Length`, `Transfer-Encoding` и `Upgrade` запрещены | `{}` |

`set_preset` выставляет режим и весь набор параметров согласованно:
`balanced` (значения по умолчанию), `low_latency` (stream-one и малые буферы),
`stealth` (крупный паддинг, длинные сессии), `cdn` (packet-up без SSE-заголовка).
`get_tuning` возвращает действующие значения и имя профиля (`custom`, если набор
не совпадает ни с одним профилем). Пользовательские заголовки не влияют на
определение профиля.

`utls_fingerprint` задаёт TLS-отпечаток клиента: `none` (по умолчанию — выбор
остаётся за клиентом), `chrome`, `firefox`, `safari`, `edge`, `ios`, `android`,
`random`, `randomized`. Значение попадает в клиентский профиль как блок
`tls.utls` и в ссылку как `fp=`; сервер его не использует.

### Сайт-заглушка

Протоколы с собственным доменом — `naive`, `anytls`, `trusttunnel`, `hysteria2`
и `vless` — объявляют команду `set_decoy_theme`. Она выбирает сайт, который
отдаётся на домене всем, кто не является клиентом:

```bash
sudo hydra plugin command hysteria2 set_decoy_theme --param theme=gallery
```

Доступные темы: `landing`, `blog`, `docs`, `media`, `status`, `portfolio`,
`shop`, `apidocs`, `conference`, `gallery`, `cafe`.

Содержимое сайта выводится из домена: название бренда, палитра, шрифт, тексты и
favicon у двух установок не совпадают, а повторная генерация того же домена
воспроизводима. Смена темы перегенерирует сайт и атомарно подменит каталог;
сайт, размещённый оператором вручную (без файла `.hydra-decoy.json`), не
трогается.

Клиентские ссылки получают параметр `extra` с изменёнными client-visible
значениями (`xPaddingBytes`, `scMaxEachPostBytes`, `scMaxBufferedPosts`,
`scStreamUpServerSecs`, `noSSEHeader`, `headers`); при значениях по умолчанию
ссылка остаётся прежней. Серверный `max_header_bytes` в ссылку не попадает.

`plugins` является алиасом `plugin`.

## Upgrade и удаление

```bash
hydra upgrade check
sudo hydra upgrade migrate-state

sudo hydra uninstall --dry-run
sudo hydra uninstall --yes
sudo hydra uninstall --yes --keep-data
```

`upgrade migrate-state` атомарно записывает pending state migrations и
идемпотентен на актуальной схеме.

`uninstall` требует явного `--yes`; `--keep-data` сохраняет state и журналы.
Перед удалением создайте backup и вынесите его за пределы VPS.

## AntiDPI

```bash
sudo hydra antidpi sync
sudo hydra antidpi selftest --full --wait 3
sudo hydra antidpi capture --seconds 180
```

Это расширенные операции диагностики и обслуживания. Детали scoring,
redaction, firewall и внешнего capture описаны в [ANTIDPI.md](ANTIDPI.md).

## Совместимость

Старые формы принимаются, но не показываются в основной справке:

| Старый синтаксис | Выполняется как |
| :--- | :--- |
| `validate` | `check` |
| `doctor` | `check` |
| `plan` | `check` |
| `reconcile` | `check` |
| `apply --dry-run` | `check` |
| `reconcile --apply` | `apply` |
| `config validate` / `config plan` | `check` |
| `runtime doctor` / `runtime reconcile` | `check` |
| `config apply` | `apply` |
| `runtime status` | `status` |
| `backup` | `backup create` |
| `restore ...` | `backup restore ...` |
| `system uninstall` | `uninstall` |

Таким образом, скрипты предыдущих релизов продолжают запускаться, но новые
скрипты должны использовать только `status`, `check` и `apply`.

## Форматы вывода и коды завершения

- `0` — команда выполнена успешно;
- `1` — preflight отрицательный либо операция завершилась ошибкой;
- `2` — синтаксическая ошибка.

В терминале ошибка показывается кратко:

```text
Command failed
root required
Code: host_operation
```

С `--json` и при перенаправлении stdout ошибки параметров возвращаются в
стабильном JSON-контракте, а не как произвольный текст argparse:

```json
{
  "ok": false,
  "error": "the following arguments are required: name",
  "error_details": {
    "code": "invalid_input",
    "message": "the following arguments are required: name",
    "retryable": false,
    "usage": "hydra plugin status NAME"
  }
}
```

Для автоматизации используйте `error_details.code` и
`error_details.retryable`. Секреты, credentials и приватные ключи в публичный
вывод не включаются.

### Стабильные коды ошибок

`error_details.code` — машинный контракт: набор значений фиксирован, а текст
`error` и `message` может меняться между версиями.

| Код | Причина | `retryable` |
| :--- | :--- | :---: |
| `invalid_input` | Некорректные параметры, данные или синтаксис команды | — |
| `host_operation` | Ограниченная команда или привилегированная операция хоста не удалась; сюда же попадает отсутствие `root` | ✔ |
| `configuration` | Конфигурация не прошла проверку или не была применена | — |
| `plugin` | Ошибка жизненного цикла плагина | — |
| `restore` | Архив не прошёл проверку или не может быть восстановлен безопасно | — |
| `conflict` | Отклонена устаревшая запись желаемого состояния | ✔ |
| `operation_failed` | Операция завершилась неуспехом без более узкой категории | ✔ |
| `internal` | Непредвиденная ошибка | — |

`retryable: true` означает, что повтор той же команды осмысленен: для `conflict`
нужно перечитать состояние и повторить, для `host_operation` — устранить причину
на хосте. Остальные коды требуют исправления входных данных или конфигурации.

При синтаксической ошибке в `error_details` дополнительно появляется поле
`usage` с ожидаемой формой команды.
