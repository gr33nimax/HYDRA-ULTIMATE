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
- аудит TLS/SNI-маршрутов.

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
hydra plugin query warp external_sources --with-state
sudo hydra plugin action dnscrypt apply_server_names \
  --param 'names=["cloudflare","quad9-dnscrypt-ip4-filter-pri"]'
```

`--param NAME=JSON` можно повторять. Операция должна быть объявлена в
`PluginMeta.commands`, `queries` или `actions`; произвольные методы вызвать
нельзя. Command/action требуют root, query является read-only.

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
