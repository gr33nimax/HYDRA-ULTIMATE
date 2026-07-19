# 🐉 HYDRA Headless CLI

Headless CLI — это JSON-интерфейс управления HYDRA без запуска интерактивного
TUI. Он предназначен для VPS, cron/systemd-задач, smoke-проверок и будущих
API-адаптеров.

```bash
sudo hydra <command> [options]
```

Команды чтения не должны менять состояние. Команды, влияющие на систему,
требуют `root`. Все результаты печатаются в stdout как JSON с UTF-8. При
ошибке команда возвращает ненулевой exit code и объект `error_details`.

## 🧭 Безопасный рабочий цикл

Перед изменением конфигурации рекомендуется выполнять команды в таком порядке:

```bash
sudo hydra backup --output /root/hydra-before-change.tar.gz
sudo hydra validate
sudo hydra doctor
sudo hydra plan
sudo hydra apply
sudo hydra doctor
```

`plan` и `apply --dry-run` не применяют конфигурацию. Если preflight показывает
ошибку `tls_mux`, сначала проверьте домены и сертификаты, затем повторите
`sudo hydra apply`: команда пересоберёт Caddy L4 из актуального state.

## 📋 Команды диагностики

### `status`

Показывает JSON-снимок системы:

```bash
sudo hydra status
```

Основные поля:

- `version`, `users` — версия state и число пользователей;
- `network` — сохранённые и эффективные сетевые флаги;
- `plugins` — installed/enabled/running/health каждого плагина;
- `runtime` — runtime-состояние и drift;
- `tls_mux` — аудит Caddy SNI-маршрутов.

`tls_mux.ok: false` означает, что мультиплексор требует внимания. Поля
`missing`, `stale`, `certificate_errors` и `errors` показывают причину.

### `validate`

Проверяет только сохранённый state и его schema:

```bash
sudo hydra validate
```

Команда не проверяет, запущены ли сервисы, и не пересобирает конфигурации.

### `doctor`

Read-only проверка готовности VPS, зависимостей, state и runtime drift:

```bash
sudo hydra doctor
```

Важные поля:

- `ok` — нет обязательных отказов;
- `required_failures` — проверки, блокирующие доверенное состояние;
- `warnings` — необязательные компоненты;
- `checks` — Python, systemd, инструменты, каталог state и `caddy_routes`;
- `reconciliation.planned` — безопасные операции для исправления runtime drift.

Для включённых TLS-маршрутов проверка `caddy_routes` обязательна. Она читает
конфиг и проверяет сервис, но не выполняет перезапуск.

### `plan`

Строит side-effect-free план применения:

```bash
sudo hydra plan
```

План включает:

- конфликты конфигурации Sing-Box;
- активные плагины и их зависимости;
- число inbounds/outbounds/route rules;
- безопасный план runtime reconciliation;
- текущий аудит `tls_mux`.

План не равен гарантии успешного применения: состояние сервера может измениться
между `plan` и `apply`, поэтому после применения следует повторить `doctor`.

### `reconcile`

Показывает обнаруженный drift без изменений:

```bash
sudo hydra reconcile
```

Флаг `--apply` применяет только безопасные операции enable/disable:

```bash
sudo hydra reconcile --apply
```

Команда не устанавливает отсутствующие пакеты, не чинит неизвестное состояние и
не пересобирает автоматически Caddy. Для конфигурационного drift используйте
`hydra apply` после проверки `hydra plan`.

### `upgrade check`

Проверяет готовность к обновлению:

```bash
sudo hydra upgrade check
```

Проверяются state schema, Python, наличие локальных изменений в Git worktree и
текущая версия HYDRA. Поле `backup_required` всегда напоминает сделать backup.

## 🔧 Команды применения и восстановления

### `apply`

Применяет текущий state к VPS:

```bash
sudo hydra apply
```

Внутри команда генерирует Sing-Box, применяет nftables/TPROXY, вызывает
включённые плагины, перезагружает Sing-Box, пересобирает Caddy L4 при
необходимости, управляет traffic daemon и выполняет health-check.

Операция транзакционная: при критическом сбое HYDRA пытается восстановить state,
конфигурации, firewall и плагины. Повторный запуск после исправления причины
является штатным сценарием.

Для просмотра плана без изменений:

```bash
sudo hydra apply --dry-run
```

### `backup`

Создаёт архив state и известных конфигураций сервисов:

```bash
sudo hydra backup
sudo hydra backup --output /root/hydra-before-change.tar.gz
```

Если `--output` указывает существующий каталог, архив создаётся внутри него.
Если указан существующий файл, команда завершается ошибкой и не перезаписывает
его. Архив содержит manifest и SHA-256 файлов; права на POSIX-системах
ограничиваются `0600`.

### `restore`

Сначала проверяйте архив без изменений:

```bash
sudo hydra restore /root/hydra-before-change.tar.gz --dry-run
```

Фактическое восстановление требует явного `--yes`:

```bash
sudo hydra restore /root/hydra-before-change.tar.gz --yes
sudo hydra validate
sudo hydra apply
```

Перед восстановлением HYDRA автоматически создаёт страховочную копию. Пути,
симлинки, path traversal и файлы вне разрешённых каталогов отклоняются.

## 👤 Пользователи

### Просмотр

```bash
sudo hydra user list
```

Секретные `credentials` в безопасный список не попадают; вместо них выводится
список доступных протоколов.

### Добавление

```bash
sudo hydra user add test
sudo hydra user add test@example.com --traffic-limit-gb 100 --expiry-date 2026-12-31
```

Идентификатор может быть обычным именем или email. UUID генерируется автоматически
и сохраняется для стабильности конфигураций. Можно передать свой UUID:

```bash
sudo hydra user add test --uuid 00000000-0000-0000-0000-000000000001
```

Добавление пользователя — транзакция: hooks включённых транспортов, state и
конфигурация откатываются, если применение не удалось.

### Блокировка и удаление

```bash
sudo hydra user block test
sudo hydra user unblock test
sudo hydra user remove test
```

Операции немедленно обновляют конфигурации включённых транспортов и откатываются
при ошибке применения.

## 🚦 Exit codes и ошибки

- `0` — команда выполнена успешно;
- `1` — ошибка валидации, host-операции, конфигурации или plugin lifecycle;
- ненулевой код также используется для ошибок аргументов `argparse`.

Пример структурированной ошибки:

```json
{
  "ok": false,
  "error": "configuration apply failed",
  "error_details": {
    "code": "operation_failed",
    "message": "configuration apply failed",
    "retryable": true
  }
}
```

Не парсите только текст `error`: для автоматизации используйте `error_details`,
но сохраняйте fallback на `error` для совместимости со старыми интеграциями.

## 🧯 Частые сценарии восстановления

### Caddy показывает старый домен

```bash
sudo hydra doctor
sudo hydra plan
sudo hydra apply
sudo hydra doctor
```

Ищите `tls_mux.missing` и `tls_mux.stale`. Если ошибка остаётся, отдельно
проверьте `systemctl status caddy-l4`, сертификат и DNS домена.

### Сервис включён, но status показывает drift

```bash
sudo hydra reconcile
sudo hydra reconcile --apply
sudo hydra doctor
```

Для `missing` и `unknown` не выполняется опасная автоматическая установка —
сначала исправьте зависимость или lifecycle вручную.

### Применение завершилось ошибкой

```bash
sudo hydra doctor
sudo hydra status
sudo journalctl -u sing-box -u caddy-l4 --no-pager -n 100
sudo hydra apply
```

Если конфигурация повреждена, используйте `restore --dry-run`, затем
`restore --yes`, `validate` и повторное `apply`.

