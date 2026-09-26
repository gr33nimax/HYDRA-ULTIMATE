# Разработка плагинов

Документ фиксирует поддерживаемый путь добавления протокола, inbound или
plugin-owned функции.

**Два жёстких правила.** Новый код не регистрирует себя через глобальные
переменные и не импортирует TUI, Telegram или другой адаптер. Всё остальное
следует из архитектурных инвариантов, описанных в
[ARCHITECTURE.md](ARCHITECTURE.md).

## Содержание

- [Новый протокол](#новый-протокол)
- [Декларация возможностей](#декларация-возможностей)
- [Новый или кастомный inbound](#новый-или-кастомный-inbound)
- [Адаптеры: UI, Telegram и будущий HTTP API](#адаптеры-ui-telegram-и-будущий-http-api)
- [Обязательные проверки](#обязательные-проверки)
- [Чего делать нельзя](#чего-делать-нельзя)

## Новый протокол

Минимальное расширение состоит из класса `BasePlugin` и фабрики:

```python
from hydra.contracts import BackupResource, ConfigFragment
from hydra.plugins.base import (
    BasePlugin,
    MaintenanceTask,
    PluginMeta,
    PluginStatus,
)


class ExamplePlugin(BasePlugin):
    meta = PluginMeta(
        name="example",
        display_name="Example Transport",
        description="Example transport",
        commands=("set_mode",),
        queries=("client_profile",),
        actions=("rotate_keys",),
        config_defaults=(("mode", "safe"),),
        subscription_profile_query="client_profile",
        connection_source="tracked",
        maintenance_tasks=(
            MaintenanceTask(
                action="refresh_rules",
                due_query="rules_update_due",
                title="Refresh Example rules",
                enabled_flag="sync_example_enabled",
                apply_on_success=True,
            ),
        ),
        backup_resources=(
            BackupResource("/etc/example", "tree"),
            BackupResource("/etc/systemd/system/example.service", "file"),
        ),
    )

    def install(self) -> bool:
        return True

    def uninstall(self) -> bool:
        return True

    def status(self, state=None) -> PluginStatus:
        ...

    def configure(self, state) -> ConfigFragment:
        return ConfigFragment(
            inbounds=[
                {
                    "type": "example",
                    "tag": "example-in",
                    "listen": "::",
                    "listen_port": 10443,
                },
            ],
        )
```

Встроенная фабрика добавляется в `BUILTIN_PLUGIN_FACTORIES`. Внешняя интеграция
передаёт фабрику через `default_plugins(extra_factories=...)` либо напрямую
создаёт `PluginContainer`. Контейнер проверяет уникальность имён и весь контракт
до запуска приложения.

### Жизненный цикл

```text
   не установлен
        │
        │  plugin install ──▶ install()
        ▼
   установлен, выключен
        │
        │  plugin enable ───▶ config_defaults, tls_domain_source
        ▼
   включён ──────────────────────────────────────────────┐
        │                                               │
        │  общий apply:                                  │  plugin disable
        │     configure() ──▶ ConfigFragment             │       │
        │     apply()     ──▶ применение на хосте        │       ▼
        │     health()    ──▶ подтверждение              │  установлен,
        │                                                │  выключен
        │  сбой любого шага ──▶ rollback к предыдущему    │       │
        │                      состоянию                 │       │
        └────────────────────────────────────────────────┘       │
                                                                 │
   plugin uninstall ──▶ uninstall() ◀────────────────────────────┘
        │
        ▼
   не установлен
```

Каждый переход выполняется прикладной службой в транзакции: плагин сообщает
результат, но не решает, сохранять ли state.

### Разделение обязанностей внутри плагина

| Механизм | Что делает | Чего не делает |
| :--- | :--- | :--- |
| `command` | Изменяет желаемую конфигурацию плагина | Не сохраняет state и не выполняет общий `apply` — это делает прикладная служба |
| `query` | Read-only проекция, клиентский профиль | Не мутирует state и не меняет runtime |
| `action` | Явная runtime-операция | Не требует общего `apply` |
| `lifecycle` | `install` / `uninstall` / `enable` / `disable` | Не вызывает цепочкой другие lifecycle hooks |
| `configure` | Готовит `ConfigFragment` | Не редактирует итоговый `config.json` Sing-Box |
| `apply` | Применяет подготовленное | — |
| `health` | Подтверждает работоспособность | — |
| `traffic_snapshot` / `traffic_source_reason` | Read-only счётчики и причина их недоступности | Не выдумывает числа: `None` и непустая причина означают «источник недоступен», накопленные значения сохраняются |

Не перечитывайте state внутри state-aware метода — кроме явного fallback при
`state is None`.

## Декларация возможностей

`PluginMeta` — единственное декларативное описание возможностей плагина.

| Поле | Назначение |
| :--- | :--- |
| `category` | `transport`, `enhancement` или `security` — группировка в инвентаре |
| `commands` | Изменяющие persisted-конфигурацию команды |
| `persist_only_commands` | Подмножество `commands`, которому нужна атомарная запись state без runtime `apply` |
| `queries` | Безопасные проекции и клиентские профили |
| `actions` | Runtime-операции, не требующие общего `apply` |
| `tls_domain_source`, `config_defaults` | Подготовка при включении |
| `subscription_profile_query`, `subscription_enabled` | Участие в legacy/обычных подписках |
| `hydra_v2_subscription_enabled` | Отдельное участие в Hydra Subscription v2; при `None` наследует `subscription_enabled` |
| `display_name` | Человекочитаемое имя во всех общих адаптерах |
| `connection_source` | Источник активных подключений: общий tracker, plugin query или отсутствие проекции |
| `maintenance_tasks` | Фоновые задачи общего scheduler без ветвлений по имени плагина |
| `backup_resources` | Точные файлы и каталоги, которые разрешено включать в backup/restore |
| `required_commands`, `required_services`, `conflicts_with` | Preflight |
| `needs_domain` | Плагину требуется домен; включение запрашивает его и участвует в TLS-preflight |
| `central_apply` | `False` исключает плагин из общего `apply` — он владеет своим жизненным циклом (так работает Honeypot) |
| `contract_version` | Явная версия контракта, проверяемая `PluginInvoker` |

`generate_client_config(user, state)` возвращает нативный клиентский формат
плагина. Если это не полный Sing-Box JSON, переопределите
`generate_singbox_client_config(user, state)` для `?format=singbox` (по умолчанию
он делегирует в `generate_client_config`). Проекция может содержать
`outbounds`, `endpoints` и `route`; subscription service объединяет их без
ветвлений по имени плагина.

## Новый или кастомный inbound

Inbound принадлежит плагину и возвращается из `configure()` внутри
`ConfigFragment.inbounds`. В тот же фрагмент можно добавить:

- `outbounds`;
- `route_rules`;
- `endpoints`;
- `dns`;
- `nft_tproxy_ports` и `nft_tproxy_ifaces`.

Перед записью все значения проверяются как JSON, порты проверяются по диапазону,
а общий planner проверяет конфликтующие слушатели.

**Обычный inbound на собственном TCP/UDP-порту не требует изменений в ядре.**

Если новый транспорт должен разделять TCP/443 с другими TLS-протоколами, ему
нужен явный адаптер политики SNI/TLS-маршрутизации. Для UDP/443 автоматического
мультиплексирования нет: порт может принадлежать только одному QUIC-транспорту.
Это ограничение сетевой модели, а не причина добавлять проверки имени плагина в
общие сервисы.

### Учёт трафика

Если Sing-Box передаёт имя пользователя в `metadata.user`, учёт трафика нового
протокола работает без изменений демона. Для нестандартной аутентификации
добавляется `UserResolver` в `ConnectionAttributor`; accounting loop при этом не
меняется.

## Адаптеры: UI, Telegram и будущий HTTP API

Адаптеры вызывают только `ApplicationService`:

| Задача | Вызов |
| :--- | :--- |
| Lifecycle | `app.protocols` |
| Изменение plugin state | `app.plugin_command` |
| Чтение | `app.plugin_query` |
| Runtime-действие | `app.plugin_action` |
| Привилегированные операции | Соответствующий application port |

Бизнес-логика не дублируется в адаптере. Благодаря этому один и тот же use-case
доступен TUI, Telegram и будущему HTTP API. Модель конкурентной записи
state (монотонная `revision`, retryable conflict) описана в
[ARCHITECTURE.md](ARCHITECTURE.md).

## Обязательные проверки

Для расширения нужны:

1. unit-тест `configure()` и валидации `ConfigFragment`;
2. lifecycle rollback-тест;
3. тест metadata-driven command/query/action, если они объявлены;
4. тест клиентской ссылки или профиля, если поддерживается подписка;
5. тест traffic attribution, если используется нестандартный resolver;
6. тест scheduler-задачи и backup-policy, если они объявлены;
7. `ruff check main.py hydra tests`, полный `pytest` и архитектурные тесты.

```bash
python verify.py                            # compile + lint + полный pytest
python -m pytest -q                         # только тесты
python -m ruff check main.py hydra tests    # только линтер
python -m compileall -q main.py hydra       # только компиляция
```

Тесты — часть архитектуры: они удерживают направление зависимостей, лимиты
размеров и запрет обхода `ApplicationService`/`HostBackend`. Ослаблять guard,
чтобы «починить тест», нельзя — сначала должно измениться само решение.

CI дополнительно проверяет Python 3.10–3.13, зависимости (`pip-audit`), миграции
состояния, Linux-сценарий с root/systemd/nftables и обновление `main → dev`.

## Чего делать нельзя

- Добавлять центральные таблицы команд, запросов или действий.
- Писать `if plugin.meta.name == ...` в общих сервисах.
- Добавлять новые импорты `hydra.plugins.registry` в production-код (фасад сохранён
  ради совместимости; зависить от канонического модуля).
- Создавать новый глобальный singleton или process-global `ApplicationService`.
- Мутировать желаемое состояние из query, render или lifecycle hooks.
- Редактировать итоговый `config.json` Sing-Box из плагина.

Новые compatibility-фасады допустимы только для уже существующего публичного
импорта. Новый код должен сразу зависеть от канонического модуля.
