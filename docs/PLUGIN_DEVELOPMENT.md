# Расширение HYDRA

Этот документ фиксирует поддерживаемый путь добавления протокола, inbound или
plugin-owned функции. Новый код не должен регистрировать себя через глобальные
переменные и не должен импортировать TUI, Telegram или другой адаптер.

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

`PluginMeta` является единственным декларативным описанием возможностей:

- `commands` — изменяющие persisted-конфигурацию команды;
- `queries` — безопасные проекции и клиентские профили;
- `actions` — runtime-операции, которые не требуют общего `apply`;
- `tls_domain_source` и `config_defaults` — подготовка при включении;
- `subscription_profile_query` и `subscription_enabled` — участие в подписках;
- `display_name` — человекочитаемое имя во всех общих адаптерах;
- `connection_source` — источник активных подключений: общий tracker,
  plugin query или отсутствие такой проекции;
- `maintenance_tasks` — фоновые задачи общего scheduler без ветвлений по имени
  плагина;
- `backup_resources` — точные файлы и каталоги, которыми владеет плагин и
  которые разрешено включать в backup/restore;
- `required_commands`, `required_services` и `conflicts_with` — preflight.

Встроенная фабрика добавляется в `BUILTIN_PLUGIN_FACTORIES`. Внешняя интеграция
передаёт фабрику через `default_plugins(extra_factories=...)` либо напрямую
создаёт `PluginContainer`. `PluginContainer` проверяет уникальность имён и весь
контракт до запуска приложения.

Запрещено добавлять отдельные центральные таблицы команд, запросов или действий,
ветвления `if plugin.meta.name == ...` в общих сервисах и импорт
`hydra.plugins.registry` в production-код.

## Новый или кастомный inbound

Inbound принадлежит плагину и возвращается из `configure()` внутри
`ConfigFragment.inbounds`. В тот же фрагмент можно добавить:

- `outbounds`;
- `route_rules`;
- `endpoints`;
- `dns`;
- `nft_tproxy_ports` и `nft_tproxy_ifaces`.

Перед записью все значения проверяются как JSON, порты проверяются по диапазону,
а общий planner проверяет конфликтующие слушатели. Плагин не должен сам
редактировать итоговый `config.json` Sing-box.

Обычный inbound на собственном TCP/UDP-порту не требует изменений в ядре.
Если новый транспорт должен разделять TCP/443 с другими TLS-протоколами, ему
нужен явный адаптер политики SNI/TLS-маршрутизации. Для UDP/443 автоматического
мультиплексирования нет: порт может принадлежать только одному QUIC-транспорту.
Это ограничение сетевой модели, а не причина добавлять проверки имени плагина в
общие сервисы.

Если Sing-box передаёт имя пользователя в `metadata.user`, учёт трафика нового
протокола работает без изменений демона. Для нестандартной аутентификации
добавляется `UserResolver` в `ConnectionAttributor`; accounting loop при этом
не меняется.

## UI, Telegram и будущий HTTP API

Адаптеры вызывают только `ApplicationService`:

- lifecycle — `app.protocols`;
- изменение plugin state — `app.plugin_command`;
- чтение — `app.plugin_query`;
- runtime-действие — `app.plugin_action`;
- привилегированные операции — соответствующий application port.

Бизнес-логика не должна дублироваться в адаптере. Благодаря этому один и тот же
use-case доступен TUI, Telegram и будущему HTTP API.

Persisted state содержит монотонную `revision`. Запись устаревшей желаемой
конфигурации отклоняется как retryable conflict, поэтому HTTP API должен
передавать конфликт клиенту и предлагать перечитать состояние. Фоновые
счётчики и курсоры изменяются через атомарный `update_state` и не создают
ложных конфликтов с настройками.

Пользовательский CRUD произвольных inbound’ов не является частью plugin API:
для него нужен отдельный типизированный `InboundDefinition`, валидация,
application service и UI/API. При этом его исполнение должно пользоваться тем
же `ConfigFragment` и общей проверкой конфликтов слушателей.

## Обязательные проверки

Для расширения нужны:

1. unit-тест `configure()` и валидации `ConfigFragment`;
2. lifecycle rollback-тест;
3. тест metadata-driven command/query/action, если они объявлены;
4. тест клиентской ссылки или профиля, если поддерживается подписка;
5. тест traffic attribution, если используется нестандартный resolver;
6. тест scheduler-задачи и backup-policy, если они объявлены;
7. `ruff check .`, полный `pytest` и архитектурные тесты.

Новые compatibility-фасады допустимы только для уже существующего публичного
импорта. Новый код должен сразу зависеть от канонического модуля.
