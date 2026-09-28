# Документация HYDRA

| Задача | Документ |
| :--- | :--- |
| Установить на чистую VPS или обновить рабочую | [UPGRADE.md](UPGRADE.md) |
| Управлять сервером из скриптов и cron | [CLI.md](CLI.md) |
| Найти путь, порт, службу или файл состояния | [REFERENCE.md](REFERENCE.md) |
| Понять устройство системы и её инварианты | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Настроить обнаружение сканирования и баны | [ANTIDPI.md](ANTIDPI.md) |
| Проверить, понимает ли транспорт целевой клиент | [COMPATIBILITY.md](COMPATIBILITY.md) |
| Настроить администрирование из Telegram | [TELEGRAM_BOT.md](TELEGRAM_BOT.md) |
| Добавить протокол, inbound или плагин | [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) |
| Продвинуть релиз `debug → dev → main` | [RELEASE.md](RELEASE.md) |
| Вести работу в репозитории coding-агентом | [AGENT_PLAYBOOK.md](AGENT_PLAYBOOK.md) |
| Узнать, что изменилось в релизе | [../CHANGELOG.md](../CHANGELOG.md) |

Значения портов и путей в документации — заводские по умолчанию; фактические
хранятся в state и видны в `hydra status`. Блоки `[!WARNING]` / `[!CAUTION]`
отмечают операции, способные привести к потере доступа или данных. При
расхождении документации с кодом источник истины — код и тесты.
