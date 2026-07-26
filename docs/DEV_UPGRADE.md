# Обновление рабочей VPS с `main` на `dev`

Этот документ описывает поддерживаемый переход с HYDRA 2.5.3 из ветки
`main` на HYDRA 2.5.4 из ветки `dev`. Для существующей установки используется
`upgrade.sh`; `bootstrap.sh` предназначен для чистой установки.

## Что гарантирует updater

Обновление выполняется как транзакция:

1. Под блокировкой определяется точный SHA ветки `dev`.
2. Новый release и новое `.venv` собираются отдельно от `/opt/hydra`.
3. Новый код читает действующий state и выполняет `upgrade check`, `validate`
   и `plan` без записи.
4. Запоминаются активные `hydra-*.service` и `hydra-*.timer`, после чего
   HYDRA-процессы временно останавливаются.
5. Сохраняются сырой `/var/lib/hydra`, wrapper команды `hydra` и проверенный
   backup с манифестом и SHA-256.
6. State атомарно мигрирует со схемы 3 на схему 4. Лимиты и отпечатки
   устройств, пользовательские credentials, Telegram-токены, сетевые секреты
   и настройки плагинов сохраняются.
7. `/opt/hydra` переключается на подготовленный release, а ранее активные
   службы запускаются снова.
8. Выполняются повторные `validate`, `plan`, `status` и проверка systemd.

При ошибке после остановки служб updater восстанавливает данные, старый код,
старый wrapper и только затем запускает прежний набор служб. Старый release и
backup не удаляются после успешного обновления.

## Перед запуском

- VPS должна работать на Ubuntu или Debian с systemd.
- Установка должна находиться в `/opt/hydra`.
- Нужны права `root`, доступ к GitHub и свободное место для второго release и
  отдельного виртуального окружения.
- В установленном Git checkout не должно быть локальных изменений. Updater
  намеренно завершится с ошибкой, если они есть.
- Не запускайте одновременно TUI, CLI-команды изменения конфигурации или второй
  updater.

Проверка текущей установки:

```bash
sudo hydra validate
sudo hydra upgrade check
sudo git -C /opt/hydra status --short
```

Последняя команда не должна ничего вывести.

## Запуск

```bash
(
  set -e
  upgrade_script=$(mktemp)
  trap 'rm -f "$upgrade_script"' EXIT
  curl -fsSL \
    https://raw.githubusercontent.com/gr33nimax/HYDRA-ULTIMATE/dev/upgrade.sh \
    -o "$upgrade_script"
  sudo env HYDRA_REF=dev bash "$upgrade_script"
)
```

Updater разрешает SHA ветки один раз и устанавливает именно этот commit, даже
если ветка сдвинется во время загрузки.

Поддерживаемые переменные:

| Переменная | Значение по умолчанию | Назначение |
| :--- | :--- | :--- |
| `HYDRA_REF` | `dev` | Ветка, чей точный SHA нужно установить. |
| `HYDRA_REPO_URL` | официальный GitHub-репозиторий | Git remote. |
| `HYDRA_INSTALL_DIR` | `/opt/hydra` | Стабильная точка входа установки. |
| `HYDRA_RELEASES_DIR` | `/opt/hydra-releases` | Каталог изолированных release. |
| `HYDRA_UPGRADE_BACKUP_DIR` | `/var/backups/hydra/upgrades` | Постоянные снимки отката. |

## Проверка результата

```bash
sudo hydra validate
sudo hydra plan
sudo hydra status
sudo systemctl --failed --no-pager
readlink -f /opt/hydra
```

Лог обновления находится в `/var/log/hydra/upgrade.log`. Каталог снимка
печатается в последней строке updater и содержит:

- `metadata.env` с исходным и целевым SHA;
- `state-before-upgrade/`;
- `hydra-backup.tar.gz` и результат его проверки;
- JSON preflight, миграции и post-cutover проверок;
- `active-units.txt`;
- маркер `SUCCESS` после полного завершения.

Кратковременно останавливаются HYDRA-службы и таймеры. Sing-box и внешние
прокси-бинарники updater напрямую не заменяет; длительность паузы в основном
зависит от запуска ранее активных HYDRA helper-сервисов.

## Если обновление завершилось ошибкой

Не запускайте поверх ошибки `bootstrap.sh` и не делайте `git reset --hard`.
Сначала проверьте:

```bash
sudo tail -n 200 /var/log/hydra/upgrade.log
sudo systemctl --failed --no-pager
sudo hydra validate
```

Обычная ошибка приводит к автоматическому откату. В каталоге снимка при этом
остаются новый неудачный release, state после сбоя и исходный state. Если
автоматический откат не смог вернуть службу, не удаляйте эти артефакты:
восстановление должно идти в порядке «остановить HYDRA-службы → вернуть
`state-before-upgrade` → вернуть прежний `/opt/hydra` и wrapper → выполнить
`systemctl daemon-reload` → запустить службы из `active-units.txt`».

После успешного обновления не удаляйте последний снимок до завершения
проверки реального трафика и подписок.

## Для разработчиков

В 2.5.4 persisted state имеет схему 4. Миграцию отдельно выполняет:

```bash
sudo hydra upgrade migrate-state
```

Команда нужна updater и аварийным процедурам. В обычной эксплуатации вызывайте
её только при остановленных HYDRA-процессах и наличии проверенного backup.
Миграция идемпотентна: повторный вызов на схеме 4 не переписывает state.
