# Tasks: устойчивость установки HYDRA на Debian

Spec: `./requirements.md` (R1–R7, KNOWN-RED). Ветка: `debug` (потом мердж).

## Progress

| State | Count | Evidence |
| --- | ---: | --- |
| Not started | 2 | TSK-004, TSK-005 |
| In progress | 0 | — |
| Complete | 4 | TSK-001 … TSK-003, TSK-006 |

## Tasks

- [x] **TSK-001 — чистая установка не требует TPROXY, когда маршрутизировать нечего**
  - **Факт:** `hydra/core/nft.py::apply_tproxy` проверяет набор tproxy-портов/интерфейсов до
    любой работы с хостом: при пустом наборе `modprobe` и `nft` не вызываются вовсе (при
    наличии `nft` таблица HYDRA по-прежнему снимается); `_ensure_tproxy_modules` теперь
    проверяет наличие `nft` и переводит отказ `modprobe` в человеческий текст про хост без
    TPROXY. Регрессии: `tests/test_nft_transaction.py` (4 новых теста: пустой набор без
    `nft`/`modprobe`, пустой набор со снятием таблицы, проверка хоста до действий,
    сообщение про ограничение ядра). `pytest tests/test_nft_transaction.py
    tests/test_orchestrator.py` → 36 passed; `verify.py` → **2020 passed**.
  - _Requirements: R4, R7._

- [x] **TSK-002 — nftables ставится установщиком, а отказ применения видно**
  - **Факт:** `bootstrap.sh` — в список пакетов добавлен `nftables` (без него apply падал на
    минимальных образах); шаг создания первого пользователя больше не прячет причину:
    вывод команды пишется в журнал, при неудаче печатается целиком и установка
    останавливается с внятным текстом вместо «строка N». `bash -n bootstrap.sh` → ok.
  - _Requirements: R2, R7._

- [x] **TSK-003 — требования к ОС, таймаут certbot, LF для скриптов**
  - **Факт:** `README.md` называет Debian 12+ / Ubuntu 22.04+ (Python 3.10+), гейт
    `bootstrap.sh` при отказе объясняет, какие версии подходят; certbot в
    `hydra/services/admin_infrastructure.py` получил `timeout=180` вместо общего 30-секундного
    (в продукте он же стоит в `certificates.py`); добавлен `.gitattributes`
    (`*.sh text eol=lf`) — Windows-чекаут держал CRLF в скриптах, из-за чего shellcheck
    показывал «literal carriage return» в каждой строке нетронутых файлов.
  - _Requirements: R1, R3._

- [ ] **TSK-004 — предпроверка TPROXY до активации транспорта**
  - Сейчас отказ приходит на шаге apply с понятным текстом, но всё ещё после попытки
    активировать транспорт. Нужна проверка на этапе `plan`/`check` для транспортов, которым
    TPROXY нужен.
  - _Requirements: R4._

- [ ] **TSK-005 — загрузки переживают медленную сеть**
  - Go всегда качается с go.dev в `/tmp` под таймаутом 120 с, без повторов и проверки места;
    фолбэк `go install xcaddy@latest` не проверяется. Сообщения сборки Caddy — по-английски.
  - _Requirements: R5._

- [x] **TSK-006 — bootstrap переживает обрыв SSH**
  - **Факт:** в `bootstrap.sh` добавлены ловушки `HUP`/`INT`/`TERM`: прерывание выполняет
    ту же очистку, что и ошибка (возврат checkout к предыдущей проверенной ревизии и
    восстановление прежнего каталога — вынесено в `restore_previous_installation`, чтобы
    пути не расходились), затем печатает, что установка прервана и что повтор команды
    продолжит её. Раньше обрыв SSH убивал установщик молча посреди pip/скачивания.
    `bash -n bootstrap.sh` → OK; файл без CR (LF закреплён в `.gitattributes`).
  - _Requirements: R6._
