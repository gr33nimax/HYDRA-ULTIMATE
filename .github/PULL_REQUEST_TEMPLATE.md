## Описание изменений

Что изменено и зачем?

## Тип изменения

- [ ] Исправление бага
- [ ] Новая функция
- [ ] Улучшение существующей функции
- [ ] Изменение документации

## Тестирование

Как проверено?

- [ ] `python verify.py` — compile, lint и все тесты прошли
- [ ] Добавлены тесты на изменённое поведение (happy path и путь отказа)
- [ ] Проверено на Ubuntu 22.04 или Debian 12
- [ ] Проверено на реальной VPS

## Чек-лист

- [ ] Изменение внесено в канонический модуль, а не в compatibility-фасад
- [ ] UI, CLI и Telegram не обходят `ApplicationService`
- [ ] Привилегированные операции идут через `HostBackend`
- [ ] Изменение схемы state сопровождается миграцией `vN → vN+1` и тестами
- [ ] Обновлены `docs/` и `CHANGELOG.md`, если изменилось публичное поведение
- [ ] В diff нет секретов, артефактов сборки и несвязанных правок

## Promotion record (только для `debug → dev`, `dev → main` и release)

- [ ] Источник: `<branch> @ <40-char SHA>`
- [ ] Цель: `dev` или `main`; emergency-исключение описано, если `dev` пропущен
- [ ] Проверки: CI, Linux integration и относящиеся compatibility checks — green
- [ ] Canary: VPS, результат и версия Hydracore указаны
- [ ] Rollback: предыдущий проверенный tag/SHA указан
- [ ] Release notes содержат source SHA, compatibility pair и rollback target
