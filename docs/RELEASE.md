# Каналы и выпуск HYDRA

## Каналы

| Канал | Назначение | Что разрешено |
| --- | --- | --- |
| `debug` | активная разработка и изолированные тестовые VPS | экспериментальные изменения и debug-обновления |
| `dev` | кандидат в релиз | интеграционная проверка и canary VPS |
| `main` | источник production-релиза | только проверенные promotion из `dev` |

Ветка — это источник конкретного commit, а не runtime-артефакт. `updater.sh`
под блокировкой разрешает SHA выбранной ветки и устанавливает именно его. В
официальной установке TUI показывает версию HYDRA, канал и короткий SHA; если
stamp отсутствует, сборка честно помечается `local`.

## Promotion

1. Откройте PR `debug → dev`; дождитесь матрицы Python, dependency audit и Linux
   integration.
2. На `dev` выполните upgrade smoke и canary на одной VPS. Запишите SHA, версию
   Hydracore, результат проверки и предыдущий rollback tag.
3. Откройте PR `dev → main`. В него попадает только тот SHA, который прошёл
   canary; экстренное исключение должно быть явно объяснено в PR.
4. После merge в `main` создайте тег и GitHub Release. Сначала обновите одну
   canary VPS, затем расширяйте rollout.

Никогда не публикуйте stable-релиз из `debug` и не меняйте running VPS через
`git pull`.

## GitHub branch protection

В GitHub включите required pull request и запрет прямого push для `dev` и
`main`. Required checks: `tests-matrix`, `dependency-audit` и
`linux-host-smoke`. Для `dev` дополнительно приложите результат его push-only
upgrade smoke; для `main` — ссылку на green canary из `dev`. Эти настройки
живут в GitHub repository settings и не могут быть надёжно заменены YAML в
репозитории.

## Release record

Каждый promotion PR и GitHub Release содержит:

```text
Product/target: HYDRA → dev | main
Source: <branch> @ <40-char SHA>
Artifact: <tag or installed SHA>
Compatibility: Hydracore <tag>; HydraBox <SHA, if applicable>
Checks: <green CI and smoke evidence>
Canary: <VPS/result>
Rollback: <previous known-good tag/SHA>
```

Если изменение затрагивает state, firewall, service lifecycle, подписки или
контракт ядра, без успешного rollback rehearsal broad rollout запрещён.
