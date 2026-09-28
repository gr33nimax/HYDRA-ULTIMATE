# Каналы и выпуск HYDRA

## Каналы

| Канал | Назначение | Что разрешено |
| --- | --- | --- |
| `debug` | активная разработка и изолированные тестовые VPS | экспериментальные изменения и debug-обновления |
| `dev` | кандидат в релиз | интеграционная проверка и canary VPS |
| `main` | источник production-релиза | только проверенные promotion из `dev` |

`updater.sh` под блокировкой разрешает SHA выбранной ветки и ставит именно его. В
официальной установке TUI показывает версию, канал и короткий SHA; без stamp
сборка помечается `local`.

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

> [!IMPORTANT]
> Если изменение затрагивает state, firewall, service lifecycle, подписки или
> контракт ядра — broad rollout запрещён без успешного rollback rehearsal.

## GitHub branch protection

Включите required pull request и запрет прямого push для `dev` и `main`.
Required checks: `tests-matrix`, `dependency-audit`, `linux-host-smoke`. Для
`dev` дополнительно приложите результат push-only upgrade smoke, для `main` —
ссылку на green canary из `dev`.

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
