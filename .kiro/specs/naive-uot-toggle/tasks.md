# Tasks: opt-out for Naive UoT (UDP over TCP)

Spec: `./requirements.md`, `./design.md` (D1–D9).

## Progress

| State | Count | Evidence |
| --- | ---: | --- |
| Not started | 0 | — |
| In progress | 0 | — |
| Blocked | 1 | TSK-007 needs a disposable Linux host or CI evidence |
| Complete | 6 | TSK-001 … TSK-006 |

## Dependency graph

```text
TSK-001 ─> TSK-002 ─> TSK-003 ─> TSK-004 ─┬─> TSK-005
                                          └─> TSK-006
TSK-007 (live Linux verification) is the release gate for the whole feature.
```

## Tasks

- [x] **TSK-001 — setting and command**
  - **Факт:** `commands` содержит `set_uot`, `config_defaults` — `("uot", True)`; `set_uot` читает `"on"/"off"/"1"/"0"` и отказывает остальному. `tests/test_naive_plugin.py::test_set_uot_validates_and_persists`.
  - Add `("uot", True)` to `NaivePlugin.meta.config_defaults`, allowlist `set_uot` in
    `commands`, and implement `set_uot(state, uot)` with strict validation; an absent key reads
    as `True`.
  - **Acceptance:** `set_uot` accepts booleans (and `"on"/"off"/"1"/"0"` spellings if the codebase
    already normalizes them elsewhere), rejects anything else, and returns `False` for a no-op.
  - **Dependency:** none. _Requirements: R1, R4._

- [x] **TSK-002 — Caddyfile rendering follows the setting**
  - **Факт:** `render_caddyfile(..., uot=True)` и `_build_caddyfile(..., uot=True)`; в режиме `off` строка `passthrough_uot` не выводится, остальные строки не меняются. `tests/test_naive_plugin.py::test_build_caddyfile_without_uot_keeps_the_rest_of_the_proxy_surface`.
  - `render_caddyfile(..., uot: bool = True)` emits `passthrough_uot` only when `uot`; every other
    line (auth, hide_ip, hide_via, probe_resistance, upstream, file_server, log) stays byte-identical.
  - **Acceptance:** a render test proves the directive is present for `True` and absent for `False`,
    and that the UoT-on render equals the current output.
  - **Dependency:** TSK-001. _Requirements: R1, R2, R3._

- [x] **TSK-003 — build selection and probes**
  - **Факт:** `NAIVE_FORWARD_PROXY_STOCK_MODULE` = upstream master `0aab84da`; `sni_router_install.install(..., forward_proxy_module=...)`; сборка и проба берутся по режиму, `_built_for_uot()` возвращает `True/False/None` по пробе с `passthrough_uot`. `tests/test_naive_installation.py::test_naive_stock_build_uses_the_upstream_module_and_plain_probe`, `::test_built_for_uot_classifies_the_installed_binary`; существующий тест форка не менялся.
  - Add `NAIVE_FORWARD_PROXY_STOCK_MODULE` (upstream master `0aab84da…`) next to the existing fork
    pin; give `sni_router_install.install()` a `forward_proxy_module` parameter defaulting to the
    fork.
  - `_download_binary()` builds from the module matching the desired mode and validates with the
    matching probe: fork probe (with `passthrough_uot`) for `uot=True`, plain probe for `False`.
  - Add `_built_for_uot()`: classify the installed binary by validating the fork probe.
  - **Acceptance:** installation tests cover both module strings, both probes, and a rejected probe
    failing the build without replacing the binary.
  - **Dependency:** TSK-001, TSK-002. _Requirements: R1, R5._

- [x] **TSK-004 — apply rebuilds only on mismatch**
  - **Факт:** в `apply` сверяется желаемый режим с `_built_for_uot()`; при расхождении — пересборка и отказ, если она не удалась; существующий fallback теперь тоже получает `uot=desired`. `tests/test_naive_plugin.py::test_apply_rebuilds_the_binary_when_the_setting_and_the_build_disagree`; rollback-тест (backup бинарника, конфига и сервиса) остался зелёным.
  - In `runtime.apply`, rebuild when `desired_uot != _built_for_uot()`, keep the existing
    validate-then-fallback path, and keep `reload-or-restart` vs `restart` behaviour.
  - **Acceptance:** tests prove rebuild is triggered in both mismatch directions and skipped when
    the installed build already matches; a failed rebuild leaves the previous binary and config.
  - **Dependency:** TSK-003. _Requirements: R1, R2, R4._

- [x] **TSK-005 — client artifacts**
  - **Факт:** `build_shadowrocket_naive_links(..., uot=False)` убирает `uot`, сохраняя `tfo`/`padding`; `links.py` берёт режим через `uot_enabled(state)`; обновлены `docs/REFERENCE.md`, `docs/CLI.md`, `README.md`, `CHANGELOG.md`. `tests/test_shadowrocket_links.py::test_naive_tcp_variants_drop_uot_when_the_server_does_not_serve_it`, `tests/test_subscriptions.py::test_shadowrocket_naive_drops_uot_when_the_server_does_not_serve_it`.
  - `build_shadowrocket_naive_links(link, *, uot=True)` drops `uot` (keeps `tfo`, `padding`) when
    off; `links.py` passes the flag read from `state.protocols["naive"].config` with `True` default.
  - Update `docs/REFERENCE.md`, `README.md`, `CHANGELOG.md`; state plainly that TCP-naive loses UDP
    when off, and that clients with explicit `udp_over_tcp` must turn it off themselves.
  - **Acceptance:** subscription tests cover both modes; docs name the setting and its cost.
  - **Dependency:** TSK-002. _Requirements: R3._

- [x] **TSK-006 — TUI**
  - **Факт:** в меню NaiveProxy добавлен пункт «UDP через TCP (UoT)» с текущим состоянием, подтверждением перед выключением и предупреждением о пересборке и UDP; команда идёт через `app.plugin_command`. `tests/test_protocol_activation.py::test_naive_menu_switches_uot_off_after_the_warning`, `::test_naive_menu_keeps_uot_when_the_warning_is_cancelled`.
  - `_menu_naive`: new item «UDP через TCP (UoT)» showing the current state, dispatching
    `set_uot` through `app.plugin_command`, with the rebuild/UDP warning and a confirmation before
    switching to off.
  - **Acceptance:** a menu test proves the command is dispatched with the right value and that the
    plugin object is not mutated directly.
  - **Dependency:** TSK-001. _Requirements: R1, R4._

- [ ] **TSK-007 — live Linux verification**
  - **Статус: blocked.** В текущем Windows worktree нет disposable Linux host; сборка Caddy и `caddy validate` локально не выполняются (проектная политика запрещает менять хост).
  - On a disposable Linux host: install with `uot` on, flip to off, prove the binary no longer
    accepts `passthrough_uot`, TCP traffic through sing-box still works, and Shadowrocket links no
    longer carry `uot`; then flip back and prove UDP over TCP works again.
  - Alternative evidence: extend the `naive-caddy` workflow to build and validate both module pins.
  - **Acceptance:** retained artifact shows both builds, both validations and the TCP/UDP outcome.
  - **Dependency:** TSK-004, TSK-005. _Requirements: R1, R2, R5._
