# Tasks: complete AmneziaWG 2.x / 3.x module update

## Progress

| State | Count | Evidence |
| --- | ---: | --- |
| Not started | 0 | — |
| In progress | 0 | — |
| Blocked | 1 | TSK-013 needs a disposable compatible Linux host/client. |
| Complete | 16 | TSK-001–TSK-012 and TSK-014–TSK-017 have local evidence. |

## Dependency graph

```text
TSK-001 ─┬─> TSK-002 ─> TSK-004 ─> TSK-006 ─> TSK-010 ─> TSK-012
         └─> TSK-003 ─> TSK-005 ─> TSK-007 ─> TSK-010
                                    └─> TSK-008 ─> TSK-009 ─> TSK-010
TSK-011 ────────────────────────────────────────────────────────> TSK-012
TSK-013 is a release gate for TSK-012.
```

## Tasks

- [x] **TSK-001 — Record the protocol-generation decision**
  - **Факт:** `.kiro/decisions/0002-awg-generation-upstream-ownership.md` accepted. `scan`, `add`, `review` (5/6), `approve` and `check` executed through the provided decision CLI.
  - _Requirements: R1, R2, R6._

- [x] **TSK-002 — Add a generation-aware directive model**
  - **Факт:** added `hydra/plugins/amneziawg/directives.py` and `tests/test_awg_directives.py`; `.venv/Scripts/python.exe -m pytest -q tests/test_awg_directives.py` → `5 passed`.
  - _Requirements: R1, R2, R7._

- [x] **TSK-003 — Preserve legacy obfuscation strategies**
  - **Факт:** constants now use the canonical legacy category; regression confirms an obfuscation update preserves AWG 3.x directives. `.venv/Scripts/python.exe -m pytest -q tests/test_awg_plugin.py tests/test_awg_directives.py` → `38 passed`; focused Ruff passed.
  - _Requirements: R1, R3, R4._

- [x] **TSK-004 — Add upstream mode adapter and complete runtime snapshot**
  - **Факт:** `installer_identity()` verifies the managed checkout; snapshot records configs, params, installer revision and enabled/active unit state; rollback restores them. `tests/test_awg_protocol_runtime.py` covers command selection and apply-failure rollback.
  - Extend `installation.py` with managed-checkout identity verification and bounded argv wrappers for `--protocol-status`, `--enable-awg3`, `--enable-awg31`, `--disable-awg3`.
  - Extend `runtime.py` snapshot/rollback to include both configs, `params`, installer identity, and enabled/active systemd state; preserve `0600` mode and the primary error.
  - Unit-test command selection, malformed status, unknown checkout, capability failure and each restore point without executing privileged host operations.
  - **Acceptance:** a failed migration restores the exact former managed files, service state and desired state.
  - **Dependency:** TSK-001, TSK-002.
  - _Requirements: R2, R5, R6._

- [x] **TSK-005 — Reconcile two server interfaces safely**
  - **Факт:** generation directives are validated and projected to both profiles; runtime apply verifies each interface. Covered by AWG directive/plugin/runtime tests.
  - Update `configuration.py` to validate primary AWG directives, preserve unknown keys, and copy only the validated upstream-generated generation subset to `awg1`.
  - On downgrade, remove only known 3.x directives; preserve peers, interface identity, profile ports and legacy obfuscation.
  - Update runtime health verification to cover both interfaces after apply.
  - **Acceptance:** fixture tests cover 2.0 → 3.0 → 3.1 → 2.0 for both interfaces and injected apply failure restores the previous generation.
  - **Dependency:** TSK-002, TSK-003, TSK-004.
  - _Requirements: R2, R3, R4, R6._

- [x] **TSK-006 — Implement transactional `set_protocol_mode` command**
  - **Факт:** `AwgProtocolModeMixin` is allowlisted and executes via `PluginCommandService`; injected apply failure restores upstream mode and desired state.
  - Add a small `AwgProtocolModeMixin`; compose it in `plugin.py` and allowlist `set_protocol_mode`.
  - Delegate through existing `PluginCommandService`; support strict validation, observed/desired no-op, drift reporting, exporter preflight, upstream migration, post-observation and central apply.
  - Add command tests for default mode, invalid mode, no-op without restart, successful migration and rollback from upstream/directive/apply/health failures.
  - **Acceptance:** desired mode is persisted only after observed mode and both interface health checks succeed.
  - **Dependency:** TSK-004, TSK-005.
  - _Requirements: R1, R2, R5, R6._

- [x] **TSK-007 — Make native client config generation-aware**
  - **Факт:** native `.conf` serializes validated generation directives only; AWG 3.1 preserves matching `RandomTrailers`.
  - Refactor `client_links.py` to use the directive model, producing a full `.conf` for 2.0/3.0/3.1 without exposing secrets in status/errors.
  - Ensure server/client `RandomTrailers` agree and 2.0 has no 3.x fields.
  - Add golden output tests and an AWG 2.0 byte-compatibility regression.
  - **Acceptance:** every emitted native `.conf` passes directive validation for its stated generation.
  - **Dependency:** TSK-002, TSK-005.
  - _Requirements: R1, R2, R4, R7._

- [x] **TSK-008 — Gate URI and subscription renderers by proven capability**
  - **Факт:** capability matrix returns stable incompatibility reasons for `wg://`, `vpn://`, `sn://awg`, Sing-Box and HydraBox; 3.x renderers fail closed.
  - Add per-renderer capability declarations for `wg://`, `vpn://`, NekoBox `sn://awg`, Sing-box and HydraBox.
  - Keep existing AWG 2.0 serialization unchanged. For 3.x, omit unsupported artifact and return a stable incompatibility reason; never reuse the legacy tuple and silently drop fields.
  - Wire the policy through subscription/user-link paths and add golden tests for supported 2.0 plus omission tests for 3.x.
  - **Acceptance:** no AWG 3.x URI, NekoBox or Sing-box artifact is emitted until a dedicated adapter has versioned grammar/runtime and import/handshake evidence.
  - **Dependency:** TSK-002, TSK-007.
  - _Requirements: R4, R5, R7._

- [x] **TSK-009 — Add proven 3.x adapters only when evidence exists**
  - **Факт:** no adapter was enabled: no versioned importer/handshake evidence exists, so the matrix intentionally retains native `.conf` as the sole 3.x artifact.
  - For each external format with published, versioned support, add a dedicated serializer adapter and golden payload tests; add import/connection smoke evidence.
  - Do not change the capability declaration merely to expose an existing partial serializer.
  - **Acceptance:** each newly enabled target has its own evidence URL/version, complete field mapping and executable import/handshake test.
  - **Dependency:** TSK-008.
  - _Requirements: R4, R7._

- [x] **TSK-010 — Surface generation and compatibility safely in TUI, CLI and status**
  - **Факт:** `protocol_mode_status` exposes redacted desired/observed mode, legacy strategy and export policy; TUI dispatches only through `plugin_command`.
  - Add desired/observed mode, selected legacy strategy and redacted compatibility summary to `observation.py`.
  - Add TUI mode selection and warning through the existing plugin-command facade; add CLI command metadata/normalized result without direct host calls.
  - Show omitted export reasons and 2.0 return path; do not show keys, directive values or raw config.
  - **Acceptance:** UI/CLI tests prove all mutations use `PluginCommandService` and snapshots contain no secrets.
  - **Dependency:** TSK-006, TSK-008.
  - _Requirements: R3, R5, R7._

- [x] **TSK-011 — Correct operator documentation**
  - **Факт:** `README.md`, `docs/REFERENCE.md`, `docs/CLI.md` and `CHANGELOG.md` now document the 3.x native-conf-only policy and safe return to 2.0.
  - Update AWG documentation in `README.md`, `docs/REFERENCE.md`, `docs/CLI.md` and `CHANGELOG.md`.
  - Describe generation vs legacy obfuscation, client compatibility, `RandomTrailers`, unsupported exports and safe downgrade; remove unsupported I1–I5/J1–J3/Itime claims.
  - **Acceptance:** every displayed client format has a matching documented compatibility policy.
  - **Dependency:** TSK-008.
  - _Requirements: R3, R5, R7._

- [x] **TSK-012 — Run focused verification and update spec evidence**
  - **Факт:** `.venv\Scripts\python.exe verify.py` → `1971 passed` (compileall, Ruff, full pytest); `git diff --check` → exit 0.
  - Run affected AWG, subscription, command and UI tests; then architecture/size guards, `ruff`, `compileall`, and `git diff --check`.
  - Update requirement status and mark completed tasks with exact command/evidence; record accepted architecture decision reference.
  - **Acceptance:** all relevant checks are green; no task is marked complete without command evidence.
  - **Dependency:** TSK-006, TSK-007, TSK-008, TSK-010, TSK-011.
  - _Requirements: R1–R7._

- [ ] **TSK-013 — Execute disposable Linux interoperability smoke**
  - **Статус: blocked.** В текущем Windows worktree нет disposable Linux host/client; локальный запуск installer/systemd/firewall запрещён проектной политикой.
  - On a disposable Linux host only, prove `2.0 → 3.0 → 3.1 → 2.0`, both server interfaces, one compatible native client handshake per supported mode, and an injected rollback.
  - Do not run installer/upgrade/systemd/firewall mutation scripts locally or on a production VPS.
  - **Acceptance:** retained CI/disposable-host artifact shows mode observation, interface health and handshake per transition.
  - **Dependency:** TSK-012.
  - _Requirements: R2, R4, R6, R7._

- [x] **TSK-014 — Extend source-proven `wg://` and `vpn://` AWG 3.x links**
  - **Факт:** Throne `wg://` receives all validated generation fields in snake_case; official `vpn://` writes exact PascalCase fields into `last_config`, including forced-safe `DisableCookies=false`, then serializes the outer container as Qt `qCompress` + unpadded Base64URL. `tests/test_awg_architecture.py tests/test_awg_plugin.py tests/test_awg_protocol_runtime.py` → `45 passed`.
  - Add every validated generation directive to Throne’s `wg://` query grammar and the official Amnezia `last_config` JSON; retain `DisableCookies=false`.
  - Add decode/golden regressions for 3.0 and 3.1; preserve 2.0 bytes.
  - _Requirements: R4, R7, R9, R11._

- [x] **TSK-015 — Gate HydraBox by SBE’s actual mode contract**
  - **Факт:** 3.0 serializes only source-proven `amnezia` fields and enables the Sing-Box/HydraBox renderer; 3.1 stays fail-closed because both pinned SBE tags omit its two fields. `tests/test_awg_architecture.py tests/test_awg_plugin.py tests/test_awg_protocol_runtime.py tests/test_hydrabox_subscription.py` → `84 passed`.
  - Permit 3.0 only for the exact source-proven SBE contract; retain an explicit 3.1 incompatibility reason until the binary/source accepts both missing fields.
  - **Каскад (2026-09-14, HydraCore 2.7.1):** 3.1 экспортируется гейтом по версии установленного ядра: `v1.14.0-extended-2.7.1-hydracore.12`+ → `singbox`/`hydrabox_subscription` = ready, старше → fail-closed с причиной, называющей требуемый релиз. `random_trailers` сериализуется JSON-булевым (ядро отклоняет строку), `disable_cookies` не выставляется. Факты: `tests/test_awg_protocol_runtime.py` (supporting/old core), `tests/test_awg_plugin.py::test_singbox_awg31_exports_boolean_random_trailers`; ядро — `option/wireguard_amnezia_test.go`, `experimental/libbox/hydracore_subscription_awg_test.go`.
  - _Requirements: R4, R8, R10._

- [x] **TSK-016 — Verify and document confirmed external compatibility**
  - **Факт:** focused AWG architecture, exporter, protocol and HydraBox tests passed (`84 passed`), `git diff --check` passed, and `.venv\\Scripts\\python.exe verify.py` passed: `1974 passed` plus `compileall` and Ruff.
  - Run focused exporter/subscription tests, then full verification; update docs and task evidence. Preserve the disposable Linux smoke blocker.
  - _Requirements: R4, R7–R11._

- [x] **TSK-017 — Keep ordinary AWG TUI free of passive export omissions**
  - **Факт:** the ordinary menu no longer adds the `Экспорты: не выдаются …` row; desired/observed generation and profiles remain. Direct rendering regression plus `tests/test_awg_protocol_runtime.py` → `15 passed`; Ruff for changed Python files and `git diff --check` → exit 0.
  - Remove the `Экспорты: не выдаются …` dashboard row only; retain desired/observed mode, profiles, the capability matrix, and fail-closed artifact behavior.
  - Add a direct menu rendering regression that verifies unavailable exports do not appear in the ordinary panel.
  - **Acceptance:** the menu does not display `Экспорты` or `не выдаются`; protocol capability tests retain their incompatibility assertions.
  - **Dependency:** TSK-010.
  - _Requirements: R12._

- [x] **TSK-018 — Метка пира в формате, который понимает upstream-установщик**
  - **Факт:** пиры получают `### Client u<12 hex>` — стабильно (из email), уникально, соответствует `^### Client [A-Za-z0-9_-]{1,15}$`; рядом остаётся человекочитаемый email, который строгий подсчёт меток игнорирует. `tests/test_awg_plugin.py::test_peer_markers_are_the_shape_the_installer_requires` — формат, уникальность, стабильность между пересборками; фокусные AWG-тесты `96 passed`, `.venv\Scripts\python.exe verify.py` → `2035 passed`.
  - Писать `### Client <имя>` (стабильное, уникальное, `[A-Za-z0-9_-]{1,15}`) плюс email отдельной строкой.
  - Сохранить чтение конфигов со старой меткой и разбор секций по публичным ключам.
  - **Acceptance:** метка соответствует `^### Client [A-Za-z0-9_-]{1,15}$`, уникальна, воспроизводима между запусками; старый конфиг читается.
  - _Requirements: R13._

- [x] **TSK-019 — Клиентские конфиги для миграции и их уборка**
  - **Факт:** `_lent_client_configs` выкладывает `/root/awg0-client-<маркер>.conf` (0600) из состояния на время вызова установщика и удаляет их в `finally` — как при успехе, так и при отказе; чужой файл не затирается (сверка `PrivateKey`), а уводится в сторону и возвращается. Путь отката (`runtime.py::rollback`) тоже передаёт состояние. Тесты: `test_protocol_migration_lends_the_installer_client_configs`, `test_protocol_migration_cleans_up_after_a_refusal_and_restores_a_foreign_file`.
  - Перед вызовом установщика выложить `/root/awg0-client-<имя>.conf` (0600) из состояния; после — удалить, чужие файлы восстановить из копии.
  - Уборка выполняется и при отказе: приватные ключи не остаются после неудачной миграции.
  - **Acceptance:** миграция находит каждый конфиг по публичному ключу; после успеха и после отказа в `/root` нет созданных HYDRA файлов; чужие не изменены.
  - **Dependency:** TSK-018.
  - _Requirements: R14._

- [ ] **TSK-020 — Проверка переключения на живом сервере**
  - Владелец: переключить 2.0 → 3.0 → 3.1 на сервере, где пиров создала HYDRA; приложить вывод `--protocol-status` и `awg show`.
  - **Acceptance:** статус подтверждает целевой режим; клиент подключается (сначала HB2 из `alpha2`).
  - **Dependency:** TSK-019.
  - _Requirements: R13, R14._
