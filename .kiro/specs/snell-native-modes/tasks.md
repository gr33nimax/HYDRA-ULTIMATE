# Tasks: Native Snell generations in Hydra Ultimate

Spec: `./requirements.md` (R1–R5), `./design.md` (D1–D6).

## Dependency graph

```text
TSK-001 ─> TSK-002 ─> TSK-003 ─> TSK-005 ─> TSK-007
                └────> TSK-004 ──┘
TSK-006 (HydraCore fence) is independent and closes R2.4
```

## Progress

| State | Count | Evidence |
| --- | ---: | --- |
| Not started | 0 | — |
| Complete | 10 | TSK-001 … TSK-010 |

## Tasks

- [x] **TSK-001 — generation state, validation and migration**
  - **Факт:** `_version()` reads a stored `4` as `5` and refuses anything but `5`/`6`; `set_settings(version, obfs_mode, obfs_host, mode)` validates the two generations, their own fields and the cross combinations; `status()` names the generation, its clients and the obfuscation. Evidence: `tests/test_snell_modes.py::test_snell_settings_validation_and_migration`, `::test_snell_status_names_the_generation_and_its_clients` (14 passed).
  - Replace `SNELL_VERSION = 4` with a generation pair understanding (`5`/`6`), read a stored
    `4` as `5`, and extend `set_settings()` with `mode` plus the per-generation validation
    matrix from the design.
  - **Acceptance:** `set_settings` accepts `5`+`none|http` and `6`+`default|unshaped|unsafe-raw`,
    refuses cross combinations and unknown values, and reports the generation truthfully in
    `status()`.
  - **Dependency:** none. _Requirements: R1, R5._

- [x] **TSK-002 — server fragment for the migrated core**
  - **Факт:** `configure()` emits `version: 5` with a flat `obfs_mode` (omitted for `none`) or `version: 6` with `mode`, and no `obfs` key at all. Evidence: `tests/test_snell_modes.py::test_snell5_server_uses_the_flat_obfs_field` (none/http/tls), `::test_snell6_server_uses_its_own_mode` (default/unshaped/unsafe-raw); core side `option/snell_test.go::TestSnellServerAcceptsTheUpstreamGenerations`.
  - Render per-user inbounds with flat `version`/`obfs_mode`/`mode` per the rendering table;
    drop the nested `obfs` object.
  - **Acceptance:** `configure()` output matches the table for all four combinations and carries
    no `obfs` key.
  - **Dependency:** TSK-001. _Requirements: R2.1–R2.3._

- [x] **TSK-003 — client artifacts (outbound, `snell://`, Shadowrocket)**
  - **Факт:** the outbound carries `version: 4` + flat `obfs_mode`/`obfs_host` for generation 5 and `version: 6` + `mode` for 6; the share link carries the real client version; the Shadowrocket form derives the version and passes a generation 6 link through untouched. Evidence: `tests/test_snell_modes.py::test_snell5_client_outbound_is_the_classic_pair`, `::test_snell6_client_outbound_matches_its_server`, `::test_snell_share_link_carries_the_client_side_version`, `::test_shadowrocket_keeps_the_classic_pair_and_skips_generation_six`.
  - Render the matching outbound version per generation, extend `client_link()` with the
    generation and (for `6`) `mode`, and make the Shadowrocket converter derive the version
    instead of hardcoding `4`, refusing generation `6`.
  - **Acceptance:** each artifact matches the table; Shadowrocket keeps PSK/port and forwards
    obfuscation for the `5` pair and returns the link unchanged for `6`.
  - **Dependency:** TSK-001. _Requirements: R3._

- [x] **TSK-004 — core gate**
  - **Факт:** `MIN_SNELL_CORE = v1.14.0-extended-2.7.1-hydracore.12` with `kernel_supports_snell()`; `configure()` and `on_enable()` refuse with a reason naming the release. Evidence: `tests/test_snell_modes.py::test_snell_gate_reads_the_installed_core_version`, `::test_snell_refuses_to_render_on_an_old_core`.
  - Add `MIN_SNELL_CORE` and a `kernel_supports_snell()` helper; refuse `on_enable` (and every
    renderer) with a reason naming the required release when the installed core predates the
    upstream Snell implementation.
  - **Acceptance:** old-core state produces a stable refusal; new-core state enables.
  - **Dependency:** TSK-002. _Requirements: R4._

- [x] **TSK-005 — HYDRA tests**
  - **Факт:** `tests/test_snell_modes.py` → `14 passed` (rendering matrix, links, Shadowrocket, validation, migration, both gate outcomes).
  - Add `tests/test_snell_modes.py` with the golden matrix, link/Shadowrocket assertions,
    validation matrix, migration and both gate outcomes.
  - **Acceptance:** the suite passes and fails if a renderer regresses to the nested `obfs`
    object or a fixed version.
  - **Dependency:** TSK-002, TSK-003, TSK-004. _Requirements: R1–R5._

- [x] **TSK-006 — HydraCore regression fence (`option/snell_test.go`)**
  - **Факт:** `go test ./option -run Snell` → `3 passed`: server 5/6 shapes and client 4/6 shapes accepted, server-side `version: 4`, the nested `obfs` object and a client-side 5 refused.
  - Assert the emitted server/client shapes are accepted by the core's option parser and that
    `version: 4` on the server and the nested `obfs` object are refused.
  - **Acceptance:** `go test ./option` covers the four accepted shapes and the two refusals.
  - **Dependency:** none (HydraCore repo). _Requirements: R2.4._

- [x] **TSK-008 — the TUI settings screen follows the generations**
  - **Факт:** `hydra/ui/_menus/plugin_settings.py` renders the screen from the generation contract: «Поколение» switches 5/6 (switching to 6 asks for confirmation because issued v4 links stop working), the transport entry offers `none|http|tls` plus the obfuscation host for generation 5 and `default|unshaped|unsafe-raw` for generation 6, and a stored `4` reads as `5` — the screen no longer sends `version=4`. Evidence: `tests/test_extended_transport_menus.py` (tls on the classic pair, the switch with its warning, a cancelled warning, a v6 mode) → `77 passed` together with the plugin, generation and subscription suites.
  - **Dependency:** TSK-001 … TSK-004. _Requirements: R1, R3._

- [x] **TSK-007 — docs and spec cascade**
  - **Факт:** `docs/REFERENCE.md` (transport row + the Shadowrocket paragraph), `docs/CLI.md` (both `set_settings` examples), `README.md` (transport row) and `CHANGELOG.md` describe the two generations, the 5↔4 pairing and the gate; the meta-spec task points at this spec. `verify.py` → `1995 passed` + compileall + ruff. Commits `6996a18` (code/docs) and `9917d32` (tests) on `debug`.
  - Update `docs/REFERENCE.md`, `docs/CLI.md`, `README.md`, `CHANGELOG.md`; point the
    meta-spec task (`D:/dev/.kiro/specs/awg31-end-to-end` TSK-011) at this spec.
  - **Acceptance:** docs name the two generations, the 5↔4 pairing and the gate; `verify.py`
    passes.
  - **Dependency:** TSK-005. _Requirements: NFR docs._

- [x] **TSK-009 — Shadowrocket takes the obfuscation from its own parameter**
  - **Факт:** live Shadowrocket exports corrected the provisional URI grammar: `none` keeps the full credential base64 with `version=4&udp=1`; `http`/`tls` use credential-only base64 followed by literal `@host:port`, plus `plugin=obfs-local;...`; TLS serializes `obfs-host={"Host":"<host>"}` inside that plugin. Generation 6 still passes through untouched. The cross-protocol target contract lives in `.kiro/specs/shadowrocket-imports/requirements.md`; regression coverage is in `tests/test_shadowrocket_links.py`, `tests/test_snell_modes.py` and `tests/test_subscriptions.py`.
  - **Dependency:** TSK-003. _Requirements: R3.4._

- [x] **TSK-010 — generation 5 obfuscation: what clients offer, not what the wire format forbids**
  - **Факт (что ломалось):** живой хост отдавал `version: 5` + `obfs_mode: tls`, и в журнале ядра
    **каждое** клиентское соединение (Throne, разные профили, трое суток) падало одинаково:
    `inbound/snell[...]: process connection …: snell: serve …: read request: open record header:
    cipher: message authentication failed`. Причина — не формат: tls-обфускация реализована с обеих
    сторон (`sing-snell/obfs.go:93-113` — `ClientConn`/`ServerConn` разбирают `ObfsModeTLS`, рабочие
    `tlsObfsClientConn`/`tlsObfsServerConn` — `:304`, `:398`). Ограничение живёт в клиентах:
    официальный Surge даёт tls только поколениям 1–3, а sing-box-клиент (и Throne на нём) на пятёрке
    его не предлагает. Сервер с tls отвечает только нашему клиенту — а живой хост не отвечал никому.
  - **Факт (доказательство):** loopback-проба на живом хосте — отдельный процесс sing-box, который
    говорит сам с собой (mixed-entry → Snell-outbound → Snell-inbound → direct) — прошла **все**
    комбинации: сервер 5 + клиент 4 с `none`, `http` и `tls`, и сервер 6 + клиент 6 со всеми тремя
    режимами; каждая ответила HTTP 204. Значит обе половины исправны во всех штатных режимах, а живой
    сбой был про клиентов: Throne (sing-box) и Surge на пятёрке `tls` не предлагают, а HydraBox до
    сервера не доходил — не импортировал `snell://` (исправлено в HydraBox, коммит `0105319`).
  - **Факт (решение):** `tls` **оставлен** рабочим режимом пятёрки — `OBFS_MODES = ("none", "http", "tls")`,
    в меню пункт TLS с однострочной пометкой, кто его понимает (наш ядро/HydraBox и mihomo — да,
    Throne и Surge — нет). Поколение 6 обфускации не имеет вовсе: там её заменяет `mode`. Проверка:
    `tests/test_snell_modes.py`, `tests/test_snell_plugin.py`, `tests/test_extended_transport_menus.py`.
  - _Requirements: R1, R5._
