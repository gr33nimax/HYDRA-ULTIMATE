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
| Not started | 7 | TSK-001 … TSK-007 |
| Complete | 0 | — |

## Tasks

- [ ] **TSK-001 — generation state, validation and migration**
  - Replace `SNELL_VERSION = 4` with a generation pair understanding (`5`/`6`), read a stored
    `4` as `5`, and extend `set_settings()` with `mode` plus the per-generation validation
    matrix from the design.
  - **Acceptance:** `set_settings` accepts `5`+`http|tls|none` and `6`+`default|unshaped|unsafe-raw`,
    refuses cross combinations and unknown values, and reports the generation truthfully in
    `status()`.
  - **Dependency:** none. _Requirements: R1, R5._

- [ ] **TSK-002 — server fragment for the migrated core**
  - Render per-user inbounds with flat `version`/`obfs_mode`/`mode` per the rendering table;
    drop the nested `obfs` object.
  - **Acceptance:** `configure()` output matches the table for all four combinations and carries
    no `obfs` key.
  - **Dependency:** TSK-001. _Requirements: R2.1–R2.3._

- [ ] **TSK-003 — client artifacts (outbound, `snell://`, Shadowrocket)**
  - Render the matching outbound version per generation, extend `client_link()` with the
    generation and (for `6`) `mode`, and make the Shadowrocket converter derive the version
    instead of hardcoding `4`, refusing generation `6`.
  - **Acceptance:** each artifact matches the table; Shadowrocket keeps PSK/port and forwards
    obfuscation for the `5` pair and returns the link unchanged for `6`.
  - **Dependency:** TSK-001. _Requirements: R3._

- [ ] **TSK-004 — core gate**
  - Add `MIN_SNELL_CORE` and a `kernel_supports_snell()` helper; refuse `on_enable` (and every
    renderer) with a reason naming the required release when the installed core predates the
    upstream Snell implementation.
  - **Acceptance:** old-core state produces a stable refusal; new-core state enables.
  - **Dependency:** TSK-002. _Requirements: R4._

- [ ] **TSK-005 — HYDRA tests**
  - Add `tests/test_snell_modes.py` with the golden matrix, link/Shadowrocket assertions,
    validation matrix, migration and both gate outcomes.
  - **Acceptance:** the suite passes and fails if a renderer regresses to the nested `obfs`
    object or a fixed version.
  - **Dependency:** TSK-002, TSK-003, TSK-004. _Requirements: R1–R5._

- [ ] **TSK-006 — HydraCore regression fence (`option/snell_test.go`)**
  - Assert the emitted server/client shapes are accepted by the core's option parser and that
    `version: 4` on the server and the nested `obfs` object are refused.
  - **Acceptance:** `go test ./option` covers the four accepted shapes and the two refusals.
  - **Dependency:** none (HydraCore repo). _Requirements: R2.4._

- [ ] **TSK-007 — docs and spec cascade**
  - Update `docs/REFERENCE.md`, `docs/CLI.md`, `README.md`, `CHANGELOG.md`; point the
    meta-spec task (`D:/dev/.kiro/specs/awg31-end-to-end` TSK-011) at this spec.
  - **Acceptance:** docs name the two generations, the 5↔4 pairing and the gate; `verify.py`
    passes.
  - **Dependency:** TSK-005. _Requirements: NFR docs._
