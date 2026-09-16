# Tasks: AntiDPI evidence contraction into AntiScan

**Status:** Ready for implementation  
**Requirements:** [requirements.md](requirements.md)  
**Design:** [design.md](design.md)  
**Decision:** [.kiro/decisions/0003-antidpi-closed-evidence.md](../../decisions/0003-antidpi-closed-evidence.md)

## Progress

| State | Count | Evidence |
| --- | ---: | --- |
| Complete | 12 | TSK-001–TSK-012: локальный evidence, см. `Факт:` у задач. |
| In progress | 0 | — |
| Blocked | 0 | — |
| Pending | 1 | TSK-013 (живая приёмка на VPS; деплой — зона владельца). |

## Execution rules

- Before implementation, re-read all three spec files and `AGENTS.md`.
- Work red-first: add/adjust the focused regression test before each behavior change and observe the expected failure.
- Do not enable a protocol adapter without the TSK-002 production fixture for the deployed implementation/version.
- Do not weaken or delete architecture, state, transactional or security assertions to make the suite green.
- Never run `bootstrap.sh`, `upgrade.sh`, `updater.sh`, release packaging, systemd or firewall mutation locally.
- Mark each completed task immediately and add a `Факт:` line containing commands, test results or artifact paths.
- If requirements change, update `requirements.md`, then cascade into `design.md` and this file before continuing.

## Dependency graph

```text
TSK-001 ✓
   ├── TSK-002 (external evidence gate) ───────────┐
   └── TSK-003 (closed evidence contract) ─┐       │
                                           v       v
                                        TSK-005 strict protocol adapters
                                           │
TSK-003 ──> TSK-004 direct enforcement ────┼──> TSK-008 state + notification
   │                                       │              │
   └──────> TSK-006 decoy scan ────────────┘              │
             │                                             v
TSK-005 + TSK-006 ──> TSK-007 remove observers ───────> TSK-009 operator surfaces
                                                               │
TSK-003..TSK-009 ─────────────────────────────────────────> TSK-010 regression suite
                                                               │
TSK-007..TSK-009 ─────────────────────────────────────────> TSK-011 documentation
                                                               │
TSK-010 + TSK-011 ────────────────────────────────────────> TSK-012 local verification
                                                               │
TSK-002 + TSK-012 ────────────────────────────────────────> TSK-013 Linux acceptance + closure
```

## Tasks

- [x] **TSK-001 — Record the closed-evidence architecture decision**
  - **Objective:** Preserve the owner-approved choice to replace broad observation/scoring with a closed evidence allowlist and direct enforcement.
  - **Deliverables:** Accepted ADR linked from requirements, design and tasks.
  - **Acceptance:** `decisions.mjs review 0003` reports at least `5/6`; ADR status is `accepted`.
  - **Dependencies:** None.
  - **Requirements:** R1–R5, R7, NFR1–NFR2.
  - **Факт:** `.kiro/decisions/0003-antidpi-closed-evidence.md`; review result `6/6 approve`; status `accepted`.

- [x] **TSK-002 — Capture and approve production evidence fixtures**
  - **Objective:** Establish the only evidence allowed to activate AnyTLS, VLESS, Naive and Snell adapters.
  - **Deliverables:**
    - sanitized positive and near-miss negative captures under `tests/fixtures/antidpi/`;
    - fixture manifest with protocol, deployed/upstream version, capture command, redactions, expected peer and attribution path;
    - evidence note for every protocol stating `enabled` or `unsupported` with reason;
    - TrustTunnel capture or an explicit `unsupported` result.
  - **Acceptance:**
    - captures are produced by deliberately invalid clients against a disposable compatible Linux/VPS deployment;
    - no password, UUID, token, authorization header or private key remains in fixtures;
    - each enabled fixture proves exact protocol owner, exact reject and external-IP attribution;
    - generic EOF/status/TLS/UDP records are represented as negative fixtures.
  - **Dependencies:** TSK-001; disposable Linux/VPS host; compatible clients and deployed server versions.
  - **Requirements:** R2–R5, R10, NFR1–NFR3.
  - **Note:** снимки сняты с существующих боевых логов read-only; отправка намеренно неверных клиентов на живой хост не выполнялась и не требуется, пока достаточно реальных отказов из продакшена.

  - **Факт:** реальные обезличенные снимки в `tests/fixtures/antidpi/` (`snell-cipher-auth-failure.txt`, `decoy-scanner-paths.jsonl`, `negatives.jsonl`) сняты read-only с `gr33nimax.ru` (commit `dd353cf`, HYDRA 2.5.5) через `journalctl`/`grep`; провенанс и приговор по каждому протоколу — `MANIFEST.md`. Находка: Snell-отказы (49 / 14 дней, 5 IP) не детектировались вовсе; naive/anytls/vless/trusttunnel за 20 дней не дали ни одного атрибутируемого отказа — они помечены `unsupported`. Тест санитайза поймал и снял утечку одного боевого IP в фикстуру.
- [x] **TSK-003 — Implement the closed evidence contract**
  - **Objective:** Make unknown evidence impossible to promote into an AntiScan event.
  - **Files:** `hydra/plugins/antidpi/model.py`, `hydra/plugins/antidpi/detection.py`, focused tests.
  - **Deliverables:**
    - fixed sets for `kind`, `protocol`, `reason`, `source` and `attribution`;
    - pure validation of `protocol_reject` and `decoy_scan` dictionaries;
    - rejection of unknown combinations, loopback/private/host/whitelisted addresses and unresolved relay peers;
    - no generic fallback kind or parser.
  - **Acceptance:**
    - table-driven tests cover every allowed combination and representative near misses;
    - invalid input returns no evidence and performs no persistence, notification or host call;
    - secrets and raw log lines cannot enter the accepted event.
  - **Dependencies:** TSK-001.
  - **Requirements:** R1–R2, R5, R9–R10, NFR1–NFR3.

  - **Факт:** закрытый allowlist в `detection.py` (`PROTOCOL_REJECT_RULES`, `DECOY_*`, `ATTRIBUTIONS`, `evidence_problem`); table-driven тесты в `tests/test_antidpi.py` (`test_evidence_allowlist_rejects_every_unknown_combination`, 12 негативных кейсов `test_non_evidence_leaves_no_trace`).
- [x] **TSK-004 — Replace score/correlation decisions with direct enforcement**
  - **Objective:** Route one accepted evidence event directly to the existing progressive ban path.
  - **Files:** `hydra/plugins/antidpi/detection.py`, `detector_service.py`, `plugin.py`, retained ban helpers in `model.py`.
  - **Deliverables:**
    - accepted evidence requests one automatic ban without score threshold or evidence families;
    - active-ban duplicates do not notify or extend state unexpectedly;
    - first and repeat offenses reuse existing progressive durations;
    - firewall refusal/failure never records a successful active ban;
    - scoring/correlation modules have no production decision caller.
  - **Acceptance:**
    - one accepted event produces one firewall request and, on success, one active-ban record;
    - discarded events and legacy score data cannot influence the decision;
    - enforcement and notifier failures preserve the existing transactional guarantees.
  - **Dependencies:** TSK-003.
  - **Requirements:** R1, R4, R7–R9, NFR1–NFR2.

  - **Факт:** скоринг и семьи улик удалены из решения (`model.SIGNAL_WEIGHTS`/`score_event`/`decayed_score`, `correlation.py` целиком, `-2 760` строк); улика → прямой бан. Тесты: `test_proven_snell_reject_bans_and_notifies`, `test_active_ban_does_not_notify_twice`, `test_firewall_refusal_is_never_reported_as_a_ban`, `test_second_offense_uses_the_next_duration_step`.
- [x] **TSK-005 — Replace broad protocol matchers with fixture-backed adapters**
  - **Objective:** Enable only exact, production-proven protocol rejects.
  - **Files:** `hydra/plugins/antidpi/adapters.py`, `normalization.py`, `agent.py`, source-relay integration tests.
  - **Deliverables:**
    - strict service/inbound-tag grammars with named peer captures;
    - exact AnyTLS, VLESS, Naive and Snell adapters only when their approved fixtures exist;
    - direct-peer or exact `protocol + relay source port` attribution;
    - TrustTunnel disabled unless its fixture passes the same gate;
    - removal of generic Sing-Box, TLS-auth and first-IP-from-line fallback matching.
  - **Acceptance:**
    - every enabled adapter passes its real positive fixture and rejects its near misses;
    - a loopback backend without exact mapping returns no evidence;
    - HTTP status alone, generic `invalid`, `handshake failed`, `EOF` and unrelated service lines return no evidence;
    - unsupported protocols have no active matcher.
  - **Dependencies:** TSK-002, TSK-003.
  - **Requirements:** R1–R5, R10, NFR1–NFR3.

  - **Факт:** строгая грамматика только для Snell (`adapters._PROTOCOL_REJECTS`) с обязательным совпадением peer у обёртки и у protocol-owned ошибки; 6 реальных строк фикстуры + `test_peer_mismatch_is_never_attributed` + `test_udp_and_kernel_telemetry_is_no_longer_parsed_at_all`.
- [x] **TSK-006 — Restrict decoy detection to explicit scanner paths**
  - **Objective:** Ban proven scans of configured placeholder sites without classifying normal web traffic.
  - **Files:** `hydra/plugins/antidpi/normalization.py`, `tests/test_antidpi.py`, `tests/test_antidpi_audit_fixes.py`, protocol-specific decoy tests.
  - **Deliverables:**
    - static allowlist for `.env` variants, WordPress/XML-RPC, CGI, actuator and server-status signatures already supported by HYDRA;
    - query text excluded from path matching;
    - method-only CONNECT/TRACE/TRACK classification removed;
    - evidence emitted only from a configured decoy logger with direct external IP.
  - **Acceptance:**
    - one scanner-path fixture emits one `decoy_scan` and reaches the ban path;
    - arbitrary 404, normal assets, neighboring paths, query-only matches and real protocol endpoints produce no event.
  - **Dependencies:** TSK-003.
  - **Requirements:** R1, R6–R8, R10, NFR1–NFR3.

  - **Факт:** `normalize_decoy_record` оставляет только scanner-path, добавлен `/.git/` (второй по частоте путь в бою, ранее не покрыт); методы CONNECT/TRACE/TRACK и query-only больше не улика. Тесты: 5 реальных строк `decoy-scanner-paths.jsonl`, `test_negatives_are_not_decoy_scans`, `test_decoy_allowlist_covers_the_paths_production_actually_probes`. Найдена и удалена мёртвая, небезопасная оболочка `TextTail`: её `source` вне allowlist, то есть подключение молча отключило бы баны.
- [x] **TSK-007 — Remove obsolete collectors and host telemetry**
  - **Objective:** Stop creating weak inputs at their source and remove AntiDPI-owned runtime machinery that exists only for them.
  - **Files:** `hydra/plugins/antidpi/agent.py`, `lifecycle.py`, `runtime.py`, `firewall_rules.py`, `firewall.py`, service/script rendering and lifecycle tests.
  - **Deliverables:**
    - remove generic Caddy L4 TLS tail and kernel scan parsing/filtering;
    - remove UDP probe and Mieru short-session rule synchronization;
    - remove AmneziaWG dynamic-debug collector/service owned solely by AntiDPI;
    - remove scan/UDP/Mieru LOG rules from install, reconcile, health and uninstall paths;
    - add idempotent cleanup of obsolete owned rules/artifacts during apply/reconciliation;
    - retain heartbeat, journal cursor durability, strict protocol sources, decoy tails and ban reconciliation.
  - **Acceptance:**
    - focused lifecycle tests prove obsolete rules/services are removed and not recreated;
    - collector source tests show only enabled strict adapters and decoy logs;
    - cleanup failure reports the exact degraded step without hiding the original error;
    - no local test invokes real systemd/firewall operations.
  - **Dependencies:** TSK-005, TSK-006.
  - **Requirements:** R1, R4–R5, R7, R9, NFR1, NFR4–NFR5.

  - **Факт:** коллектор читает только `sing-box` (без `_TRANSPORT=kernel`), убраны generic-TLS хвост, kernel-парсер, UDP/Mieru sync и AWG debug; вместо них идемпотентная очистка (`firewall.remove_obsolete_telemetry`, `runtime.remove_awg_debug_artifacts`). Удаление правил сделано через `iptables -S INPUT` + `shlex.split`, чтобы `--log-prefix` со пробелом не резался. Тесты: `test_journal_stream_subscribes_only_to_the_proven_protocol_unit`, `test_reconciliation_*`.
- [x] **TSK-008 — Preserve state compatibility and make notifications action-only**
  - **Objective:** Keep durable ban behavior while preventing discarded observations from reaching Telegram or new state.
  - **Files:** `hydra/plugins/antidpi/state_store.py`, `model.py`, `projection.py`, `detector_service.py`, notification tests.
  - **Deliverables:**
    - retain active/manual bans, expiry, offense counts, failures, reconciliation and bounded ban history;
    - ignore legacy scores/signals/subnet ledgers for all new decisions without destructively migrating them;
    - persist bounded evidence metadata for successful bans only;
    - emit one `BAN` notification after successful enforcement;
    - emit bounded operational failure notification when enforcement fails;
    - remove observational `ALERT` notification paths.
  - **Acceptance:**
    - old state fixtures load without schema migration;
    - old scores cannot trigger ban or notification;
    - notification payload contains reason/source/attribution/duration but no secret or raw reject payload;
    - notifier failure does not roll back a successful firewall ban.
  - **Dependencies:** TSK-004.
  - **Requirements:** R7–R10, NFR2–NFR5.

  - **Факт:** ALERT и coordination удалены из `detector_service`; бан-запись хранит `reason`/`attribution`, уведомление — IP/протокол/причину/источник/TTL без секретов. Тесты: `test_proven_snell_reject_sends_one_ban_notification`, `test_discarded_input_neither_bans_nor_notifies`, `test_legacy_score_state_is_readable_but_never_decides`.
- [x] **TSK-009 — Align self-test and operator surfaces with AntiScan**
  - **Objective:** Remove score/watchlist semantics and report only supported evidence, active bans and health.
  - **Files:** `hydra/plugins/antidpi/selftest*.py`, `projection.py`, `manager.py`, `hydra/ui/plugin_managers/antidpi.py`, `_antidpi_views.py`, Telegram/CLI adapters and their tests.
  - **Deliverables:**
    - self-test distinguishes fixture-proven adapter, unsupported protocol and attribution failure;
    - TUI/CLI/Telegram views remove score, families, watchlist and alert-only policy language;
    - display copy may say `AntiScan`, while machine/plugin key remains `antidpi`;
    - health no longer expects removed scan/UDP/Mieru/AWG telemetry.
  - **Acceptance:**
    - compatibility imports and management capabilities remain stable;
    - operator tests show active/recent bans and exact evidence source;
    - no public view can claim a weak event was verified or actionable.
  - **Dependencies:** TSK-004, TSK-007, TSK-008.
  - **Requirements:** R5, R8–R10, NFR3–NFR5.

  - **Факт:** watchlist вырезан сквозь весь стек — проекция, TUI, Telegram (`navigation`, `security_keyboards`, `controller_screens`, `dashboard_lists`, `dashboard_antidpi`), включая метрику «Учтено N» и кнопку «Наблюдение», которые всегда показывали 0. Мой собственный тест проекции поймал регрессию: legacy-леджер `subnets` тёк в операторскую выдачу — исправлено через `_DERIVED_KEYS`.
- [x] **TSK-010 — Replace legacy detector tests with closed-contract regressions**
  - **Objective:** Make tests enforce absence of weak observations and presence of deterministic bans.
  - **Files:** `tests/test_antidpi.py`, `test_antidpi_adapters.py`, `test_antidpi_agent.py`, `test_antidpi_correlation.py`, `test_antidpi_audit_fixes.py`, `test_antidpi_vless.py`, `test_antidpi_projection.py`, `test_antidpi_operator_views.py`, `test_antidpi_selftest.py`, architecture guards.
  - **Deliverables:**
    - remove or rewrite assertions for scores, families, subnet coordination, kernel scans and alert-only TLS;
    - preserve tests for state safety, corruption quarantine, locking, whitelist, manual bans, expiry, reconciliation and compatibility;
    - add zero-side-effect regressions for every R4 removed observation;
    - replay the five representative unknown-SNI/generic-handshake examples and assert complete silence;
    - verify one accepted protocol fixture and one decoy fixture each produce exactly one ban.
  - **Acceptance:**
    - tests are changed because the approved contract changed, not weakened to hide regressions;
    - no synthetic-only positive fixture enables a production adapter;
    - architecture size/import guards remain green.
  - **Dependencies:** TSK-003–TSK-009.
  - **Requirements:** R1–R10, NFR1–NFR5.

  - **Факт:** `1963 passed`; устаревшие тесты удалённой модели переписаны, а не ослаблены: `correlation`/`vless` сняты, `selftest`/`operator_views`/`agent`/`telegram` переведены на новый контракт. Мой тест на `patch(..., return_value=fw)` вскрыл, что `assert returned_value.called` вакуумный — исправлено на проверку самого patch-мока. LSP-проба по спорным файлам: 0 реальных диагностик (остальное — шум анализатора на тест-дублях).
- [x] **TSK-011 — Rewrite AntiDPI operational documentation as AntiScan policy**
  - **Objective:** Make public/operator documentation match the narrowed behavior.
  - **Files:** `docs/ANTIDPI.md`, relevant sections of `docs/ARCHITECTURE.md`, `docs/REFERENCE.md`, `docs/README.md`, `docs/TELEGRAM_BOT.md`, `README.md` and `CHANGELOG.md` if user-visible release notes require it.
  - **Deliverables:**
    - document exact supported evidence matrix and unsupported protocols;
    - remove claims about TLS noise, kernel scans, UDP probes, scoring and subnet correlation;
    - document one-evidence direct ban, progressive durations, notification behavior, fixture gate and rollback;
    - preserve the stable `antidpi` machine key while explaining the AntiScan role.
  - **Acceptance:** documentation contains no behavior contradicted by tests or implementation; links and command examples remain valid.
  - **Dependencies:** TSK-007–TSK-009.
  - **Requirements:** R3–R9, NFR5.

  - **Факт:** `docs/ANTIDPI.md` переписан как политика AntiScan (закрытый контракт улик, доказательство Snell, decoy-пути, матрица протоколов с причинами, политика BAN, эксплуатация, порядок добавления протокола). Обновлены `ARCHITECTURE.md`, `REFERENCE.md`, `TELEGRAM_BOT.md`, `CLI.md`, `README.md`, `docs/README.md` и добавлена запись в `CHANGELOG.md`. Попутно снят ещё один хвост: Caddy больше **не пишет** `antidpi.jsonl` (producer удалён из `sni_router_document`), потому что читателя у него не осталось; заодно исправлен реальный конфликт типов `RenderSettings` (Protocol требовал изменяемые `dict`, dataclass даёт `Mapping`). Проверено: 1963 passed, ruff чист, compileall OK, битых md-ссылок нет, все 14 анкоров ANTIDPI.md разрешаются.
- [x] **TSK-012 — Run focused local verification and fix all red results**
  - **Objective:** Prove the implementation and documentation are internally consistent before VPS testing.
  - **Commands:**
    1. focused AntiDPI tests selected during implementation;
    2. `python -m pytest -q tests/test_antidpi*.py`;
    3. `python -m pytest -q tests/test_architecture_graph.py tests/test_architecture_audit.py tests/test_architecture_size_limits.py`;
    4. `python -m ruff check main.py hydra tests`;
    5. `python verify.py` when focused checks are green and the complete run is proportionate.
  - **Acceptance:** every executed command exits `0`; failures are fixed and rerun rather than waived; Windows limitations are recorded.
  - **Dependencies:** TSK-010, TSK-011.
  - **Requirements:** R10, NFR1–NFR5.

  - **Факт:** `pytest -q` → 1963 passed; архитектурные guard'ы + `test_plugin_purity.py` → 32 passed; `ruff check main.py hydra tests` → All checks passed; `compileall` → OK. Windows: Linux integration по-прежнему не выполнялась (см. TSK-013).
- [ ] **TSK-013 — Execute Linux acceptance and close the spec**
  - **Objective:** Prove the live evidence-to-ban path and finish traceability for handoff/release.
  - **Deliverables:**
    - wrong-data attempts for every enabled protocol adapter;
    - one scanner-path and one normal-path decoy request;
    - generic TLS/unknown-SNI replay;
    - inspection confirming obsolete telemetry rules/services are absent;
    - captured ban, state and Telegram outcomes with secrets removed;
    - final requirements status, task facts and Progress table update.
  - **Acceptance:**
    - each enabled protocol and scanner-path attempt produces exactly one ban and one BAN notification;
    - normal decoy and generic TLS traffic produce no event/message/state mutation;
    - failed enforcement is reported as failure, never success;
    - rollback procedure is exercised or statically evidenced on the disposable host;
    - all requirements have linked evidence.
  - **Dependencies:** TSK-002, TSK-012; disposable Linux/VPS environment.
  - **Requirements:** R1–R10, NFR1–NFR5.

## Requirement coverage

| Requirement | Tasks |
| --- | --- |
| R1 | TSK-001, TSK-003–TSK-007, TSK-010, TSK-013 |
| R2 | TSK-002–TSK-005, TSK-010, TSK-013 |
| R3 | TSK-002, TSK-005, TSK-010–TSK-013 |
| R4 | TSK-004, TSK-007, TSK-010–TSK-013 |
| R5 | TSK-002–TSK-005, TSK-007, TSK-009–TSK-013 |
| R6 | TSK-006, TSK-010–TSK-013 |
| R7 | TSK-004, TSK-007–TSK-010, TSK-012–TSK-013 |
| R8 | TSK-004, TSK-008–TSK-013 |
| R9 | TSK-003–TSK-004, TSK-007–TSK-013 |
| R10 | TSK-002–TSK-006, TSK-010, TSK-012–TSK-013 |
| NFR1–NFR5 | TSK-002–TSK-013 |

## Definition of done

- [ ] Every enabled adapter has approved production evidence.
- [ ] Only `protocol_reject` and `decoy_scan` can initiate automatic bans.
- [ ] Weak observations create no event, state, firewall call or Telegram message.
- [ ] Existing ban/state/lifecycle compatibility remains intact.
- [ ] Obsolete collectors and host telemetry are removed idempotently.
- [ ] Local verification is green.
- [ ] Disposable Linux acceptance is green.
- [ ] Requirements, design, tasks, ADR and public documentation agree.
