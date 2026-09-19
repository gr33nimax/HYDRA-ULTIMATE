# Design: AntiDPI evidence contraction into AntiScan

**Version:** 1.0  
**Date:** 2026-09-16  
**Status:** Design approved 2026-09-16  
**Requirements:** [requirements.md](requirements.md)  
**Decision:** [.kiro/decisions/0003-antidpi-closed-evidence.md](../../decisions/0003-antidpi-closed-evidence.md)

## Overview

The implementation keeps the existing `antidpi` plugin identity, state store, ban lifecycle, firewall reconciliation and operator entry points, but removes the broad observation/scoring pipeline from production behavior.

The new pipeline has one rule:

```text
strict parser + exact external attribution
                 │
                 ├─ protocol-owned reject ─┐
                 └─ decoy scanner path ────┤
                                           v
                                  immediate ban intent
                                           │
                          ┌────────────────┴────────────────┐
                          v                                 v
                    firewall accepted                firewall failed
                    persist active ban               persist failure
                    Telegram BAN                     bounded failure notice
```

Every other input terminates at the parser boundary. There is no alert-only path, score accumulation, evidence-family correlation or subnet inference.

## Design goals

1. Make every automatic ban explainable by one exact evidence record.
2. Remove weak observers instead of muting their notifications downstream.
3. Reuse existing state locking, progressive ban durations, ipset enforcement, reconciliation and compatibility facades.
4. Require production fixtures before a protocol adapter can become active.
5. Reduce code and runtime surfaces; introduce no framework, process, dependency or configurable rule engine.

## Non-goals

- Generic TLS or Internet-noise monitoring.
- Port/UDP scan detection.
- Multi-signal threat scoring.
- ASN/Geo reputation decisions.
- A pluggable detector framework.
- A persisted state-schema rename from `antidpi` to `antiscan`.

## Research findings

Upstream source establishes a small set of typed rejection paths:

- AnyTLS returns `anytls: authentication failed` when the received password digest is absent or unknown; sing-box wraps the returned error with `process connection from <source>`.
- VLESS returns `unknown UUID: <uuid>` from its service and sing-box wraps it with the inbound source.
- Naive rejects failed Basic proxy authentication with `407` and logs `authorization failed` through a function that includes `request.RemoteAddr`.
- Snell multi-user services return typed `snell: bad user key`; `ServerError` carries the source peer.
- ShadowTLS v3 deliberately falls back after failed ClientHello verification and therefore does not expose a safely attributable enforcement event.
- Hysteria2 deliberately serves the masquerade handler after failed protocol authentication and does not expose a stable rejection event suitable for this contract.

Primary sources:

1. <https://github.com/SagerNet/sing-anytls/blob/cec2d74334be6e3ae6d319d48bd32839e107e3aa/service.go#L83-L132>
2. <https://github.com/SagerNet/sing-box/blob/6e0520ecb5c56fcd697ef5cc80ca5496fa22f287/protocol/anytls/inbound.go#L101-L115>
3. <https://github.com/SagerNet/sing-vmess/blob/31ec11e8790c48a4bf11711806a61e929ee6b89d/vless/service.go#L55-L64>
4. <https://github.com/SagerNet/sing-box/blob/6e0520ecb5c56fcd697ef5cc80ca5496fa22f287/protocol/vless/inbound.go#L154-L168>
5. <https://github.com/SagerNet/sing-box/blob/6e0520ecb5c56fcd697ef5cc80ca5496fa22f287/protocol/naive/inbound.go#L158-L170>
6. <https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snell.go#L70-L82>
7. <https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv5/server.go#L211-L223>
8. <https://github.com/SagerNet/sing-shadowtls/blob/2d5886b68fad10d098af94a6814479c81a0e4129/service.go#L132-L151>
9. <https://github.com/apernet/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/core/server/server.go#L225-L240>

These sources prove upstream semantics, not the exact deployed log rendering. A sanitized VPS capture remains the activation gate for each adapter.

## Architecture

### Existing components retained

| Component | Retained responsibility |
| --- | --- |
| `AntiDPIPlugin` | public plugin contract, lifecycle, operator commands |
| `AntiDPIStateStore` | locked atomic plugin-state transactions and corruption handling |
| firewall/ipset helpers | apply/release/reconcile active bans |
| ban duration helpers | progressive durations and offense counts |
| whitelist helpers | trusted networks and host-address exclusion |
| source relay | exact `protocol + relay source port` resolution |
| compatibility facades | stable imports and plugin key |

### Components narrowed or removed from the production path

| Area | Design change |
| --- | --- |
| `adapters.py` | Replace broad substring patterns with a small anchored protocol allowlist and named peer captures. |
| `normalization.py` | Keep exact decoy-path normalization and only protocol-owned structured rejects; remove generic TLS/status inference. |
| `agent.py` | Stop tailing generic TLS/kernel telemetry and stop creating UDP/Mieru/AWG observers. |
| `detection.py` | Replace score/correlation decision with validation of an already proven evidence event and direct ban intent. |
| `model.py` | Retain ban/expiry/manual-ban helpers; remove signal weights and score functions from runtime use. |
| `correlation.py` | Remove from production decision flow; delete if no compatibility contract or test requires it. |
| firewall telemetry | Remove scan, UDP-probe and Mieru inference rules plus their reconciliation steps. |
| operator views | Remove watchlist/score-centric output; show active/recent bans and evidence source. |
| notifier | Eliminate observational ALERT; emit BAN or bounded enforcement failure only. |

### Dependency direction

The change does not alter architectural layers:

```text
agent/adapters/normalization
          │
          v
AntiDPIPlugin detector service
          │
          ├── AntiDPIStateStore
          ├── firewall helpers / HostBackend
          └── notifier callback
```

Pure parsers remain free of filesystem, subprocess, systemd and persistence dependencies.

## Evidence model

Use the existing dictionary event transport; do not introduce a new class hierarchy.

An accepted event has this closed schema:

```python
{
    "kind": "protocol_reject" | "decoy_scan",
    "protocol": "anytls" | "vless" | "naive" | "snell" | "trusttunnel" | "https",
    "reason": "authentication_failed" | "unknown_uuid" | "bad_user_key" | "scanner_path",
    "source": "journal" | "caddy-naive" | "caddy-decoy" | "caddy-trusttunnel",
    "attribution": "direct" | "relay-exact",
    "path": "/.env",  # decoy_scan only; bounded/redacted
}
```

The external address remains the tuple key returned beside the event and is validated before state mutation.

### Validation invariants

- `kind`, `protocol`, `reason`, `source` and `attribution` must belong to fixed sets.
- `protocol_reject` must use a protocol/reason/source combination declared in code.
- `relay-exact` requires a successful exact source-relay lookup; no time-window fallback.
- Loopback, private, host-owned and configured-whitelist addresses are rejected.
- Credential material and raw authorization data never enter the event.
- An invalid or unknown combination returns `None`; it is not converted to a generic event.

## Protocol adapter design

### AnyTLS

Accept only the deployed full error grammar that includes:

- exact AnyTLS inbound/service owner;
- `process connection from <peer>`;
- `anytls: authentication failed`;
- fallback-disabled conclusion where applicable.

When the backend peer is loopback, require exact relay-port mapping. Generic TLS failure and `EOF: fallback disabled` are not accepted.

### VLESS

Accept only native VLESS inbound rejects whose cause is an exact unknown UUID/authentication error and whose backend peer is direct or exactly relay-mapped.

Remove status-only classification from `normalize_vless_record()`. A request to the configured XHTTP path becomes protocol evidence only when correlated by exact connection identity to a native reject; temporal proximity is forbidden. If the deployed logs cannot supply that identity, only the native reject path is eligible.

### Naive

Accept the deployed implementation's explicit invalid-user/authorization-failed marker on the protocol CONNECT auth gate. A bare `401/407` access status is insufficient.

The record must provide the external peer directly or through exact relay mapping. Scanner paths on the Naive decoy remain separate `decoy_scan` events.

### Snell

Accept only the deployed typed bad-user-key error (or byte-equivalent rendered form) with direct TCP source. Generic malformed HTTP, handshake failure and connection-close text are not accepted unless a future typed upstream error and production fixture prove the semantic.

### TrustTunnel

Keep disabled initially. Enable only after a sanitized deployed capture proves a native token/authentication reject and exact external attribution. A status-only CONNECT record is insufficient.

### Unsupported protocols

ShadowTLS, Hysteria2, Mieru, Telemt, AmneziaWG, qWDTT and Calls have no active adapter. Their services do not enter the collector filter merely to produce discarded records.

## Decoy scan design

Keep a static code allowlist in `normalization.py`; no user-configurable regex engine.

A request qualifies only when:

1. it comes from a logger attached to an enabled decoy surface;
2. the external public IP is present directly;
3. the normalized path, excluding query text, matches an existing high-confidence token;
4. the address is not trusted, host-owned or whitelisted.

Method-only classification is removed. Normal paths and arbitrary 404 responses return `None`.

## Decision flow

```text
collector record
  └─ strict source-specific parser
       ├─ no match → discard
       └─ candidate
            └─ exact attribution + whitelist validation
                 ├─ fail → discard
                 └─ accepted evidence
                      └─ state transaction
                           ├─ active ban exists → record bounded duplicate only; no notification
                           └─ no active ban
                                └─ request firewall ban
                                     ├─ success → record ban + one BAN notification
                                     └─ failure → record failure + bounded failure notification
```

No score threshold or family correlation is consulted.

## State and compatibility

The plugin-owned JSON remains backward readable; no `AppState` schema change is required.

### Retained fields

- active bans and expiry;
- manual bans;
- offense/ban counts used for progressive durations;
- enforcement failures and reconciliation state;
- bounded recent ban history;
- notification delivery counters needed operationally.

### Legacy fields

Legacy `scores`, `signals`, `signal_counts`, subnet ledgers and watchlist data may remain on disk for rollback compatibility, but the new runtime never reads them for classification or enforcement and never appends to them.

No destructive state migration is performed. Rolling back code restores the old reader without requiring a state restore.

### New history record

A successful automatic ban records only bounded non-secret evidence:

```python
{
    "ip": "203.0.113.7",
    "kind": "protocol_reject",
    "protocol": "vless",
    "reason": "unknown_uuid",
    "source": "journal",
    "attribution": "relay-exact",
    "at": 1789550000.0,
    "duration": 600,
}
```

## Collector and host lifecycle

### Remove

- generic Caddy L4 TLS error tail;
- kernel scan parsing and journal filters;
- UDP probe synchronization;
- Mieru short-session synchronization;
- AmneziaWG dynamic-debug service used only by AntiDPI;
- scan/UDP/Mieru LOG rule creation, reconciliation and health requirements.

### Keep

- protocol journald records only for enabled strict adapters;
- decoy access JSON tail;
- protocol-specific access logs needed by an enabled strict adapter;
- heartbeat, state locking, cursor durability and ban reconciliation.

Upgrade/apply must remove obsolete AntiDPI-owned telemetry rules and artifacts idempotently. Rollback remains code/package rollback; retained state and ban sets are compatible.

## Telegram and operator surfaces

### Telegram

`BAN` contains:

- external IP and optional Geo/owner enrichment;
- `protocol_reject` or `decoy_scan`;
- protocol and bounded reason;
- source and attribution method;
- ban duration.

It must not contain credentials, UUID values, tokens or raw log lines.

No discarded input can call the notifier. Firewall failure uses a distinct operational failure action and cooldown.

### TUI/CLI/status

- Keep plugin enable/disable, manual ban/unban, active bans and health.
- Replace score/watchlist language with evidence/bans.
- Display name may be `AntiScan`; stable machine key remains `antidpi`.
- Health no longer requires removed telemetry rules.

## Error handling

| Failure | Behavior |
| --- | --- |
| malformed record | return `None`; no state mutation |
| unknown protocol/reason pair | return `None` |
| missing or ambiguous peer | discard and increment only an in-memory/debug diagnostic if needed |
| exact relay lookup miss | discard; no temporal fallback |
| state corruption | preserve existing quarantine/degraded behavior |
| firewall ban rejected | preserve failure, do not record active ban, send bounded failure notice |
| notifier failure after successful ban | keep ban and record delivery failure; do not roll back enforcement |
| obsolete rule cleanup failure | surface degraded reconciliation with exact failed step |

## Testing strategy

### Fixture provenance gate

Store sanitized captures under `tests/fixtures/antidpi/` with a small manifest containing protocol, upstream/deployed version, capture command, redactions and expected external attribution. Do not store secrets or raw UUIDs.

Only adapters with a reviewed fixture are placed in the production allowlist.

### Unit tests

- exact positive parser fixture per enabled protocol;
- near-miss negatives for generic wording and unrelated service tags;
- direct and exact-relay attribution;
- loopback/private/whitelist rejection;
- decoy path positive and normal/query-only negative cases;
- event-schema validation and secret redaction.

### Decision tests

- one accepted event requests one ban using the existing first duration;
- active-ban duplicate does not notify again;
- enforcement failure does not claim success;
- discarded input changes no state and calls neither firewall nor notifier;
- legacy score data has no effect on decisions.

### Integration and architecture tests

- collector subscribes only to retained sources;
- obsolete firewall telemetry is removed during apply/reconcile;
- compatibility imports/plugin key remain stable;
- state corruption, locking, cursor and ban reconciliation regressions remain green;
- architecture graph/size guards and Ruff pass.

### Live Linux verification

On a disposable compatible VPS:

1. attempt each enabled protocol with deliberately incorrect data;
2. capture the exact log and relay mapping;
3. verify one ban and one Telegram BAN;
4. replay generic TLS/unknown-SNI traffic and verify complete silence;
5. request one scanner path and one normal decoy path;
6. verify obsolete telemetry rules/services are absent after reconciliation.

Local Windows tests cannot replace this gate.

## Requirement traceability

| Requirement | Design coverage |
| --- | --- |
| R1–R2 | strict parser boundary, evidence schema, exact attribution |
| R3, R5, R10 | protocol adapter matrix and fixture provenance gate |
| R4 | collector/lifecycle removals and unsupported adapters |
| R6 | decoy scan normalization |
| R7 | direct decision flow and retained enforcement |
| R8 | Telegram/operator surfaces |
| R9 | state and compatibility |
| NFR1–NFR5 | validation invariants, no dependencies/processes, retained boundaries |

## Rollback

1. Revert the feature code/package while leaving plugin state intact.
2. Reconcile the prior AntiDPI runtime through its existing apply path.
3. If obsolete telemetry had been removed, the prior version recreates its owned rules/services.
4. Existing bans and offense counts remain readable in both directions.

## Amendment design — Snell false-positive ban withdrawal (2026-09-19)

**Version:** 1.1 (amendment)
**Requirements:** `requirements.md` → «Requirements amendment — Snell false-positive ban withdrawal (2026-09-19)»
**Status:** design ready, awaiting implementation

### Problem statement (verified, not assumed)

| Fact | Evidence |
| --- | --- |
| The Snell grammar binds any inbound tag | `hydra/plugins/antidpi/adapters.py:27` — `inbound/snell\[[^\]]+\]` |
| The matched tag is discarded before the event exists | `hydra/plugins/antidpi/adapters.py:84-98` — the returned dict carries protocol/reason/source/attribution, no tag |
| The state reader is deliberately unused | `hydra/plugins/antidpi/agent.py:194-197` — `del state_reader` |
| One reject is enough to ban | `hydra/plugins/antidpi/detection.py:178` — `should_ban=not active_ban` |
| Enforcement path is `ipset add` + `INPUT DROP` | `hydra/plugins/antidpi/detector_service.py:259-300`, `:314-354` |
| The current suite locks this in | `tests/test_antidpi.py:87-101`, `tests/test_antidpi_adapters.py:57-78` |

Two mechanisms produce the reported false positive, and the code cannot distinguish them:

1. a legitimate client whose PSK is stale, mistyped or generated for another generation — the wire
   result is byte-identical to a hostile probe;
2. an orphaned or retired Snell listener still present in the running core configuration: its tag
   matches the wildcard grammar and no comparison against desired state ever happens.

Neither is a parser bug. The defect is the **policy**: `record_auth_failed` is treated as proof of
hostility, and tag ownership is never checked.

### Decision D-A — Snell leaves the automatic enforcement allowlist

The single authoritative change is the evidence contract, not the parser:

```python
# hydra/plugins/antidpi/detection.py
PROTOCOL_REJECT_RULES: dict[str, frozenset[str]] = {}   # was {"snell": {"record_auth_failed"}}
```

Consequences, all of them intentional:

- `evidence_problem()` returns `"protocol snell has no proven reject"` for the existing event;
- `observe_event()` takes the discard branch: no state mutation, no firewall call, no `BAN`, no
  score, no watchlist entry — while still advancing the journal cursor, so a discarded record is
  never replayed (`detector_service.py:334-347`);
- `decoy_scan` enforcement and manual bans are untouched;
- existing active bans keep their recorded TTL and expire normally; offense counts stay readable.

This is a one-line contract change with the smallest possible rollback surface. Reverting the line
restores the previous behavior exactly, with no state migration in either direction.

### Decision D-B — the parser survives as a diagnostic, not as an enforcement input

The Snell grammar, its sanitized fixture and the journal stream are **kept**, because they are the
only mechanism that can answer the open question «does a discriminator between a hostile probe and
credential drift exist?». They are demoted, not deleted:

- `adapters._PROTOCOL_REJECTS` keeps its anchored grammar and gains a docstring stating that it is a
  diagnostic parser with no enforcement consumer while `PROTOCOL_REJECT_RULES` is empty;
- `hydra antidpi capture` / `selftest` keep collecting and redacting the records;
- nothing in the parser can reach `ipset`, state or Telegram by itself — `detection.py` is the only
  gate, and it is closed.

Deleting the collector instead would remove the very evidence a future enabling task needs, and
would enlarge the rollback surface for no behavioral gain.

### Decision D-C — tag ownership becomes a precondition for the next adapter

A wildcard inbound tag SHALL NOT be accepted again. The requirement is recorded where the enabling
procedure lives (`docs/ANTIDPI.md` §13) and here, and it must be implemented **together with** the
next adapter rather than as dead code today:

1. the protocol plugin exposes the tags its current desired state generates
   (`snell` already does: `hydra/plugins/snell/plugin.py:73-99`; attribution already resolves them:
   `hydra/services/traffic_attribution.py:287-302`);
2. the journal normalizer compares the matched tag against that set and drops non-matching records
   before an event exists — this is the layer that has `state_reader`, and it is the layer where the
   `del state_reader` placeholder currently sits (`agent.py:194-197`);
3. the enabling task's acceptance SHALL include a negative fixture: an exact reject on an unowned or
   retired tag produces no event, no state, no firewall call and no notification.

No matcher is written now: with `PROTOCOL_REJECT_RULES` empty there is no consumer, and a guard for
an adapter that does not exist is speculative code.

### Decision D-D — the self-test states what it actually proves

`selftest_targets.SUPPORTED_PROTOCOLS = ("snell",)` and the probe remain, but the report SHALL claim
parser/plumbing coverage («the parser sees this reject and the pipeline archives it redacted»), not
enforceability. The journal-path, redaction and archive coverage is genuinely valuable and would be
lost by removing the probe; the misleading claim is what changes.

### Decision D-E — no state schema change, no migration

The plugin key `antidpi`, `SCHEMA_VERSION`, the state file layout, the ban ladder, the ipset set name
and the systemd unit are unchanged. Withdrawing a rule cannot require a migration: nothing is
written differently, only fewer events are accepted.

### Surfaces that change

| Surface | Change |
| --- | --- |
| `hydra/plugins/antidpi/detection.py` | `PROTOCOL_REJECT_RULES` emptied; comment states why |
| `hydra/plugins/antidpi/adapters.py` | docstring: diagnostic-only parser |
| `hydra/plugins/antidpi/labels.py` | `snell:record_auth_failed` label marked as historical evidence, not an enforceable signal |
| `hydra/plugins/antidpi/selftest_report.py` / `selftest.py` | wording: parser proof, not enforcement proof |
| `docs/ANTIDPI.md` | §3, §6 matrix, §12 self-test, §13 enabling checklist |
| `CHANGELOG.md` | new top entry: the withdrawal and its reason |
| `tests/test_antidpi*.py` | enforcement assertions flipped to discard assertions |

### Error handling

| Failure | Behavior |
| --- | --- |
| Snell record arrives after the change | discarded, cursor advanced, nothing observable |
| Operator expected a Snell ban | status/history shows no new bans; the withdrawal is documented, not silent |
| Legacy ban record already persisted | kept and expired normally; no rewrite, no retroactive unban |
| Decoy path still enforced | unchanged code path, unchanged tests |
| Rollback | revert the allowlist line; the parser, fixtures and docs remain valid |

### Testing strategy

- **Contract:** an exact fixture line yields `evidence_problem() != ""` and
  `is_enforcement_evidence(...) is False` — the current positive assertion is inverted, not deleted,
  because the approved requirement changed.
- **No side effects:** the exact fixture line produces no state mutation, no firewall call and no
  notification through `AntiDPIPlugin.observe_event`.
- **Parser intact:** the fixture still parses (tag, peer and served address agreement still proven),
  so the diagnostic value is not silently lost.
- **Unowned tag:** an otherwise exact reject carrying an unknown or retired tag produces no event.
- **Unchanged:** decoy-scan ban, manual ban, expiry, whitelist, reconciliation, cursor durability,
  state corruption and compatibility facades stay green.
- **Architecture:** graph/audit/size guards and Ruff pass; no new import, process or dependency.

### Requirement traceability

| Amendment requirement | Design coverage |
| --- | --- |
| No automatic ban from a Snell auth failure | D-A |
| Snell absent from the allowlist until a proven discriminator exists | D-A, D-B |
| Owned-tag verification before any future enforcement | D-C |
| Manual bans and decoy enforcement unchanged | D-A, D-E |
| Evidence, not promises | Testing strategy, D-D |

### Rollback

1. Restore the single `PROTOCOL_REJECT_RULES` entry.
2. No state restore, no migration, no host action: persisted bans, cursors and offense counts are
   compatible in both directions.
3. Re-run `pytest -q tests/test_antidpi*.py` and confirm the pre-amendment assertions pass again.

### Note on the decision journal

`scripts/decisions.mjs` is absent from this repository (verified), so the ADR-light workflow cannot
be executed here. The architectural choice is recorded in this design extension, as already done for
`.kiro/specs/vless-yandex-cdn/design.md` (D10–D12).

## Links

- Requirements: `.kiro/specs/antidpi-evidence-contraction/requirements.md`
- Decision: `.kiro/decisions/0003-antidpi-closed-evidence.md`
- Current policy documentation: `docs/ANTIDPI.md`
- Related spec: `.kiro/specs/vless-yandex-cdn/`
