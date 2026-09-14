# Design: complete AmneziaWG 2.x / 3.x module update

## 1. Decision and boundary

HYDRA will treat AWG 3.x as a **generation-wide runtime property**, not as an extra legacy preset. It will keep using `wiresock/amneziawg-install` to generate, probe, migrate, and reverse-migrate protocol-specific material. HYDRA will then read that material once, validate it, project it to both managed interfaces and to each export format that has proven support.

This avoids the dangerous alternative: letting several Hydra renderers independently invent `HeaderProtectionKey`, timers, or `RandomTrailers` values.

| Concern | Owner |
| --- | --- |
| Generate/probe/migrate AWG generation | upstream installer/runtime |
| Desired generation and transaction | HYDRA plugin command service |
| Read/validate/preserve directives | HYDRA typed directive model |
| Legacy per-profile obfuscation presets | existing HYDRA profile logic |
| Client export capability | renderer-specific adapter |
| Rollback | existing `PluginCommandService` + extended AWG snapshot |

Accepted decision: `.kiro/decisions/0002-awg-generation-upstream-ownership.md`.

## 2. Facts and constraints

Upstream exposes non-interactive commands:

| Mode | Command |
| --- | --- |
| observe | `--protocol-status` |
| 2.0 | `--disable-awg3` |
| 3.0 | `--enable-awg3` |
| 3.1 | `--enable-awg31` |

AWG 3.0 introduces `HeaderProtectionKey`, `ContentPaddingAddition`, and the rekey/timeout directives. AWG 3.1 additionally introduces `RandomTrailers`; it must agree at both endpoints. `DisableCookies` removes Cookie Reply anti-DoS protection and stays disabled—not a normal tuning control.

The two HYDRA interfaces (`awg0`, `awg1`) are materialized by HYDRA, while upstream migrates its managed primary interface. Therefore HYDRA must copy only the **upstream-generated, validated generation-directive subset** from the primary interface to the secondary one; it must not generate or guess values.

Sources: <https://github.com/wiresock/amneziawg-install/blob/main/amneziawg-install.sh>, <https://docs.amnezia.org/documentation/amnezia-wg/>, <https://github.com/amnezia-vpn/amneziawg-go>.

## 3. Data ownership

### Desired state

```python
# state.protocols["amneziawg"].config
{
    "protocol_mode": "2.0",  # omitted legacy value normalizes to 2.0
    "profiles": {
        "desktop": {
            "preset": "wired",
            "obfuscation": {"Jc": 12, "Jmin": 50, ...},
        },
    },
}
```

Only the selected mode and existing legacy profile settings live in desired state. `HeaderProtectionKey` and other upstream-generated protocol directives remain only in the managed `0600` AWG files. This prevents a second secret source of truth.

### Directive categories

`hydra/plugins/amneziawg/directives.py` will be the one parser/model owner.

| Category | Directives | Scope |
| --- | --- | --- |
| Legacy transport obfuscation | `Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4`, `I1` | existing profile-local preset |
| AWG 3.0 protocol | `HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout` | generation-wide, upstream-owned |
| AWG 3.1 protocol | `RandomTrailers`, `DisableCookies` | generation-wide, upstream-owned |
| Unknown | any other `[Interface]` key | lossless passthrough; never deleted |

`AwgInterfaceDirectives` parses a single `[Interface]` block into typed known values plus ordered unknown entries. It provides:

- strict duplicate/malformed/generation validation;
- `for_mode(mode)`, which rejects absent required fields and rejects 3.x fields in mode 2.0;
- `replace_generation_directives(interface_text, source)`, which changes only known generation keys and leaves peer blocks, legacy fields, and unknown keys intact;
- redacted `summary()` for status/UI.

The validator checks syntax and cross-profile equality. It does not claim a client runtime supports a field; that belongs to the export adapter.

## 4. Module changes

| Module | Change |
| --- | --- |
| `constants.py` | Split legacy and generation directive names; retain compatibility aliases only where callers require them. |
| `directives.py` (new) | Typed parser, validation, redaction, lossless reconciliation. |
| `installation.py` | Managed installer identity check; argv adapter for status/migration commands with bounded timeout and redacted failures. |
| `profiles.py` | Retain existing strategy/carrier behavior; rotation modifies legacy keys only. |
| `configuration.py` | Parse primary upstream interface; reconcile legacy profile fields while preserving unknowns; propagate validated AWG 3.x subset to `awg1`; validate before write. |
| `runtime.py` | Extend snapshot and rollback to `awg0.conf`, `awg1.conf`, `params`, installer revision/identity, and enabled/active service state. |
| `observation.py` | Desired/observed mode, redacted directive summary, and export compatibility—not raw values. |
| `client_links.py` | Use directive model and renderer adapters; never iterate one legacy key tuple for all outputs. |
| `services/subscriptions/serialization.py` | Explicit NekoBox adapter and versioned capability gate. |
| `plugin.py` | Add command capability `set_protocol_mode`; compose the small mode mixin. |
| AWG TUI files | Add mode/status action through `PluginCommandService`; retain existing strategy wizard. |
| CLI metadata | Allowlist `set_protocol_mode mode=<2.0, 3.0, 3.1>`; no UI/CLI host calls. |

New components stay small; the existing facade `plugin.py` remains composition-only.

## 5. Mode command and transaction

`AwgProtocolModeMixin.set_protocol_mode(state, mode)` is invoked through `PluginCommandService`, which already snapshots desired state and calls plugin snapshot/rollback around central configuration apply.

```text
validate requested canonical mode
  -> verify installed, managed upstream checkout and params
  -> observe --protocol-status
  -> no-op if desired == observed == requested
  -> preflight all requested export policies
  -> upstream migration command
  -> observe mode again and parse primary directives
  -> write requested desired mode only in in-memory state
  -> PluginCommandService central apply
       -> reconcile awg0 + propagate generation subset to awg1
       -> apply both interfaces and verify health
       -> persist state on success
  -> on exception/apply failure: plugin rollback + desired-state restore
```

A mismatch between desired and observed before a request is not silently fixed. The status exposes drift and the administrator explicitly selects the requested repair mode.

### Snapshot / rollback

The AWG snapshot contains file bytes and modes for both configs and `params`, installer Git `HEAD`/remote identity, plus systemd enabled/active state for both interfaces. Rollback restores files atomically with `0600`, daemon-reloads when needed, restores service enablement/activity, and re-applies the previous config. The original migration/apply exception remains the primary error; rollback failure is appended as recovery evidence.

No migration touches an unmanaged interface or checkout whose remote/revision cannot be identified.

## 6. Legacy obfuscation strategy behavior

The existing `wired`, `mobile`, `stealth`, `low_latency` and carrier presets remain the operator-facing choices for `J*`, `S*`, `H*`, and `I1`.

| Operation | Legacy directives | AWG 3.x directives |
| --- | --- | --- |
| Change preset | regenerate validated profile-local values | preserve verbatim |
| Rotate obfuscation | regenerate validated profile-local values | preserve verbatim |
| Switch mode | preserve | upstream generates/removes, then HYDRA validates/projects |
| Reconcile peer | preserve unless profile update requests change | preserve/verbatim copy from primary |

There is intentionally no raw AWG 3.x field editor in this feature. It would create two competing authorities, allow one-sided `RandomTrailers`, and expose a foot-gun around `DisableCookies`. A future advanced policy feature may add explicit requirements, validation and a client-impact warning.

## 7. Export capability matrix

Current code drops every AWG 3.x directive from `.conf`, URI, NekoBox and Sing-box paths. The new design makes that inability explicit.

| Export | 2.0 | 3.0/3.1 initial policy | Evidence required to claim 3.x support |
| --- | --- | --- | --- |
| Native `.conf` | supported | render complete validated directives | golden config + compatible client handshake smoke |
| `wg://` | existing legacy serializer | unavailable until grammar/version supports all required fields | versioned URI grammar + import smoke |
| Official `vpn://` | existing legacy serializer | unavailable until official payload schema supports all required fields | official schema + import smoke |
| NekoBox `sn://awg` | existing legacy binary layout | unavailable; fixed serializer must not truncate fields | versioned layout + import smoke |
| Sing-box/HydraBox | existing legacy projection | unavailable; do not advertise support | verified released runtime capability + connection smoke |

For an unavailable export, the plugin returns no AWG artifact and a stable reason such as `awg_3_1_not_supported_by_singbox`. It never emits a partial profile. Native `.conf` remains available as the safe delivery route for compatible clients.

When an export gains proof, it becomes a dedicated adapter with generation-specific golden tests; it does not alter generic directive parsing.

## 8. Presentation and operator flow

The AWG menu shows:

```text
Generation: desired 3.1 / observed 3.1
Legacy strategy: desktop wired; mobile MTS
Protocol directives: AWG 3.1 present; Cookie Reply protection enabled
Exports: .conf ready; vpn:// unavailable for AWG 3.1; sing-box unavailable
```

No keys, timer values, padding values, or `RandomTrailers` are printed. The mode selector warns before transition that existing 2.0-only clients stop connecting and offers the safe `2.0` return path. CLI emits the same normalized fields in JSON/text.

## 9. Error policy

| Failure | Result |
| --- | --- |
| invalid mode/directive | reject before host mutation |
| absent/mismatched managed checkout | reject before host mutation |
| upstream 3.x capability rejection | rollback; report kernel/tools incompatibility |
| malformed/missing directive after migration | rollback; no desired-state commit |
| client renderer lacks active mode | omit only that artifact with reason; no partial link |
| interface apply or health failure | restore files/services/state and reapply former config |
| selecting active mode | no-op; no restart |

## 10. Test plan

1. `directives.py`: parse, duplicate rejection, unknown-key preservation, 2.0/3.0/3.1 validation, redaction, bilateral `RandomTrailers` equality.
2. Plugin command: legacy default, validation, installer command selection, no-op, drift report, migration and every rollback boundary.
3. Configuration/runtime: two-interface propagation, preset/rotation preservation, params/service snapshot and restoration.
4. Renderer golden tests: byte-identical 2.0 regression; complete 3.x native `.conf`; explicit omission/reason for each unsupported output.
5. UI/CLI/status: application-service-only dispatch and redacted display.
6. Architecture and size guards.
7. Disposable Linux smoke: `2.0 → 3.0 → 3.1 → 2.0`, primary and secondary interface health, compatible native client handshake, injected migration/apply rollback.

## 11. Documentation

Update `docs/REFERENCE.md`, `docs/CLI.md`, the AWG section of `README.md`, and `CHANGELOG.md`. Correct the unsupported I1–I5/J1–J3/Itime claim rather than extending it by assertion.

## 12. Extension design (2026-09-08): evidence-gated AWG 3.x external formats

### Research findings

| Target | Version/evidence | Proven mode | Decision |
| --- | --- | --- | --- |
| Sing-Box Extended / HydraBox | Tags `v1.14.0-extended-2.7.0` and `2.7.1`, `option/wireguard.go` | 3.0 | Release notes claim 3.1 integration, but both exact source tags omit `random_trailers` / `disable_cookies`; permit only complete 3.0 endpoint until source and binary contracts reconcile. |
| Throne | `1.3.0-beta.3`, `src/ui/profile/edit_wireguard_amnezia.cpp` | 3.1 | Its native `wg://` parser/editor reads and writes every 3.0 field plus `random_trailers` and `disable_cookies`; extend the existing WG URI serializer, retain `DisableCookies=false`, and add a version-pinned import regression. |
| Official Amnezia `vpn://` | `amnezia-client` parser plus `config-decoder` | 3.1 | The official parser reads all 3.x fields from nested `last_config`. The envelope is one unpadded Base64URL Qt `qCompress` payload—not `vpn://free/<outer>/<inner>`—and must be decoder-shaped tested. Wiresock contains no link generator. |

Sources: [SBE 2.7.0 release](https://github.com/shtorm-7/sing-box-extended/releases/tag/v1.14.0-extended-2.7.0), [SBE 2.7.0 options](https://raw.githubusercontent.com/shtorm-7/sing-box-extended/v1.14.0-extended-2.7.0/option/wireguard.go), [Throne 1.3.0-beta.3 editor](https://raw.githubusercontent.com/throneproj/Throne/1.3.0-beta.3/src/ui/profile/edit_wireguard_amnezia.cpp), [official client AWG parser](https://raw.githubusercontent.com/amnezia-vpn/amnezia-client/dev/client/core/models/protocols/awgProtocolConfig.cpp).

### Decision D4 — per-target mode declarations, not a global 3.x switch

The capability matrix is a pure renderer policy keyed by target and AWG mode.
It returns `ready` only when the target’s pinned version can receive the full
validated directive set; otherwise it returns a stable remediation string.
This preserves the current native `.conf` fallback and prevents a client’s
presence from accidentally enabling all renderers.

```text
validated AwgInterfaceDirectives
        ├─ native .conf: 2.0 / 3.0 / 3.1
        ├─ SBE HydraBox: 2.0 / 3.0 (exact probe)
        ├─ Throne 1.3.0-beta.3 wg://: 2.0 / 3.0 / 3.1 (import regression)
        └─ Amnezia vpn://: 2.0 / 3.0 / 3.1 (parser-shaped decode regression)
```

### Components, data and error policy

1. A pure `AwgExportCapability` declares target, supported modes and reason.
2. The SBE serializer maps only source-proven 3.0 directives into the existing
   `amnezia` object and rejects any 3.1 directive rather than omitting it.
3. HydraBox preflight requires the exact SBE identity and renderer declaration;
   generic Sing-Box or another extended build does not qualify.
4. The Throne adapter extends the existing `wg://` query with source-proven 3.x
   fields under a pinned `1.3.0-beta.3` policy and requires an import regression.
   The official `vpn://` adapter adds the same source-proven fields to
   `last_config`, then serializes the outer container as Qt `qCompress` +
   unpadded Base64URL; no separate Wiresock format exists.

Capability declarations are code constants, not persisted user input. Status
returns only target, mode and reason; it never returns directive values or keys.
A mismatch of core identity, missing capability, unknown field, failed decode /
import, or failed handshake produces a fail-closed omitted artifact and preserves
the native configuration path.

### Test plan

- Decode the pinned SBE example and assert the exact supported 3.0 field map.
- Golden HydraBox subscription for AWG 3.0; negative golden tests for 3.1 and a
  mismatched core identity.
- Decode a locally generated single-payload `vpn://` with the exact Qt
  `qCompress` shape; assert outer container and parser-shaped `last_config`.
- Keep a Throne source-grammar golden; executable import and handshake remain
  separate disposable-client evidence.
- Run the disposable Linux native handshake matrix separately; it remains the
  final interoperability proof.
