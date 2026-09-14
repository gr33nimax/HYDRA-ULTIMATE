# Requirements: complete AmneziaWG 2.x / 3.x module update

## Intent

HYDRA currently installs `wiresock/amneziawg-install`, manages two AWG server interfaces, generates native configs/links/subscriptions, and offers legacy obfuscation presets. Every current renderer knows only legacy `Jc…H4` and `I1` directives. AWG 3.0/3.1 fields are currently absent everywhere, so a server-only migration would break client delivery.

HYDRA must update the whole plugin as one coherent feature: runtime mode, server config, existing obfuscation presets, client exports, subscriptions, status, UI/CLI, migration and rollback.

## User story

As a HYDRA administrator, I want to select AWG `2.0`, `3.0`, or `3.1`, inspect compatible obfuscation settings, and receive only client artifacts that can represent the active generation, so that a server migration neither silently loses directives nor leaves clients with invalid profiles.

## Requirements

### R1 — Canonical mode and directive model

- HYDRA SHALL persist the desired protocol mode as exactly one of `2.0`, `3.0`, `3.1`; absent legacy value means `2.0`.
- HYDRA SHALL use one typed, generation-aware interface-directive model as the source for server reconciliation and every client serializer.
- The model SHALL distinguish legacy transport obfuscation (`Jc`, `Jmin`, `Jmax`, `S1`–`S4`, `H1`–`H4`, `I1`) from AWG 3.x protocol directives: `HeaderProtectionKey`, `ContentPaddingAddition`, `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `RandomTrailers`, `DisableCookies`.
- HYDRA SHALL preserve unknown upstream directives during a read/reconcile/write cycle instead of deleting them.
- HYDRA SHALL never log, display in normal status, or persist a duplicate plaintext copy of private keys or `HeaderProtectionKey` outside its managed AWG files.

### R2 — Mode semantics and validation

- `2.0` SHALL emit no AWG 3.x directives.
- `3.0` SHALL require and consistently emit the upstream-generated AWG 3.0 directive set, including `HeaderProtectionKey`.
- `3.1` SHALL require the AWG 3.0 directive set plus `RandomTrailers`; the value SHALL match in server and every emitted compatible client profile.
- `DisableCookies` SHALL remain disabled by default. HYDRA SHALL not expose it as a casual preset toggle because it disables Cookie Reply anti-DoS protection; an explicit future advanced-security setting requires separate requirements.
- HYDRA SHALL reject malformed, duplicate, generation-incompatible, or incomplete required directives before it applies a configuration.

### R3 — Preserve and expose existing obfuscation choices

- HYDRA SHALL retain the current `wired`, `mobile`, `stealth`, `low_latency`, and carrier variants for legacy transport obfuscation.
- Changing a legacy preset or rotating obfuscation SHALL not erase or alter AWG 3.x protocol directives.
- The AWG management UI and headless command result SHALL show the active generation, selected legacy strategy, and a redacted capability summary; secrets and raw keys remain hidden.
- HYDRA SHALL document which choices are profile-local legacy transport settings and which are generation-wide protocol settings.

### R4 — Complete server and client projection

- WHEN a supported AWG mode is active THEN HYDRA SHALL render the same validated generation-relevant directive set in each server interface and in each compatible client profile.
- HYDRA SHALL update native `.conf`, `wg://`, official `vpn://`, NekoBox `sn://awg`, Sing-box/HydraBox exports, subscription generation, and user-link views only where their actual format/runtime supports the selected directive set.
- Each renderer SHALL declare its supported modes. It SHALL either produce a complete validated profile or omit that artifact with a specific compatibility reason; it SHALL never silently drop required AWG 3.x fields.
- Existing AWG 2.0 client profiles and links SHALL remain byte-compatible unless an administrator explicitly changes mode or legacy obfuscation strategy.
- A mode transition SHALL preserve user identities, peers, addresses, ports, standard WireGuard keys, mappings, and enabled profiles.

### R5 — Administrator control and status

- UI and CLI SHALL delegate mode requests only through the canonical plugin command/application service; UI shall not execute host commands.
- Selecting the already observed desired mode SHALL be a successful no-op without restarting an interface.
- Plugin status SHALL show desired mode, observed upstream mode, directive/export compatibility state, and a clear remediation message for unsupported client formats, without secrets.
- The command SHALL reject invalid modes, uninstalled runtime, unmanaged installer checkout, or unsupported upstream migration interface before host mutation.

### R6 — Transactional migration and recovery

- A mode change SHALL use the upstream non-interactive migration mechanism, not hand-authored AWG 3.x directives.
- Before mutation HYDRA SHALL snapshot both managed interface files, upstream `params`, installer identity/version, and systemd enabled/active state.
- HYDRA SHALL check upstream mode before and after migration, validate every server directive set, apply both interfaces, and verify required runtime health before committing desired state.
- IF capability probing, upstream migration, directive validation, client projection preflight, configuration apply, or runtime health verification fails THEN HYDRA SHALL restore the snapshot and previous desired state, reapply the former working configuration, and retain the original error as the primary failure.
- HYDRA SHALL never claim success unless the requested mode is observed active and all enabled export targets have completed their declared compatibility policy.

### R7 — Compatibility and documentation

- HYDRA SHALL state that AWG 3.x requires compatible clients and that `3.1` requires matching `RandomTrailers` values.
- HYDRA SHALL correct existing documentation that claims unsupported `I1`–`I5`, `J1`–`J3`, or `Itime` support.
- HYDRA SHALL not label generic Sing-box output, NekoBox binary output, or any external URI as AWG 3.x-capable without a versioned, executable compatibility test.

## Out of scope

- `amneziawg-proxy` and its traffic imitation modes.
- Automatic client capability discovery or automatic mode selection.
- A generic raw-directive editor.
- Enabling `DisableCookies` through the normal UI.
- Linux integration execution on a production VPS.

## Acceptance evidence

- Unit tests: mode/directive parsing, default compatibility, strict validation, legacy preset preservation, command selection, no-op behavior, and each rollback point.
- Golden output tests: `.conf`, URI, subscription and Sing-box/HydraBox artifact for each renderer/mode it claims to support; unsupported output has an explicit reason and no malformed link.
- Regression test: legacy AWG 2.0 output remains byte-compatible.
- Linux disposable-host smoke: `2.0 → 3.0 → 3.1 → 2.0`, a matching client handshake per supported export type, and rollback after injected migration/apply failure.

## Extension (requirements, 2026-09-08)

### Intent

Enable AWG 3.x client delivery only for formats proven by source-level grammar,
version-pinned runtime capability, and executable import/handshake evidence:
Throne, HydraBox through Sing-Box Extended `v1.14.0-extended-2.7.1`, and the
official Amnezia `vpn://` link.

### R8 — Evidence-gated external renderers

- WHEN evaluating a renderer THEN HYDRA SHALL identify the exact client/core
  version, source parser and full directive mapping before enabling AWG 3.x.
- IF a format cannot carry every mandatory AWG 3.0/3.1 directive THEN HYDRA
  SHALL retain the native `.conf` fallback and an explicit incompatibility
  reason; it SHALL not publish a partial artifact.
- WHEN evidence confirms an adapter THEN HYDRA SHALL pin its compatible version
  range, serialize the complete generation-specific payload, and add a golden
  payload plus executable import/handshake regression.

### R9 — Throne delivery

- WHEN Throne `1.3.0-beta.3` imports an AWG 3.1 `wg://` link THEN HYDRA
  SHALL emit its source-proven query fields, including `random_trailers` and
  `disable_cookies`; HYDRA SHALL keep the latter false by default.
- IF a later Throne build changes the parser/runtime contract THEN HYDRA SHALL
  fail closed until its versioned source and import regression are updated.

### R10 — HydraBox and Sing-Box Extended

- WHEN HydraBox reports the pinned Sing-Box Extended capability contract THEN
  HYDRA SHALL include a complete AWG 3.x endpoint in its encrypted subscription.
- IF the reported core identity/version/capability differs from the pinned
  contract THEN HYDRA SHALL omit the AWG 3.x endpoint with a stable reason.

### R11 — Official Amnezia link

- WHEN HYDRA emits the official `vpn://` AWG 3.x container THEN it SHALL put
  every generation directive in the nested `last_config` JSON fields consumed by
  `AwgClientConfig::fromJson`, in addition to the native config text.
- HYDRA SHALL encode the complete outer container with the official Qt
  `qCompress` wire shape (big-endian uncompressed size + zlib, Base64URL without
  padding), then cover its decode and parser-shaped nested `last_config` golden
  payload for 2.0, 3.0 and 3.1.

### Constraints and open evidence gaps

- Throne `1.3.0-beta.3` source proves its AWG editor maps the 3.1 boolean fields;
  subscription import still requires an executable regression
  (<https://raw.githubusercontent.com/throneproj/Throne/1.3.0-beta.3/src/ui/profile/edit_wireguard_amnezia.cpp>).
- Sing-Box Extended `2.7.0` release notes claim Amnezia 3.1 integration, but the
  exact `2.7.0`/`2.7.1` `option/wireguard.go` accepts no `random_trailers` or
  `disable_cookies`. HydraBox therefore remains 3.0-only until source and binary
  contracts reconcile
  (<https://github.com/shtorm-7/sing-box-extended/releases/tag/v1.14.0-extended-2.7.0>).
- The official client source serializes and deserializes AWG 3.x fields in the
  nested `last_config` JSON. Its `config-decoder` confirms the exact envelope as
  Qt `qCompress` plus unpadded Base64URL; a user-provided real exported link has
  the same single-payload form (the secret link itself is not retained).
  (<https://raw.githubusercontent.com/amnezia-vpn/config-decoder/master/mainwindow.cpp>).
- `DisableCookies` remains out of scope and disabled.

## Evidence

- Accepted architecture decision: `.kiro/decisions/0002-awg-generation-upstream-ownership.md`
- Upstream migration commands and capability flow: <https://github.com/wiresock/amneziawg-install/blob/main/amneziawg-install.sh>
- AWG generation and client compatibility: <https://docs.amnezia.org/documentation/amnezia-wg/>
- `RandomTrailers` / `DisableCookies` implementation: <https://github.com/amnezia-vpn/amneziawg-go>
- Sing-box support must be treated as unproven until versioned tests pass: <https://github.com/SagerNet/sing-box/issues/4045>
