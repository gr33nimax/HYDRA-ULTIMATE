# Requirements: Native Snell generations in Hydra Ultimate

## Overview

Hydra Ultimate has rendered Snell for a core whose Snell implementation it owned itself: a
per-user `inbound` with `version: 4` and an obfuscation block shaped `obfs: {mode}`. The
migrated HydraCore (`v1.14.0-extended-2.7.1`) carries the upstream Snell implementation
instead, and that core accepts a different contract:

| Side | Accepted by the core | Evidence |
| --- | --- | --- |
| server (`inbound`) | `version` 5 (`obfs_mode: none,http,tls`) or 6 (`mode: default,unshaped,unsafe-raw`); 4 is refused | `snell: unsupported version: 4` |
| client (`outbound`) | `version` 4 (`obfs_mode` + `obfs_host`) or 6 (`mode`); 5 is refused | `snell: unsupported version: 5` |
| obfuscation shape | flat `obfs_mode` / `obfs_host`; a nested `obfs` object is refused | `unknown field "obfs"` |

`github.com/sagernet/sing-snell` implements Snell in pairs: `snellv5` ships a server only,
`snellv4` ships the client for the same protocol, and `snellv6` ships both. There is no
client-side “version 5” to select — a 5-mode pair is written as server `5` + client `4`.

Today the plugin therefore cannot enable Snell at all on the migrated core: it emits a
server `version: 4` and a nested `obfs` block, both of which the core rejects. Selecting
`tls` and selecting a generation are also impossible by construction.

## User Roles

- **Operator (admin):** chooses the Snell generation and obfuscation once for the whole server.
- **User:** receives a working profile/link for the chosen generation.

## Requirements

### R1: One Snell generation, selected by the operator

**User Story:** As an operator, I want to choose the Snell generation once, so that every
user is served by a matching server and client.

**Acceptance Criteria:**

1. WHEN the operator selects a generation THEN HYDRA SHALL persist exactly one of `5` or `6`
   in the plugin configuration.
2. WHEN the persisted value is `4` or absent THEN HYDRA SHALL read it as `5`, because a
   server-side `4` no longer exists in the core.
3. IF a generation outside `5` and `6` is requested THEN HYDRA SHALL refuse it with a
   message naming the two supported generations.
4. WHEN the generation is `5` THEN the operator SHALL be able to choose an obfuscation mode
   `none`, `http` or `tls` and an obfuscation host used by `http` and `tls`.
5. WHEN the generation is `6` THEN the operator SHALL be able to choose a mode `default`,
   `unshaped` or `unsafe-raw`, and obfuscation settings SHALL NOT apply.

### R2: The server profile is valid for the migrated core

**User Story:** As an operator, I want the generated server configuration to be accepted, so
that enabling Snell does not take the core down.

**Acceptance Criteria:**

1. WHEN the generation is `5` THEN each user inbound SHALL carry `version: 5` and, when the
   obfuscation mode is not `none`, a flat `obfs_mode`.
2. WHEN the generation is `6` THEN each user inbound SHALL carry `version: 6` and a flat
   `mode`.
3. HYDRA SHALL NOT emit the nested `obfs` object, at any generation.
4. WHEN the generated fragment is parsed by the migrated core's own option parser THEN it
   SHALL be accepted (proven by a core-level test, not only by a golden file).

### R3: Client artifacts match the selected generation

**User Story:** As a user, I want a client profile that matches the server, so that the
tunnel connects on the first attempt.

**Acceptance Criteria:**

1. WHEN the generation is `5` THEN the emitted sing-box outbound SHALL carry `version: 4`
   with flat `obfs_mode` / `obfs_host` — the client half of the 5-mode pair.
2. WHEN the generation is `6` THEN the emitted outbound SHALL carry `version: 6` with flat
   `mode`.
3. WHEN a share link is produced THEN it SHALL carry the client-side version the generation
   requires (server `5` → client `4`, generation `6` → `6`) together with the obfuscation
   parameters the pair needs, and the operator-visible generation SHALL stay truthful in
   status and documentation.
4. WHEN the Shadowrocket form of a classic Snell link is produced THEN it SHALL use `version=4`
   plus `udp=0|1`; an un-obfuscated profile SHALL retain the full credential payload, while
   `http`/`tls` SHALL use Shadowrocket's `plugin=obfs-local;...` form with a credential-only
   payload followed by literal `@host:port`. The TLS plugin host SHALL be the client-exported
   `{"Host":"<host>"}` object. HYDRA SHALL derive that form from the active generation and
   SHALL leave a generation 6 link untouched rather than fabricating an unsupported profile.
5. WHEN credentials are regenerated after a generation change THEN PSK, port and tag SHALL be
   identical to the pre-change values.

### R4: Refusal instead of a broken profile

**User Story:** As an operator, I want a clear refusal when the installed core cannot serve
the selected generation.

**Acceptance Criteria:**

1. WHEN the generation is `5` or `6` and the installed HydraCore is older than the first
   release with the upstream Snell implementation THEN HYDRA SHALL refuse to enable the
   plugin and SHALL name the required release.
2. WHEN the installed core satisfies the gate THEN enabling SHALL proceed.
3. The refusal SHALL be stable and testable (a named reason, not a silent skip).

### R5: No regression for issued credentials and working links

**Acceptance Criteria:**

1. Per-user PSKs and ports SHALL NOT change when the generation changes; the derivation
   label (`snell-v5-psk`) stays.
2. WHEN the server moves to generation `5` THEN existing v4-shaped client links SHALL keep
   working (the 5-mode server accepts the classic request).
3. WHEN the server moves to generation `6` THEN the status SHALL state that only v6 clients
   are served, because a v4 client cannot talk to a v6 server.

## Non-Functional Requirements

- **Verification:** golden tests per generation and obfuscation mode in HYDRA plus a
  core-level parser test in HydraCore; `verify.py` stays green.
- **Compatibility:** no change to ports, PSK derivation, tags or subscription shape beyond
  the fields above.
- **Docs:** `docs/REFERENCE.md`, `docs/CLI.md`, `README.md` and `CHANGELOG.md` describe the
  selectable generations, the 5↔4 pairing and the gate.

## Out of Scope

- Multi-user `users[]` inbounds (HYDRA keeps one inbound and one PSK per user).
- HydraBox-side Snell links (`snell://` parsing/UI in the client app). HydraBox already
  tunnels Snell through the core; only the Kotlin link parser does not know the scheme.
- Any change to the client ABI or to the HydraCore Snell implementation itself.

## Open Questions

1. Should a generation change be applied by the ordinary plugin apply (core reload), or does
   it need an explicit warning step because v4 clients stop working on `6`?
2. Is a Shadowrocket-compatible form of `obfs=tls` needed, or do we only forward the values
   and let the client decide?

## Evidence

- Core option surface: `HydraCore/option/snell.go` (`version` enums, `obfs_mode`, `mode`).
- Core implementation: `HydraCore/protocol/snell/{inbound,outbound}.go`.
- Pairing: `github.com/sagernet/sing-snell@v0.0.0-20260829071736-20f2eaec77c3` — `snellv5/`
  has `server.go` only, `snellv4/client.go` is the 5-mode client, `snellv6` ships both.
- Current plugin: `hydra/plugins/snell/plugin.py` (`SNELL_VERSION = 4`, nested `obfs`).
- Shadowrocket link form: `hydra/services/subscriptions/shadowrocket.py`
  (`version = "4"` hardcoded).
- Same gate pattern as AWG 3.1: `hydra/plugins/amneziawg/client_links.py::kernel_supports_awg31`.
