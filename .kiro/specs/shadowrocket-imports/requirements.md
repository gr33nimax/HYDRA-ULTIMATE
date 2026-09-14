# Micro Spec: Shadowrocket import formats

**Type:** Minor Fix
**Effort:** < 1 дня
**Date:** 2026-09-14

## Intent (What + Why)

**What:** Make the Shadowrocket subscription serialize native Snell v4 and AmneziaWG links in the URI forms exported by a working Shadowrocket client, instead of forwarding the generic HYDRA/Throne forms.

**Why:** A live client report proved that the current Snell link imports without its obfuscation and the current `wg://` link imports while losing AWG parameters. The target client expects a Snell `plugin` payload plus `udp`, and an AmneziaWG `obfs=amneziawg` payload whose parameters live in one JSON `obfsParam` value.

## Boundaries (Files + Out-of-scope)

**Files:**

- `hydra/services/subscriptions/shadowrocket.py` — add the target-only AWG mapper and render the verified Snell v4 forms.
- `hydra/services/subscriptions/links.py` — apply the mapper only to Shadowrocket subscriptions and suppress NekoBox/official-AWG alternatives there.
- `tests/test_shadowrocket_links.py` — golden URI grammar tests, including safe preservation of `+` in WireGuard keys.
- `tests/test_subscriptions.py` — integration test for the Shadowrocket subscription target.

**Out-of-scope:**

- qWDTT, HydraCore, server-side AWG configuration, the generic/Throne `wg://` URI, the official `vpn://` URI, and NekoBox `sn://awg` serialization.
- Snell generation 6: it remains unconverted because Shadowrocket does not import that generation.
- Claiming an AWG 3.x handshake: the mapper carries all available generation fields, but the only supplied live connection proof is AWG 2.0.

## How

1. For Snell client version 4, emit `udp=0|1`; emit the un-obfuscated form with the existing full credential payload; for `http`/`tls`, emit a credential-only base64 user part followed by literal `@host:port` and a `plugin=obfs-local;...` payload. TLS uses the client-exported `{"Host":"<host>"}` inner value.
2. For a generic AWG `wg://`, preserve raw query `+` characters while parsing, map standard keys to Shadowrocket camelCase names, set `obfs=amneziawg`, and place every legacy and present generation field into compact string-valued `obfsParam` JSON. Add safe `"false"` defaults for the two boolean schema fields when absent.
3. Shadowrocket receives only that mapped AWG link; skip the target-incompatible `vpn://` and `sn://awg` alternatives.

## Acceptance

- A v4 Snell `none` link has `version=4&udp=1`; `http` and `tls` carry the expected `plugin` form, with TLS preserving the JSON Host object; v6 is unchanged.
- A mapped AWG link has `publicKey`, `privateKey`, `presharedKey`, `ip`, `keepalive`, `udp=1`, `obfs=amneziawg`, and one decodable `obfsParam` JSON object containing every supplied AWG field as a string.
- Base64 WireGuard keys containing `+` survive conversion and are percent-encoded in the target URI rather than becoming spaces.
- The Shadowrocket subscription contains no `vpn://` or `sn://awg` AWG duplicate.
- Focused tests and `verify.py` pass. The code does not expose real credentials in logs, test fixtures, or documentation.

## Upgrade-гейт

If a Shadowrocket version-specific AWG 3.x import/handshake proves that this one JSON grammar cannot carry a required directive, promote the work to a Quick Spec and add a versioned capability policy rather than silently dropping it.
