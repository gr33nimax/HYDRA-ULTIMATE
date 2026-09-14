# Design: Native Snell generations in Hydra Ultimate

## Decisions

- **D1 — A generation is a pair.** `5` = server `version: 5` + client `version: 4`;
  `6` = server `version: 6` + client `version: 6`. The core's own library has no client half
  for v5 (`sing-snell/snellv5` ships `server.go` only; `snellv4/client.go` is that client), so
  “client 5” is not a choice we can offer.
- **D2 — Flat fields.** `obfs_mode`, `obfs_host` and `mode` are written flat. The nested
  `obfs` object disappears from every renderer; the core answers `unknown field "obfs"` for it.
- **D3 — Migration reads `4` as `5`.** A stored `4` (or an absent value) means the classic
  generation. Server-side `4` no longer exists, and the `5` server accepts the classic request,
  so already issued links keep working after the upgrade.
- **D4 — Gate on the core version.** Both generations require a HydraCore carrying the upstream
  Snell implementation: `MIN_SNELL_CORE = v1.14.0-extended-2.7.1-hydracore.12`. Older cores get
  a refusal naming the release, using the same helper shape as
  `hydra/plugins/amneziawg/client_links.py::kernel_supports_awg31`.
- **D5 — Generation `6` is exclusive.** It serves v6 clients only. The plugin says so in
  `status()` and in the docs instead of silently breaking v4 clients.
- **D6 — Shadowrocket form only for the `5` pair.** The converter keeps the real client
  version (`4`) and emits Shadowrocket's own grammar: `udp=0|1`; no-obfuscation uses the full
  base64 credential payload, while `http`/`tls` use a credential-only base64 user part followed
  by literal `@host:port` and `plugin=obfs-local;...`. TLS places the host in the client-exported
  `{"Host":"<host>"}` inner object. For generation `6` it returns the link unchanged rather
  than inventing a form the client cannot import.

## State

`PluginState.config` for the `snell` plugin:

| Key | Values | Default | Applies to |
| --- | --- | --- | --- |
| `version` | `5`, `6` | `5` | both |
| `obfs_mode` | `none`, `http`, `tls` | `none` | generation `5` only |
| `obfs_host` | hostname | `www.bing.com` | generation `5` with `http`/`tls` |
| `mode` | `default`, `unshaped`, `unsafe-raw` | `default` | generation `6` only |

A stored `version: 4` is read as `5`; any other value is refused.

## Rendering

| Generation / obfs | server `inbound` | client `outbound` | `snell://` |
| --- | --- | --- | --- |
| `5`, `none` | `version: 5` | `version: 4` | full credential base64, `version=4`, `udp=1` |
| `5`, `http` | `version: 5`, `obfs_mode: http` | `version: 4`, `obfs_mode: http`, `obfs_host: <host>` | credential-only base64 + `@host:port`, `plugin=obfs-local;obfs=http;obfs-host=<host>;obfs-uri=/`, `version=4`, `udp=1` |
| `5`, `tls` | `version: 5`, `obfs_mode: tls` | `version: 4`, `obfs_mode: tls`, `obfs_host: <host>` | credential-only base64 + `@host:port`, TLS `plugin` host `{"Host":"<host>"}`, `version=4`, `udp=1` |
| `6`, any | `version: 6`, `mode: <mode>` | `version: 6`, `mode: <mode>` | `version=6`, `mode=<mode>` |

Everything else in the fragment (tags, ports, `network: [tcp, udp]`, `psk`, `listen`) stays as
it is today.

## Validation

`set_settings(state, version, obfs_mode, obfs_host, mode)`:

- `version`: `4` is normalized to `5`; only `5` and `6` are accepted.
- `obfs_mode`: one of `none`, `http`, `tls`; with generation `6` only `none` is accepted
  (obfuscation belongs to the classic protocol, `mode` replaces it).
- `obfs_host`: non-empty, no scheme, no whitespace; required for `http`/`tls`.
- `mode`: one of `default`, `unshaped`, `unsafe-raw`; with generation `5` only `default` is
  accepted.

`on_enable()` re-validates the stored state, checks the core gate and only then opens the port
range. `configure()`, `generate_client_config()` and `client_link()` assert the gate as well, so
a renderer can never emit a profile the installed core would refuse.

## Tests

- `tests/test_snell_modes.py` (HYDRA): golden fragments for all four combinations, the share
  link and the Shadowrocket form; `set_settings` validation matrix; `4 → 5` migration; the gate
  answering “old core” with a reason and “new core” with success.
- `option/snell_test.go` (HydraCore): the parser accepts the emitted server shapes
  (`version: 5` with each `obfs_mode`, `version: 6` with each `mode`) and the client shapes
  (`version: 4` with `obfs_mode`/`obfs_host`, `version: 6` with `mode`), and refuses
  `version: 4` on the server plus the nested `obfs` object. This is the regression fence for the
  failure that started this work.

## Risks

- Moving the server to generation `5` is compatible with issued v4 links; moving to `6` is not,
  and the status must say so before the operator applies it.
- Third-party clients (Shadowrocket, Surge) implement the `5` pair only, so `6` is a sing-box
  generation.
