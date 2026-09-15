# Design: opt-out for Naive UoT (UDP over TCP)

Approach chosen by the owner: **A** (one setting; HYDRA picks the build itself). Micro/Quick spec,
2026-09-15.

## D1 — Setting and owner

| Concern | Owner |
| --- | --- |
| Desired UoT state (`state.protocols["naive"].config["uot"]`, default `True`) | naive plugin (`set_uot` command, validation) |
| Caddyfile rendering (`passthrough_uot` present only when on) | `naive/configuration.py::render_caddyfile` |
| Which module the binary is built from | `naive/installation.py` + `core/sni_router_install.py` |
| Rebuild decision and transaction | existing `naive/runtime.py::apply` + `PluginCommandService` snapshot/rollback |
| Client artifacts (Shadowrocket `uot`) | `services/subscriptions/shadowrocket.py` + `links.py` |

Default `True` keeps today's behaviour for existing installs: an absent key means «как раньше»,
and nothing rebuilds.

## D2 — Build selection (two pinned module strings, one build at a time)

```text
on  → github.com/caddyserver/forwardproxy@caddy2=github.com/aUsernameWoW/forwardproxy@c55724423ecd39402624538071f198036be79c25
off → github.com/caddyserver/forwardproxy@0aab84dad4fc2830789f34e27b4d7bc22a40889e
```

- Fork pin — current `NAIVE_FORWARD_PROXY_MODULE`, unchanged.
- Stock pin — upstream `caddyserver/forwardproxy` master at `0aab84da…`
  («Add :443 to the quickstart», 2026-03-21). Verified upstream `go.mod` requires
  `caddyserver/caddy/v2 v2.8.4`, i.e. compatible with the `v2.10.2` build HYDRA already uses.
- Upstream carries the plain `forward_proxy` handler with `basic_auth`, `hide_ip`, `hide_via`,
  `probe_resistance`, `upstream socks5://…` — the whole Caddyfile HYDRA renders without UoT.
- `sni_router_install.install()` gains `forward_proxy_module: str = NAIVE_FORWARD_PROXY_MODULE`,
  so the L4 path stays untouched.

## D3 — Detection is a probe, not a stored assumption

The installed binary is classified by validating a probe Caddyfile **with** `passthrough_uot`:

- validates → fork is installed (UoT-capable);
- fails → stock.

This is the same evidence the current installer already uses in reverse, needs no marker file,
and cannot silently drift from reality.

`apply()` then becomes:

```text
desired = config["uot"] (default True)
if desired != built_for_uot():
    rebuild the binary with the module for `desired`   # _download_binary()
render Caddyfile for `desired`
validate → enable → reload-or-restart (existing path)
```

The existing fallback (`if error and self._download_binary(...)`) stays as the second line of
defence for a binary that lacks the handler entirely.

## D4 — Why the stock build is required for «off» (and nothing weaker works)

- The fork has no «disable UoT» option; the UoT branch fires on the magic address unconditionally.
- With `upstream socks5://…` configured, the fork never consults ACL/`ports` (the ACL walk only
  runs when `upstream` is unset), and its README states the incompatibility — so the magic host
  cannot be blocked by config.
- Therefore the only configuration-independent way to stop serving UoT is to not have the fork
  code. With `desired != built_for_uot()` above, the operator still only flips one setting.

## D5 — Client artifacts

- `build_shadowrocket_naive_links(link, *, uot: bool = True)`: TCP/HTTP2 variants add
  `uot=2` only when `uot`; `tfo=1` and `padding=1` stay (they are not UoT). HTTP/3 variant is
  untouched.
- `links.py` passes `uot` read from `state.protocols["naive"].config` (single boolean read; the
  plugin keeps ownership of validation). Unknown/absent → `True`.
- HYDRA's own sing-box naive profile needs no change: sing-box sets `UoT` only when
  `udp_over_tcp.enabled` is explicit (`UDPOverTCP *UDPOverTCPOptions`, `omitempty`), and its
  outbound advertises TCP-only otherwise. Documented as an open item for third-party clients.
- Docs: `docs/REFERENCE.md` (naive row + the `uot=2` sentence), `README.md` (transport row),
  `CHANGELOG.md`.

## D6 — UI

`_menu_naive` gains «UDP через TCP (UoT)» with the observed state and a short warning:
выключение пересобирает Caddy без UoT, и UDP по TCP-профилю перестанет ходить (QUIC остаётся).
Command goes through `app.plugin_command(state, "naive", "set_uot", uot=<bool>)`.

## D7 — Error policy

| Failure | Result |
| --- | --- |
| invalid setting value | reject in `set_uot` before any host mutation |
| rebuild failed / module missing / probe rejected | keep the previous binary (`.previous`), rollback config + service, keep the previous setting |
| rendered Caddyfile invalid for the new binary | `apply` returns False; `PluginCommandService` rolls back |
| setting flipped but binary is already correct | no rebuild, ordinary reload |

## D8 — Tests

1. `render_caddyfile`: `passthrough_uot` present only for `uot=True`; upstream line unchanged.
2. `set_uot`: validation, persistence, no-op when unchanged.
3. `installation._download_binary`: fork module string and fork probe when on; stock module string
   and plain probe when off; probe rejection fails the build.
4. `runtime.apply`: rebuild triggered when `desired != built_for_uot()` in both directions;
   no rebuild when they agree.
5. Shadowrocket: `uot=2` present when on, absent when off, `tfo`/`padding` unchanged.
6. TUI: switching the setting dispatches `set_uot` through `plugin_command`.

## D9 — Limits and open items

- **Живая проверка обязательна.** Сборка Caddy и `caddy validate` не выполняются в Windows
  worktree: нужен Linux-хост (или расширение `naive-caddy` workflow на обе сборки).
- `uot=2` vs таблица совместимости Shadowrocket (UoT v1) — отдельный вопрос, не в этой спеке.
- Третьи клиенты с явным `udp_over_tcp` потеряют UDP при «off» — это ожидаемая цена, отражаем
  в документации, а не «тихо».
