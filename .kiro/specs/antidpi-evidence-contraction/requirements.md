# Requirements: AntiDPI evidence contraction into AntiScan

**Spec Type:** Feature Spec  
**Created:** 2026-09-16  
**Status:** Requirements approved 2026-09-16  
**Target branch:** `debug`

## Intent

Сузить AntiDPI из универсального наблюдателя сетевых аномалий до доказательного защитного контура AntiScan. Модуль должен создавать событие и применять автоматический бан только в двух случаях:

1. конкретный протокол подтвердил, что внешний клиент дошёл до его authentication/handshake gate с неправильными protocol-owned данными;
2. внешний клиент запросил на сайте-заглушке путь, однозначно характерный для автоматического сканера.

Слабая телеметрия, общие TLS-ошибки, сетевые эвристики и неподтверждённая атрибуция должны исчезнуть из потока наблюдений, state, score и Telegram, а не переводиться в `alert-only`.

## User story

Как владелец HYDRA/VPS, я хочу, чтобы AntiScan банил только доказанные обращения с неправильными данными к закрытым протоколам и доказанные сканы сайтов-заглушек, чтобы Telegram показывал реальные защитные действия, а не поток необязательных наблюдений.

## Terminology

- **Protocol reject** — отказ, произведённый конкретным protocol-owned authentication/handshake parser после получения неправильного UUID, password, token, user key или формата protocol frame.
- **Exact attribution** — внешний публичный IP получен непосредственно из protocol-owned TCP/HTTP peer либо восстановлен через точное соответствие `protocol + relay source port`; временная или эвристическая корреляция не считается точной.
- **Decoy scan** — запрос к включённому сайту-заглушке по allowlist пути, характерного для автоматического поиска уязвимостей или секретов.
- **Discarded input** — входная запись, не прошедшая доказательный контракт; она не становится событием AntiScan.

## Requirements

### R1 — Closed evidence allowlist

AntiScan SHALL принимать только protocol reject и decoy scan, определённые этой спекой.

1. WHEN входная запись не принадлежит разрешённому evidence type THEN AntiScan SHALL отбросить её до scoring, correlation, persistence и notification.
2. WHEN evidence type отсутствует в явном allowlist THEN AntiScan SHALL считать его запрещённым по умолчанию.
3. WHEN новый протокол добавляется в allowlist THEN изменение SHALL включать реальный production fixture, parser test и доказательство атрибуции внешнего IP.
4. AntiScan SHALL NOT создавать общий fallback matcher для неизвестных protocol errors.

### R2 — Proven protocol reject

Protocol reject SHALL считаться доказанным только при одновременном выполнении всех условий:

1. запись привязана к точному service/inbound tag конкретного протокола;
2. parser распознаёт точную protocol-owned ошибку, а не общие слова `invalid`, `EOF`, `handshake failed`, `unauthorized` или HTTP status без контекста;
3. внешний IP доказан exact attribution;
4. IP является публичным, не loopback и не входит в trusted/host whitelist;
5. ошибка означает неправильные данные клиента на protocol authentication/handshake gate.

WHEN все условия выполнены THEN AntiScan SHALL немедленно применить автоматический бан без накопления score и без требования второй evidence family.

WHEN хотя бы одно условие не выполнено THEN AntiScan SHALL полностью отбросить запись без ALERT.

### R3 — Initial protocol evidence matrix

Начальная реализация SHALL поддерживать только подтверждённые адаптеры из следующей матрицы:

| Protocol | Allowed evidence | Attribution requirement | Initial state |
| --- | --- | --- | --- |
| AnyTLS | exact `anytls: authentication failed` / fallback-disabled error chain | direct external peer or exact relay mapping | eligible after fixture locks exact production line |
| VLESS | native `unknown UUID` or exact native authentication reject | direct external peer or exact relay mapping | eligible |
| Naive | exact server-generated invalid-user / `authorization failed` marker on protocol CONNECT auth gate | Caddy/Naive external peer or exact relay mapping | eligible after fixture locks deployed implementation |
| Snell | exact `snell: bad user key` or equivalent typed upstream error | direct external TCP peer | eligible after fixture locks deployed version |
| TrustTunnel | exact native invalid token/authentication reject | direct external peer or exact relay mapping | disabled until live production fixture proves format and attribution |

1. HTTP status alone, including `400`, `401`, `403`, `404`, `405`, `407`, `421` and `426`, SHALL NOT be sufficient evidence unless the adapter also proves the exact protocol auth gate and protocol-owned rejection marker.
2. VLESS SHALL NOT classify arbitrary status responses on an XHTTP path as authentication evidence.
3. Unsupported or unproven protocols SHALL remain absent from the event pipeline rather than emit alert-only observations.

### R4 — Explicitly unsupported observations

AntiScan SHALL stop observing and persisting all of the following:

- unknown SNI;
- generic TLS EOF, TLS alert and handshake failure;
- generic malformed TLS/ClientHello on shared TCP/443;
- connection burst and rate-only events;
- kernel `port_scan` / `port_sweep` telemetry;
- UDP probes and UDP rate telemetry;
- Mieru low-volume FIN/RST inference;
- subnet/distributed-scan correlation;
- time-correlated source attribution;
- generic Sing-Box errors;
- generic Telemt `invalid`/handshake text;
- AmneziaWG invalid MAC/unknown-peer telemetry;
- Hysteria2/qWDTT generic handshake or packet errors;
- protocol mismatch and other producer-less legacy signals.

WHEN such input is encountered THEN no score, signal, history entry, watchlist entry, Telegram message or automatic ban SHALL be produced.

### R5 — Unsupported protocol policy

The initial implementation SHALL NOT produce enforcement events for ShadowTLS, Hysteria2, Mieru, Telemt, AmneziaWG, qWDTT or Calls.

1. ShadowTLS SHALL remain unsupported while wrong credentials intentionally fall through and cannot be exactly attributed to an external peer.
2. UDP protocols SHALL remain unsupported while the observed source address can be spoofed or the reject occurs before return-routability/address validation is proven.
3. A future adapter MAY be enabled only through the R1 evidence gate; no heuristic substitute is permitted.

### R6 — Proven decoy scan

WHEN a request reaches an enabled decoy site with a public, non-whitelisted external IP AND the normalized request path matches the decoy scanner allowlist THEN AntiScan SHALL immediately apply an automatic ban.

The initial scanner-path allowlist SHALL cover existing explicit signatures for:

- `.env` and its backup/suffix variants;
- WordPress login/XML-RPC probes;
- CGI paths;
- actuator endpoints;
- server-status and equivalent existing high-confidence decoy paths.

The following SHALL NOT constitute decoy scan evidence by themselves:

- arbitrary `404` or unknown path;
- `favicon.ico`, `robots.txt` or normal browser assets;
- scanner-looking text found only in a query string;
- HTTP method alone, including `CONNECT`, `TRACE` or `TRACK`;
- a request on a real protocol endpoint rather than a configured decoy surface.

### R7 — Enforcement policy

1. WHEN proven evidence is accepted THEN AntiScan SHALL request the existing automatic IP ban path immediately.
2. The first offense SHALL use the existing first progressive ban duration; repeat offenses SHALL preserve the existing progressive duration policy.
3. WHEN firewall enforcement rejects or fails the ban THEN AntiScan SHALL preserve the failure reason and expose operational failure without claiming success.
4. Trusted networks, current host addresses and configured whitelist entries SHALL remain exempt.
5. Manual bans, active bans and ban expiry SHALL remain supported.
6. Existing transactional state write and firewall reconciliation guarantees SHALL remain unchanged.

### R8 — Telegram and operator output

1. WHEN a ban is successfully applied THEN AntiScan SHALL send one `BAN` notification containing IP, protocol or decoy source, exact evidence kind, ban duration and attribution source.
2. WHEN a ban cannot be applied THEN AntiScan SHALL send one bounded operational failure notification.
3. WHEN input is discarded or non-actionable THEN AntiScan SHALL NOT send an `ALERT` notification.
4. Operator status MAY expose aggregate discarded-input diagnostics only if they cannot trigger Telegram, score, watchlist or enforcement state.
5. Existing notifications such as `Verified score: 0.00` SHALL disappear because their source events no longer exist.

### R9 — State and compatibility

1. The public plugin key `antidpi`, service identity and compatibility imports SHALL remain stable.
2. Operator-facing copy MAY describe the narrowed role as `AntiScan`, but SHALL NOT require a state schema migration solely for renaming.
3. Existing state files containing legacy scores, signals or history SHALL remain readable.
4. Legacy weak evidence SHALL NOT be replayed, promoted or used to trigger new bans after upgrade.
5. Existing active/manual bans and offense history required by progressive durations SHALL remain valid.
6. Disabling or uninstalling the plugin SHALL continue to remove owned runtime rules and service artifacts according to current lifecycle contracts.

### R10 — Evidence fixtures and verification

1. Every enabled protocol adapter SHALL have a sanitized fixture captured from the deployed production implementation/version using deliberately incorrect client data.
2. Each fixture SHALL prove the exact reject string, protocol identity and external-IP attribution path.
3. Synthetic strings invented only for unit tests SHALL NOT be sufficient to enable an adapter.
4. Negative fixtures SHALL cover generic EOF, unknown SNI, HTTP status-only responses, unrelated service messages, loopback peers without exact mapping and spoofable UDP messages.
5. Tests SHALL prove that one accepted protocol reject or one accepted decoy scan reaches the ban path.
6. Tests SHALL prove that every removed observation class produces no event, no state mutation, no notification and no firewall call.

## Non-functional requirements

### NFR1 — Safety

The contraction SHALL reduce the set of ban-capable inputs; it SHALL NOT broaden parser matching or relax IP attribution.

### NFR2 — Determinism

For a fixed log fixture and state, classification SHALL be deterministic and SHALL NOT depend on timing proximity, ASN/Geo enrichment or correlation with unrelated events.

### NFR3 — Privacy

Notifications and persisted evidence SHALL NOT include credentials, UUIDs, tokens, passwords or raw authorization headers.

### NFR4 — Resource use

The implementation SHALL NOT add a process, journal stream, firewall telemetry chain or external dependency. Removed collectors/rules SHOULD reduce runtime work.

### NFR5 — Compatibility

Python 3.10–3.13 compatibility and existing plugin lifecycle/application boundaries SHALL remain intact.

## Out of scope

- Detecting generic Internet background noise on TCP/443.
- Detecting unknown SNI, obsolete TLS clients, latency probes or malformed generic TLS.
- Generic host port scanning, UDP scanning or distributed subnet scanning.
- DDoS detection or provider-edge protection.
- GeoIP/ASN-based verdicts.
- Automatic credential rotation or client remediation.
- Renaming the persisted plugin key, systemd unit or public compatibility modules.
- Adding support for protocols without production evidence fixtures.

## Acceptance evidence

The feature is acceptable when all of the following are demonstrated:

1. Replaying the five representative `unknown_sni` / generic TLS handshake examples produces zero AntiScan events and zero Telegram messages.
2. A proven VLESS wrong-UUID fixture with exact external attribution produces one automatic ban and one `BAN` notification.
3. Equivalent enabled fixtures for AnyTLS, Naive and Snell produce the same deterministic result.
4. One decoy request for `/.env` produces one automatic ban; a normal unknown path produces nothing.
5. Generic TLS, kernel scan, UDP, Mieru inference and unsupported-protocol fixtures produce no state mutation or firewall call.
6. Existing active/manual bans survive loading and reconciliation.
7. Focused AntiDPI tests, architecture guards and Ruff pass.
8. Linux integration limitations are stated explicitly if live firewall/systemd verification cannot be executed locally.

## Open evidence gates

These are implementation prerequisites, not permission to reintroduce heuristics:

- capture and sanitize real deployed log lines for AnyTLS, VLESS, Naive and Snell;
- verify exact source-relay attribution against those captures;
- keep TrustTunnel disabled unless its deployed implementation produces an exact native reject with attributable external IP.
