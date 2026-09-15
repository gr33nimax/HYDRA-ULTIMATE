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

## Extension (requirements, 2026-09-15): quiet operator screen

### R12 — Hide passive export omissions in the AWG TUI

- WHEN the ordinary AmneziaWG status screen renders THEN it SHALL show the desired/observed generation and profiles, but SHALL NOT render a line naming export formats that are not issued.
- HYDRA SHALL keep capability evaluation and fail-closed artifact omission unchanged; it SHALL not fabricate a partial client artifact merely to make the screen look complete.
- Detailed incompatibility reasons remain available to internal status/CLI diagnostics and the code paths that explicitly request an artifact; they are not normal-dashboard copy.

**Acceptance evidence:** a menu regression test proves that an unavailable export is absent from the rendered AWG status panel while the mode and profile data remain visible; protocol capability tests keep their existing omission assertions.

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
- Sing-Box Extended `2.7.0` release notes claimed Amnezia 3.1 integration while
  its `option/wireguard.go` accepted neither `random_trailers` nor
  `disable_cookies`, so HydraBox stayed 3.0-only. **Каскад (2026-09-14,
  HydraCore 2.7.1):** HydraCore now carries the upstream `2.7.1` source merged
  into `debug` and adds both fields to `option.WireGuardAmnezia`
  (`transport/wireguard.AmneziaOptions`, proven by
  `option/wireguard_amnezia_test.go` and the AWG subscription test), so the gate
  is the installed core version — `v1.14.0-extended-2.7.1-hydracore.12` or newer
  opens 3.1, an older core keeps it fail-closed with a reason naming the
  release
  (<https://github.com/shtorm-7/sing-box-extended/releases/tag/v1.14.0-extended-2.7.1>).
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

## Extension (requirements, 2026-09-15): переключение режима там, где пиров создала HYDRA

### Intent

Живой сервер показал: переключить 3.x **невозможно**, если пользователей создаёт HYDRA.
Upstream-установщик перед сменой режима обязан переписать всех клиентов одной транзакцией (§6680
его скрипта), а для этого ему нужно (а) у каждого пира метка `### Client <имя>` и (б)
восстановимый клиентский конфиг `awg0-client-<имя>.conf` с тем же публичным ключом. HYDRA писала
`### <email>` и клиентских файлов не оставляла — поэтому отказ приходил на любом её сервере,
независимо от версий пакетов и ядерного модуля. Это предусловие чужого скрипта не проверяла ни
одна спека — тесты покрывали плагин, а не требования установщика.

### R13 — Пиры, созданные HYDRA, распознаются upstream-установщиком

- Метка пира — `### Client <имя>`, где имя стабильно, уникально и удовлетворяет
  `[A-Za-z0-9_-]{1,15}`: email не подходит ни по длине, ни по алфавиту.
- Email остаётся рядом отдельной строкой-комментарием для человека; строгий подсчёт меток
  upstream её не учитывает.
- Конфиги с прежней меткой (без префикса `Client`) продолжают читаться без миграции состояния.

### R14 — Клиентские конфигурации восстановимы на время миграции

- Перед миграцией HYDRA выкладывает клиентские конфиги в каталог, который ищет upstream (`/root`),
  с именем `awg0-client-<имя>.conf` и правами `0600`; источник правды остаётся в state.
- Чужие файлы не затираются: если файл уже есть и его ключ совпадает — используется он; если не
  совпадает — HYDRA сохраняет копию и возвращает её на место.
- После миграции файлы, созданные HYDRA, удаляются независимо от исхода: приватные ключи не
  остаются лежать в домашнем каталоге.

### Приёмка

1. На сервере, где пиров создала HYDRA, переключение 2.0 → 3.0 → 3.1 проходит и подтверждается
   статусом (desired == observed).
2. Метки соответствуют строгому выражению upstream, уникальны и не меняются между пересборками.
3. Клиентские конфиги существуют только на время миграции; после — удалены, чужие копии восстановлены.
4. Конфиг со старой меткой читается без миграции состояния.
5. Тесты: формат и стабильность метки; подготовка и уборка конфигов при успехе и при отказе;
   отказ upstream-скрипта сообщается причиной, а не молчанием.

## Extension (requirements, 2026-09-15, вторая): параметры 3.x и всегда включённые поля 3.1

### Intent

Миграция 3.1 на живом сервере применилась, но трафик ломался в деталях: Throne отвергал
cookie-пакеты («crypto padding is smaller than the header protection nonce»), а HB2 не проходило
рукопожатие вообще. Причина — наши же значения `S1–S4`: генератор обфускации подбирает их
независимо и допускает нули (S1=62, S2=86, S3=45, S4=21), а в 3.x паддинг каждого типа пакета
несёт материал для защиты заголовка. В рабочей конфигурации владельца Throne cookies выключены —
и это единственное, чего у приложения нет.

### R15 — Параметры 3.x пригодны для защиты заголовков

- Генератор обфускации в режиме 3.x выдаёт `S1–S4` одним значением в безопасном коридоре:
  не меньше нонса защиты заголовков и внутри границ, которые принимают клиенты (S3 ≤ 64, S4 ≤ 32).
- Валидатор отвергает набор, несовместимый с 3.x (разные или слишком маленькие S), с внятным текстом.
- Включение 3.x приводит текущие значения к безопасным **до** миграции: сервер и клиенты должны
  получить согласованный набор, а миграция и так требует перевыпуска профилей.

### R16 — Для 3.1 оба поля включены, во всех форматах

- Серверный конфиг на 3.1 несёт `RandomTrailers = true` и `DisableCookies = true`.
- Каждый клиентский формат (`native .conf`, подписка HB2, `wg://`, `vpn://`) несёт оба поля
  со значением true — выдавать всегда, а не только когда так вышло на хосте.
- Осознанный размен владельца: без cookie-реплаев слабее защита от подделанного источника.
  Для 3.x это принятое решение, а не случайность конфигурации.

### Приёмка

1. На сервере с 3.1 в конфиге стоят оба поля true и одинаковые безопасные `S1–S4`.
2. Профиль подписки и `.conf` несут `random_trailers` и `disable_cookies` = true.
3. Throne и HB2 подключаются и передают трафик; проба проходит без отброшенных пакетов.
4. Тесты по каждому формату; `verify.py` зелёный.

## Extension (requirements, 2026-09-15): корректировка S-политики 3.x

**Статус:** этот раздел заменяет R15 и R16 выше в части принудительной нормализации `S1`–`S4` и постоянного включения полей 3.1. Он создан до изменения реализации после проверки документации AmneziaWG и исходника используемого AWG-движка.

### R17 — Минимальная, а не выдуманная S-политика

- WHEN `HeaderProtectionKey` включён THEN HYDRA SHALL требовать для каждого `S1`–`S4` значение не меньше 12 байт; разные значения разрешены.
- HYDRA SHALL NOT заменять существующие или upstream-сгенерированные `S1`–`S4` на `32/32/32/32` только из-за перехода на 3.0 или 3.1.
- IF `RandomTrailers` уже включён на сервере THEN HYDRA SHALL сохранять единый набор S между сервером и каждым профилем; равные `S1`–`S4` допускаются как рекомендация upstream, но не как безусловное требование генератора.
- WHEN существующий набор содержит хотя бы одно `S < 12` при включённой Header Protection THEN HYDRA SHALL отказаться от применения с понятной причиной; он SHALL NOT молча подменять значения.

### R18 — Поля 3.1 принадлежат серверу

- HYDRA SHALL читать фактические `RandomTrailers` и `DisableCookies` из upstream-конфига и передавать их без изменения только в форматы, которые могут представить оба поля.
- HYDRA SHALL NOT принудительно включать `RandomTrailers` или `DisableCookies` в генераторе либо клиентских экспортёрах.
- WHEN `RandomTrailers` включён THEN HYDRA SHALL сохранять server/client согласованность и предупреждать, что upstream рекомендует стандартные совместимые `H1=1`, `H2=2`, `H3=3`, `H4=4`; изменение H-политики требует отдельного доказательства.

### Приёмка R17–R18

1. AWG 3.x с `S1=62,S2=86,S3=45,S4=21` и Header Protection проходит генераторную валидацию и сохраняется без переписывания.
2. Любой `S < 12` при Header Protection отклоняется до применения и без изменения файла.
3. Переключение 2.0 → 3.x не меняет `S` или флаги 3.1 без явного upstream-изменения.
4. Экспорты повторяют наблюдаемые серверные `random_trailers` и `disable_cookies`; неполный формат не публикуется.
5. Утверждение о живом handshake появляется только после отдельной серверной пробы.

### Evidence

- AmneziaWG docs: Header Protection использует первые 12 байт соответствующего S; равные S — рекомендация при `RandomTrailers`, не общее требование: <https://docs.amnezia.org/documentation/amnezia-wg/>.
- AWG v3 API: Header Protection требует `S1`–`S4` не меньше 12: <https://pkg.go.dev/github.com/amnezia-vpn/amneziawg-go/v3>.
- Используемый движок проверяет только каждое `S >= HeaderCipherNonceSize` (12), без требования равенства: `D:/go/pkg/mod/github.com/shtorm-7/wireguard-go@v0.0.5-extended-1.6.1/device/uapi.go`.

### Реализация (2026-09-15)

R17 закрыт в `hydra/plugins/amneziawg/presets.py`: принудительные `32/32/32/32` убраны, каждое поле рисуется в своём диапазоне с нижней границей 12, валидатор отвергает `S < 12` с именем поля. R18 закрыт доказательством: писателя этих полей в HYDRA нет (флаги берутся из серверного конфига и повторяются экспортами в обоих направлениях: `test_3x_flags_follow_the_server_in_both_directions`). Красное до фикса — `4 failed, 2 passed`, после — `6 passed`; фокусные AWG-наборы `115 passed`; `verify.py` → Ruff `All checks passed!`, `2043 passed`. Живой handshake остаётся TSK-020, а стабильный раскат ждёт ещё и Snell v6.
