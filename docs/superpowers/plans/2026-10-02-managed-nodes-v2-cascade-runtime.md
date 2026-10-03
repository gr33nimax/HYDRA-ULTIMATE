# managed nodes v2 — production cascade runtime execution boundary

Parent-owned technical refinement of the approved design §9, not implementation
or evidence of working cascades. Implement only after the independent core-proof
recovery gate passes. Retain the third Luna:max worker; no fourth worker/reviewer.

## actual gap and reuse

`cascade_runtime.py` is only a Protocol. `ManagedNodeCascadeService` journals a
candidate and calls snapshot/apply/probe/profile/rollback ports, but production
composition supplies `None`. Supplying another fake, an always-true capability
map, or checking both ports independently does not close this gap.

Reuse canonical owners:

- `ApplicationService`, `ConfigurationApplier` and its snapshots/rollback;
- `PluginContainer.collect_fragments`, `ConfigFragment`, existing transport
  client/server renderers and protocol counter APIs;
- pinned mTLS `ManagedNodeClient`/agent and durable operation IDs;
- immutable profile/snapshot stores, read-only observations and existing five-minute
  sync coordinator. Their independently found read/accounting defects must be fixed first.

Do not apply the node-side full-user/full-protocol projection to the **base**.
`ManagedNodeApplyService._project_protocols` disables unassigned transports and is
not a base overlay API. Base users, enabled transports, credentials, subscription
URLs, routing policy and direct profiles must remain authoritative and intact.

## 1. actual scoped transport contexts

Initial production adapters are only `vless` and `anytls`, with settings validated
by their real transport owners. A selected-but-incompatible variant is explicitly
unavailable, never silently converted to another protocol/mode.

An entry context needs additional scoped authentication subjects on the existing
canonical protocol inbound, a same-protocol outbound to the exit, and a routing
rule matching **only** that entry subject. An exit transit subject must have an
explicit direct exit and must not match any entry context, including reverse B→A
routes. User A's normal direct credentials and routing remain unchanged.

Before implementing routing, verify that the pinned engine and both transport
owners expose the necessary authenticated-user metadata (the sing-box `auth_user`
rule candidate), including actual VLESS and AnyTLS user names. Unsupported metadata
is a concrete capability failure; no catch-all inbound/final route workaround.
Scoped rules precede broad existing catch-all rules without changing their meaning
for ordinary subjects. A missing/broken second hop cannot select `direct` at entry.

Extend the existing injected runtime contribution seam, not a global registry or
new plugin facade. Providers must use the **AppState passed into rendering**, not
re-read an older saved state: expiry/block/new-user changes must not leave stale
extra subjects active. Transport renderers receive ephemeral extra `User` subjects;
these never enter `AppState.users`, desired business-user digest/count, or public
subscriptions as independent users. Scoped outbounds/rules are typed contributions
merged by the canonical configuration owner. Render/query callbacks do not mutate
host or desired state.

## 2. credentials and public peer material

**Do not derive exempt transit credentials from public route IDs plus a subscriber's
known business UUID.** A subscriber could then compute an exit credential, connect
directly to the exempt transit account, and bypass first-hop billing.

Use a stable, random, protected per-route secret with domain-separated derivation
for participant, protocol, business user and entry/transit/probe role. Existing
protected credential facilities hold it with 0700/0600 atomic durable writes.
Neither seed nor derived passwords/auth UUIDs enter operation/state documents,
logs, exceptions, argv, public runtime/status, or published second-hop client config.
State stores only validated opaque credential references. Renaming preserves the
secret and IDs. Removing a route deletes credentials only after all necessary
participant cleanup is confirmed; rollback retains the previous material.

Credential transfer, where needed, is a bounded typed protected mTLS mutation,
not an arbitrary file/shell/config endpoint. Persist received material only in
scoped credential storage. Validate request target identity, operation ID, role,
receipt binding, size and field whitelist; secret-bearing DTO repr/logs are redacted.
The entry needs its scoped downstream credential; a public subscription needs only
the first-hop scoped credential. Technical probes have a separate identity and are
not business user/quota material.

Public peer parameters come from an authenticated receipt-bound canonical export:
address/public port, protocol/variant, SNI, Reality public material or verified TLS
trust policy. Do not persist a raw remote client config carrying UUID/password or
private filesystem paths in a plan. A local whitelist constructs the actual
outbound. No TLS bypass, arbitrary outbound types or secret-bearing log output.

## 3. participant transaction protocol

Provide a real production `CascadeRuntime`, with local-base and authenticated remote
participant implementations behind the existing runtime port. Necessary new
management-only participant prepare/query/apply/rollback/finalize operations may
be added as explicit bounded typed methods under the existing pin/source-IP gate;
there is no generic command, network proxy or filesystem RPC.

The coordinator freezes the public plan, credential references and participant
operation IDs before effects. Durable exclusion covers **both servers**, not just
the cascade ID. Ordinary sync/protocol edits and overlapping cascades cannot
replace a participant's pending intent. Network waits do not hold the state lock.

Required order:

1. Validate known distinct participants, selected same protocol, compatible settings
   and current authoritative business entitlements.
2. Persist immutable intent and scoped participant leases, then acquire a real
   snapshot on every affected participant before any configuration mutation.
3. Prepare credential/runtime contexts and apply using existing configuration and
   user owners. Query the exact receipt after a timeout before any replay.
4. Verify active context/config proof, not merely `operation.state == succeeded`.
5. Run the actual whole-path probe and gather publication material.
6. Switch only the cascade's confirmed profile pointer, then atomically confirm the
   desired definition/operation; readers reject uncommitted pointers and fall back
   to the previous confirmed route. Release leases/finalize snapshots afterward.

Successful **individual** participant apply must not discard the rollback snapshot
while the distributed operation can still fail. Current normal node apply removes
its snapshot on success, so do not reuse that success path blindly for cascades.

On uncertainty, preserve recoverable operation/leases and do not replay or forget.
On known partial failure, roll back every possibly affected scoped participant and
report original/rollback reasons separately. Base rollback restores route effects
without reverting independent newer business-policy changes. No distributed atomic
commit is promised. Local generated config is never a second desired-state source.

## 4. real whole-path proof

Run the actual compatible client with only the **entry** configuration through
both servers to an independently available bounded target. Require a correct
response and exit-path evidence: a unique route/protocol technical transit-context
counter change bound to the same active exit runtime, plus egress verification
where measurable. Two successful direct-hop probes, a process, port, desired file,
user count or fake runtime are insufficient.

The technical context is route-specific to avoid unrelated concurrent probes
creating a false exit proof. Do not expose its authentication UUID in public counter
samples. Every probe has one total deadline, a protected temporary config and
termination-before-cleanup. Missing client/material/target evidence is `unknown`,
not fake success, `not_applicable` for a supported transport, or a fabricated fleet
Offline status. No candidate profiles are published without proof.

## 5. accounting and normal sync

Bind real protocol counter names to explicit `(business user, context, role)`
metadata. Normal direct, cascade entry, transit and probe contexts are distinct.
The current `read_node_counters` only reads saved business-user emails; it cannot
magically count the new ephemeral subjects. Add the binding at the canonical
counter collection seam, not prefix-based guessing or traffic division.

Only direct and cascade-entry business bytes contribute to quotas. Exit direct
traffic remains billable; transit/probe bytes are excluded. Base-entry traffic must
also pass through canonical accounting without recharging local direct bytes.
Process/counter epochs and cumulative context high-water marks follow the recovered
producer/consumer contract. Take a final identifiable counter sample before context
retirement so removal does not discard earned consumption.

Existing five-minute sync and immediate targeted operations reconcile latest users,
expiry, blocks, resets and route contexts, refresh receipts/profiles, and perform
bounded path checks. No separate periodic timer. Reconfiguration of a route's
prerequisite shows consequences before confirmation. Node removal includes cleanup
on other affected participants; an unavailable necessary participant means durable
resumable removal, not offline forget/detach.

## 6. profile publication and validation

Export cascade profiles through canonical client renderers using the scoped entry
subject but the original business user identity in the confirmed envelope. Stable
profile identity is route/user/protocol; labels decorate from current desired name.
Each selected protocol yields its own profile. Renaming has no apply/rekey effect.
Direct IDs, links and credential material remain unchanged.

Dedicated cascade publication binds both participant receipts, current user policy
and actual path proof; it does not overwrite unrelated node profile pointers. Main
subscription reads only local committed material and filters current entitlements,
including stale fallback bundles. No query-time remote polling.

Test actual production adapters/rendered config, not only the coordinator Protocol:
all three supported topologies, multiple protocols, opposite isolated routes,
direct-profile stability, blocked/expired/disabled users, immutable retries,
unknown receipts, before/after-effect failures, rollback failures, crash publication
windows, rename/remove, counter/source restarts and single-count billing.

Add a separately invoked Linux integration scenario for isolated disposable hosts
with actual engine/client and mTLS, exit shutdown without first-hop fallback, and
verified egress/traffic. Never execute this privileged installer/host scenario
locally. CI wiring is not CI execution evidence. Explicitly distinguish real
unprivileged Windows/loopback evidence from Linux/root/SSH/VPS scenarios not run.

Parent reviews actual diff, runs focused/full/architecture/Ruff/compile gates and
records limitations before whole-product acceptance. A partial checkpoint cannot
satisfy tasks 7–9 or authorize deployment, commit/push, a fourth agent or fallback.
