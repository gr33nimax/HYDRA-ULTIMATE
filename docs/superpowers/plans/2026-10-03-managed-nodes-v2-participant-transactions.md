# distributed cascade — authenticated participant transactions

Next product slice after the preparation-production owner fixes and independent
parent verification. Same third retained implementation worker; no new agents.

## existing canonical seams

`ManagedNodeCascadeService._execute` freezes a public operation plan, ensures all
participant snapshots, prepares scoped technical context, applies each participant,
queries uncertain outcomes, invokes path proof and then publication/commit. Its
injected `CascadeRuntime` still has no production implementation.

`ManagedNodeAgent.dispatch` and the existing mTLS/IP-restricted control transport
own remote management. Keep `/v1/apply`, `/v1/operations/<id>`, ordinary profiles
and technical probe contracts intact. Existing ordinary operation GET checks its
target equals the node ID; cascade operation targets a route ID, so use a distinct
typed cascade operation/status endpoint rather than weakening that identity check.

`ManagedNodeCascadePreparationOwner` owns immutable protected local preparations.
The canonical runtime contributor now consumes its revalidated read-only provider.
`ManagedNodeApplyGate` owns current persisted participant exclusion and a sealed
local owner capability; production ordinary apply cannot accept that capability.

## concrete next owner

Implement a real participant service and a concrete distributed runtime with:
- local participant adapter using canonical application/configuration ownership;
- remote participant adapter over the existing authenticated control client;
- durable scoped prepare/apply/query/rollback/finalize records and snapshots;
- authenticated receipt-bound technical material delivery.

Wire these production adapters, not only an injected fake Runtime in tests. Keep
missing actual engine/path/publication providers explicitly unavailable; do not
claim a ready cascade merely because the participant transaction works locally.

## typed protocol, no generic host RPC

Add a minimal namespaced cascade API for preparation, status/material, participant
apply, rollback and finalization. Requests and receipts have exact schemas and bind
operation ID, full immutable public plan digest, route/topology/protocol, local
receiver identity/role, engine and prepared configuration identities. Validate
bounded bodies, unexpected fields, malformed IDs and duplicate/reordered effects.

The receiver's authenticated identity comes from configured/pinned enrollment and
control security, not a request-supplied `authenticated=true`. The base coordinator
is the sole control caller; node→node routing does not require management access
from node A to node B. Base talks to each participant and relays only the typed
protected material needed for that operation. Do not open new management peers.

Nodes need not contain the base's complete enrollment inventory. Validate their
own identity and frozen explicit participants, not a copied global state aggregate.
Reject loop/same participant, protocol mismatch, foreign plan/operation/role and
stale engine/config/material. No arbitrary config, paths, commands or state import.

Route seed distribution, if needed for shared scoped derivation, uses an explicit
private transfer DTO over this mTLS channel into protected immutable storage. It
never enters AppState, public Operation.plan, status, repr, errors, logs or argv.
Frozen public material references/digests are not raw credentials. Import validates
local scope and operation before a protected write; repeated identical import is
idempotent, conflicting seeds fail closed, uncertain cleanup retains the seed.

## effects and recovery

Snapshot before every participant effect; immutable protected checksummed storage,
CAS/revision and context identity. Frozen participant IDs cover both old and new
route participants during edits. Lease each receiver before config changes.

Apply only the scoped overlay via the canonical transport render/config owner and
operation-bound apply authorization. For `base`, never use node `_project_protocols`
that disables protocols not assigned to one node. Preserve main users/protocols,
direct profiles and unrelated routes. Rollback restores the operation's scoped
runtime contribution, not a stale whole desired state over newer user changes.

A participant that applied successfully retains its rollback snapshot until the
entire distributed operation is finalized. Uncertain sends are status-queried by
original operation ID/plan before replay; unknown status cannot be treated as
not-applied. A failure after mutation must be distinguishable from a rejected
pre-effect request. Do not silently release uncertain leases or delete snapshots.

Rollback is idempotent and bound to the saved operation/context; failures retain
recovery evidence. Finalize releases only after coordinator confirmation, not after
an individual successful apply or an unverified technical response. Do not publish
business profiles while the participant transaction is merely staged.

## installed-engine/path gate remains explicit

Current HydraCore is the actually installed newest-channel release, not a pin.
Observe executable identity and config evidence through HostBackend; never install,
upgrade, rebuild or substitute the binary to satisfy these tests.

Config syntax/port/process/receipt is not `auth_user` support or end-to-end proof.
Future installed-engine capability validation needs positive authenticated-user
matching and negative control on an isolated technical context for the same binary.
Whole-path proof must issue an actual first-hop client request and observe the
expected second-hop technical exit, not count sockets or reuse direct probes.
No fake always-true proof/permit, direct fallback or generic unbound hash evidence.

This transaction slice may return honest unavailable at the later path/publication
gates; its actual adapters/receiver transitions must nonetheless be implemented
and wired. Engine capability/client/path proof, final profiles and single-count
accounting are the following slice, not a reason to produce a no-edits checkpoint.

## validation

RED/GREEN real client/DTO/agent/service roundtrip: both roles and all three topology
forms, no copied base inventory, frozen retry after response loss, no blind replay,
snapshot retention after successful peer apply, prepare/apply failure before and
after effect, rollback failure/restart recovery, finalize ordering, wrong receiver/
plan/role/protocol/seed/material, concurrent ordinary apply exclusion, no public
secret leakage. Use canonical renderer and injected temporary HostBackend; never
live host mutation locally.

Keep locked-file scope protected against unsafe ancestor paths; lock creation and
privileged filesystem policy belong to injected host/storage ownership, not generic
RPC. Do not widen existing state schemas silently or bypass architecture budgets.
Maintain formatting-safe headroom, source/import/cwd identity, final targeted,
architecture/Ruff/compile/full project-.venv verification and clean index.
Windows mock/roundtrip checks are not Linux/root/SSH/VPS/installed-engine evidence.
