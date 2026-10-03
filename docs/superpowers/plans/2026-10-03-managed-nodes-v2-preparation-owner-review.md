# technical preparation owner review — actual production seam

The terminal worker is `3fcb15c7-e6b0-41b2-bf15-9bf5391b5b20`.
Its native mandatory gates pass, but whole criterion-1 remains unsatisfied.
The parent has reproduced the following production-path gaps; this slice is not accepted.

## 1. production contributions cannot stage even with trusted providers

Actual `production_runtime_contributions()` constructs `ManagedNodeCascadeRenderer`
without `engine_fingerprints_provider`. `_render_technical()` immediately returns
when this provider is absent. Passing the documented preparation owner and peer
provider cannot change that condition. The tests' `_renderer()` supplies the missing
provider independently, bypassing production wiring.

Parent project-Python reproduction uses the actual `_owner` fixture and protected
temporary store. Set `owner.credentials` to `CascadeCredentialStore(root=tmp_path /
'cascade-credentials')`, confirm snapshots, and `owner.prepare('stage-1', 'vless')`.
The fixture `_renderer(owner, owner.credentials, 'base')` emits one subject; the actual
`production_runtime_contributions(host=_Host(), root=tmp_path,
preparation_owner=owner, technical_peer_material_provider=_peer)` emits zero.
Owner's `preparations_for_render(state)` independently returns one valid context.

Fix the genuine canonical wiring/validation boundary. Technical rendering must
consume independently revalidated current-engine/context evidence from its trusted
preparation owner; it must not acquire a final business permit or fake fingerprint
provider merely to unblock staging. Default missing providers still emit no contexts
and create no files. Test the real production contributor and production application
composition with trusted injected providers, including engine/config drift after
preparation; never only the test-specific renderer factory.

## 2. base lease does not guard ordinary application apply

`cascade_leases.assert_node_unleased(namespace, 'base')` correctly rejects an active
base participant. However, `ApplicationService.apply_config` binds directly to
`OrchestrationService.apply_config`, whose process lock does not check persisted
cascade leases. Its `ConfigurationApplier.apply` preflight only prepares TLS;
config writes, nftables and reload proceed independently of `ManagedNodeRecords`.

Parent isolated reproduction called actual `ConfigurationApplier.apply` with an
active base candidate from `_state(_route())`. Use injected no-op TLS/TPROXY,
registry, transaction and Sing-Box adapters; injected `write_config` records a call
and returns False to stop before any host effect. Output:
`record lease blocks base: True`, `canonical ordinary base apply reaches config write: True`.

Guard the actual ordinary apply entry before TLS preparation, snapshots/mutations,
config/firewall/reloads and any desired-state restore/save. A lease rejection must
not flow through generic failed-apply rollback that writes a stale snapshot. Check
current persisted intent atomically with ownership/serialization, not only a stale
caller-provided state lacking the operation. Both participants must remain excluded.

Only a separately validated, operation-bound participant apply may own its matching
lease. Do not bypass this with a public boolean or globally setting a current
operation ID; remote generic apply cannot claim a cascade owner by guessing its ID.
The network/participant runtime remains the next slice, but do not permanently deny
its future explicit owner path. Inject a service-level authorization/guard boundary
if needed; preserve the core dependency direction and application facade contracts.

RED tests must cover ApplicationService/production ordinary apply under an active
base lease, zero host effects and zero save/restore on rejection, stale caller state,
conflicting operation, legitimate ordinary apply after confirmed lease release,
and safely bound owner authorization. Preserve user desired changes; exclusion
must not silently roll them back or overwrite them.

## 3. private context filename must identify a tuple unambiguously

`CascadePreparationStore._path_parts` joins operation/route/participant/protocol
with `-`, but each ID may contain `-`. `(op='a-b', route='c', participant='exit')`
and `(op='a', route='b-c', participant='exit')` produce the same filename. Scope
validation prevents reading another context, but immutable creation makes one valid
operation block the other. Use a canonical, unambiguous tuple key (e.g. SHA-256 of
canonical JSON tuple) or safe separate scoped components. This is not deriving an
auth secret from public IDs. Add the collision regression; no legacy adapter or
silent migration of this unaccepted private store.

## scope and gates

Do not rebuild stages 1/2, regenerate retired-test inventory, or fill live providers
with synthetic successes. Keep final business publication and actual engine/path
proof fail-closed. Preserve scoped subjects, protected repr, snapshots/CAS/accounting,
mutual TLS/IP policy, main users/protocols/URLs and all host/git/agent restrictions.

Bootstrap is back near its ceiling (490), records 499/500. Extract coherent managed
composition/cascade persistence responsibilities if these fixes need space; leave
formatting-safe headroom, never compress whitespace or weaken guards.

Actual project `.venv` RED/GREEN tests first, after-formatting targeted/architecture/
Ruff/compile/full verify/diff/index gates. Native default-Python gates alone do not
replace the project interpreter. No local Linux/root/VPS/installer operations.
After the owner fixes, the parent reviews actual source and reproductions before
proceeding to authenticated participant transactions and real path evidence.
