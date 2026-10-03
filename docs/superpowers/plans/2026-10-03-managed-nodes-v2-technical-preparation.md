# production cascade — technical preparation before business activation

Parent-owned next implementation slice after accepted protocol/repr/budget fixes.
This does not promise live routing or permit publication without real-engine evidence.

## canonical lifecycle

Current `ManagedNodeCascadeRenderer` requires final path proof before rendering a
route; the coordinator's first candidate is absent from committed cascades. Break
that circularity with an explicit **technical** preparation input, never by publishing
an unfinished desired definition or by inventing a final render permit.

The following are separate facts:

1. frozen desired candidate and durable participant exclusion;
2. protected credential preparation and canonical technical-only configuration;
3. syntax/config receipt and actual running technical context;
4. actual first-hop client request observed through the second hop;
5. business activation and confirmed profile publication.

Preparation is allowed before fact 4, but only for isolated technical subjects.
Never infer fact 4 from hashes, process/socket/file/count checks or a fake provider.
Installed engine version/fingerprint is observed, not implicitly a pinned release.

## durable owner and participants

Use existing frozen `Operation.plan` and IDs as coordinator authority. A preparation
must bind operation ID and full public plan digest, route ID, local participant ID,
role, selected same protocol, actual engine identity and prepared-context/config
identity. Non-secret IDs/references may persist; auth credentials never enter plans.

Take immutable snapshots before credential/config mutation. Derive participant
leases from the active frozen plans using an atomic state update: conflicting
cascade changes and ordinary applies cannot replace either participant's pending
intent. Do not hold the state lock during network work. Updating both peers from
one plan is not a distributed atomic commit.

The local receiver validates its own authenticated identity/role against explicit
frozen participant metadata. It need not contain the base's full NodeDefinition
inventory. Removing that inventory assumption must not permit arbitrary peers,
wrong participants, same-server loops or mismatched protocol/plan/operation.

Do not change global/feature schema solely to duplicate the existing route-ID
credential reference. Any genuinely new durable state field requires an explicit
format decision, not an unnoticed exact-shape v1 edit.

## read-only staged rendering

Add a typed technical preparation context and an injected read-only provider to
canonical rendering. It supplies a frozen uncommitted candidate owned by an active
operation, not arbitrary render-time topology from saved business state.

Construct separate route/protocol/operation-scoped technical entry and transit
subjects from the protected random route secret. Existing role `probe` plus local
participant and a dedicated operation identity can domain-separate these identities.
Use no business user's UUID/credentials for the technical identity; do not add it
to persisted users, digests, quota or subscription output.

Per-plugin protocol scopes from the preceding fix remain mandatory. Match only the
technical entry subject to the same-protocol peer outbound; transit exits directly
and cannot enter another cascade. Existing business/direct routing is untouched.
Remote client material must be canonical, whitelist-validated and authenticated;
missing providers/material remain fail-closed. Do not loosen TLS/probe validators
or create a generic remote-config/command/filesystem endpoint.

Render has no filesystem or state writes. It consumes the AppState passed by the
canonical configuration owner, with immutable candidate/preparation bindings.
Prepare material in an explicit mutation owner, never in a provider getter.

Bind preparation to the context being applied and to the actual engine. Distinguish
pre-apply baseline config proof from post-apply prepared config proof: comparing the
new configuration forever to its old digest would disable its own staged context.
Avoid a self-referential digest of a config containing its own digest.

## promotion and invalidation

Successful technical syntax/application does not grant business activation. Final
promotion requires both participant receipts and real whole-path evidence for the
same operation, topology, protocol, configuration and engine identities. Technical
and final permits are distinct types/stages; an arbitrary hash-shaped document must
not be accepted as trusted evidence merely because it parses.

Engine drift, context drift, wrong receipt, stale lease, modified candidate or missing
proof blocks promotion. Rendering finalized business contexts re-filters current
expiry/block/disabled-protocol policy. No public profile/capability-success flag
before final proof; production without trusted preparation/proof/material providers
continues unavailable.

Interrupted stages retain snapshots/credential references and their original IDs.
Unknown apply result is queried before replay. Failed rollback keeps recovery data.
Retire only the staged scoped contexts during abort, not unrelated newer desired
users/protocols/routes. Preserve last confirmed business profiles until a verified
replacement/removal commits.

## current slice gate

Implement the real preparation owner/provider/typed rendering integration and its
local canonical tests. Network participant RPC, actual client/path verification,
final profile publication and accounting remain explicitly later work if not
implemented; no fake production support to make the broad acceptance green.

RED/GREEN scenarios: uncommitted candidate can render technical-only without final
permit; no committed desired mutation or business profile/user side effect; correct
local entry/exit without global definition inventory; wrong operation/digest/role/
participant/protocol/lease/engine rejected; mixed-protocol and opposite-route
isolation; queries do not create credentials; initial/persisted restart recovery;
failed stage and rollback retain safe evidence; final permit cannot be inferred
from syntax or an empty/missing path result.

Use actual canonical renderers and injected HostBackend in temporary tests. Observe
budgets after formatting and leave bootstrap headroom. Parent independently checks
diff/regressions/architecture/Ruff/compile and final project-Python suite. Windows
mock/render tests are not installed-engine, Linux/root/SSH/VPS evidence. Preserve
all deployment/git/agent limitations and the accepted earlier fixes.
