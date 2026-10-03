# scoped cascade foundation — parent review of ad054278

The foundation is partial and not accepted. The native final-tree architecture
and full verification **failed**: `hydra/bootstrap.py=501`, 26 architecture tests
passed, full suite 2698 passed / 1 Windows skip / 1 failure. The writer report of
"full verification passes" predates final formatting/gates and is not final evidence.
Snapshot: `C:/Users/user/AppData/Local/Temp/hydra-node-v2-runtime-foundation-tum4soxt`,
HEAD `57c4ed0`, clean index, tracked patch SHA
`44b0081f42369a97a3b2c74c9949c7eb7f4edc42d972e0a7ca7cbfff78038499`,
74 new source/doc files ZIP SHA
`62e1e7b3ed969884362e671a908243f3997730eaeec7bfc88313c3a564abe65c`.

## reproduced protocol isolation defect

`RuntimeSubject` currently carries only name/UUID. `PluginContainer.collect_fragments`
extends one copied state with **every** runtime subject, then invokes **every** plugin
on that state. Ephemeral users have empty `disabled_protocols` and no transport scope.

Parent used real `_state/_renderer/_canonical_peer` fixtures and canonical
`PluginContainer([VlessXhttpPlugin(), AnyTLSPlugin()])` + `generate_config`:

- one VLESS-only route and its VLESS entry subject;
- both VLESS and AnyTLS enabled on the participant;
- actual VLESS inbound contains the VLESS subject: **true**;
- actual AnyTLS inbound contains the same VLESS subject: **true** (must be false).

This can admit first-hop credentials through a different transport and violate
same-protocol hops/isolation. One-protocol fixtures cannot detect it.

Fix the dependency-neutral runtime contribution contract and its canonical consumer
so each subject is explicitly protocol-scoped. Prefer a per-plugin scoped render
state/subject selection; do not depend on an arbitrary transport plugin honoring
an extra user's disabled list to enforce the boundary. Ordinary business users and
policy must remain unchanged. Technical probes explicitly whitelist supported
protocols too, not unrestricted access to unrelated transports. No new global registry.

Add RED tests with both transports enabled: VLESS-only, AnyTLS-only and two selected
protocols/opposite routes. Check actual inbound rosters, outbound types, scoped rules,
direct credentials/profile stability and source state nonmutation. Preserve existing
assertions; helper tests are not installed-engine path proof.

## reproduced secret representation defect

`CascadeCredentialScope.__repr__` and `RuntimeSubject.__repr__` are protected, but
`CascadeCredentialScope.subject(...)` returns the regular `User` dataclass. Parent
verified **`subject.uuid in repr(subject) == True`** without printing the credential.

All new secret-bearing intermediate objects must also have protected representations.
Do not solve this only by hiding the outer DTO. Keep domain dependencies and business
`User` behavior stable; avoid a broad unrelated public model rewrite. Add a regression
covering the returned/intermediate subject and peer/contribution errors. Seed and
second-hop credentials must not enter state/plans/public status/argv/logs.

## formatting-safe bootstrap responsibility

Extract a coherent composition responsibility and leave headroom (target ≤470 lines
for `bootstrap.py`), preserving sole canonical production wiring and dependency direction.
Do not remove blank lines or disable the formatter/guard. Report and verify **after**
formatting; never claim the pre-format count/gate as final. No repeated full gates before
final code settlement are needed.

## staging/proof lifecycle gap to resolve before participant implementation

`ManagedNodeCascadeRenderer.render` requires a final `CascadeRenderPermit` containing
entry/exit receipt hashes and **path_proof_sha256** before it creates any subject/route.
It also only reads committed `namespace.cascades`. But the first participant/path proof
needs a route, and an uncommitted coordinator candidate is not in that namespace.
Without a separate technical preparation state this is a circular prerequisite.

Define explicit read-only render input from frozen, leased participant preparation:
only a dedicated technical subject may be staged before whole-path proof; no business
subjects/profile/capability publication. Use operation ID/context/config/engine bindings
and protected credential refs. Promote to business contexts only after the real proof.
This must not treat arbitrary hash-shaped strings, boolean flags or process/port checks
as valid proof. Current production providers remain absent/fail-closed until real owners
are implemented. Do not add global schema migration merely for a redundant reference.

Exit participant validation cannot assume its local state contains the base's entire
`NodeDefinition` inventory. Use explicit authenticated participant-context metadata
bound to the frozen plan; never weaken target/role validation to accept arbitrary peers.

Preserve accepted cumulative accounting, stores, mTLS/base-IP, desired/runtime separation,
snapshots/CAS/rollback and prior direct profiles. Pending semantic retirement-proof
repairs remain in `2026-10-02-managed-nodes-v2-parity-owner-review.md`. Whole-product
acceptance remains blocked by actual participant transactions, engine/whole-path proof,
publication and source-scoped single-count accounting. No VPS/Linux/root proof or
commit/push/deployment is authorized.
