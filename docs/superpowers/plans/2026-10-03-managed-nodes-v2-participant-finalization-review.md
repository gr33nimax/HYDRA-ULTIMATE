# parent review of stopped participant recovery tree

Reviewing child `3b3eb9d0-6fc8-492a-94ee-a2856dc64462`, stopped after
workflow `7aa3e5d4-860e-4460-9cb8-000dec9f7c16` timeout. Its report is not
independent acceptance. The owner seed-replay correction DOES pass the exact
original parent reproduction: base rollback removes the seed; rejected prepare
keeps it absent and preserves revision. Protected scoped restoration content
now exists; no installed-engine/live-path readiness is implied.

Three additional concrete transaction defects block checkpoint acceptance.

## 1. completed rollback/finalize cannot be replayed after response loss

Project-.venv reproduction using current `_owner/_request/_coordinator_transfer`
in `tests/test_managed_node_cascade_participant.py` and temporary directories:

- ensure_snapshot -> prepare -> rollback returns `rolled_back`;
- immediately call rollback again: `ValueError: cascade participant file is unavailable`;
- independent fixture ensure_snapshot -> prepare -> actual owner apply (test
  context changed to PREPARED) -> finalize with coordinator digest returns
  `finalized`; immediate identical finalize also throws the same error.

Both terminal branches call `store.remove_snapshot` again. That method calls
`_safe_file(path)` with missing_ok=False, although the first successful terminal
call already removed the snapshot. The following HostBackend.remove_file's
missing_ok=True is unreachable. This breaks original-ID recovery of lost terminal
responses and restart recovery. Make absence idempotent at the shared snapshot
cleanup owner, retaining unsafe/symlink/ancestor/nonregular/permission checks.
Add remote and local terminal replay, restart, actual mTLS response-loss tests and
no extra apply/seed/state mutation assertions. No generic exception suppression.

## 2. snapshot write can succeed with an artifact its reader refuses

`CascadeParticipantStore.snapshot` validates a context but does NOT check the
encoded envelope length before HostBackend.atomic_create. `_write_record` DOES
bound its encoded bytes. `_safe_file/_read` both cap snapshots at _MAX_RECORD=1MiB.

Parent reproduced a valid entry restore context for route `route-size`, protocol
VLESS, 4,000 uniquely scoped subjects, each corresponding outbound and auth_user
forward/reject pair. Request is a frozen save of an existing route. Context
validate_for passes. `store.snapshot(request, 'a'*64, 'b'*64, context)` succeeds,
creates a **1,750,079-byte** snapshot AND a participant record. Reading that same
artifact via snapshot_data immediately fails `cascade participant file is unsafe
or too large`. Participant ensure_snapshot can therefore confirm a snapshot that
cannot be used for rollback after subsequent effects.

Bound the entire encoded snapshot envelope before creating snapshot OR record;
no unreadable artifact/receipt may be confirmed. Existing safety policy remains
unchanged (do not merely increase reader limit or remove bound). A valid oversized
context must fail before effects/private partial writes; boundary-size accepted
artifacts must round-trip. Include current generated config within its 8MiB limit
while snapshot exceeds 1MiB to prove independent limits. No massive pasted fixture;
generate subjects in the test. Retain immutable write-once checks and checksums.

## 3. cascade_remove cannot enter its defined apply phase

Exact project-.venv reproduction:

- old route `CascadeDefinition('remove-route','Route','base','exit',['vless'])`;
- plan `{cascade_id: route.id, previous: route.to_document(), cascade: None}`;
- CascadeParticipantRequest('remove-op','cascade_remove', route.id,
  canonical_digest(plan), plan, 'exit','transit',route,'vless');
- `_owner(tmp, capture_restore_context=lambda s,op,r: CascadeRestoreContext.empty(r))`
  with callback intended to remove its owned config;
- owner.ensure_snapshot(request); owner.apply(request).

This raises `ValueError: cascade participant phase transition is invalid` BEFORE
calling apply_config. `_apply_owned` expects snapshotted for cascade_remove, then
writes applying; `_transition` only permits prepared -> applying. There is no
remove preparation endpoint/step that changes that expectation.

Also inspect the next post-effect branch: remove's record receipt is the baseline
snapshot receipt, yet `_apply_owned` compares the new config hash to that OLD
config identity. A real removal changes config and would then be rejected even
if the phase transition were patched. Fix the removal transaction coherently:
validate/freeze actual canonical target context before effects, preserving the
pre-effect scoped restoration artifact. Confirm post-effect context against the
right removal target, not the old baseline or an invented hash. Missing target
render evidence must fail BEFORE effects. Do not ignore hash checks or allow all
snapshot/apply phases indiscriminately just to make removal pass.

Add real canonical remove-success and before/after-effect failure -> rollback,
including removal of owned subjects/rules/outbounds, keeping current desired main
users/direct routes/other cascades. Cover old/new participants and original IDs,
restart/retries and finalization. This is existing participant transaction behavior,
not implementation of final cascade publication, billing or synthetic path proof.

## execution constraints and evidence

Same retained third logical worker only, no extra reviewer/model/tool fallback.
Read current source/tests and fix canonical owners with RED/GREEN assertions.
Keep architecture limits with after-formatter headroom; no compressed lines,
weakened/removed assertions, legacy adapters/migrations, deployment or privileged
host commands. No git stage/commit/push/reset/restore/stash/clean/branch switch or
unrelated cleanup. Keep exact schema/business state/main URLs/engine/protocols.

Run project-.venv targeted gates then current formatted architecture/Ruff/compile/
full verify/diff/index. Report actual native outcomes and residual whole-product
blockers; don't reuse stale green counts. Full criterion-1 remains honestly closed
until installed-engine capability, whole-path proof, publication/accounting and
Linux/VPS evidence; it does not mean abandon these bounded corrections.

## parent inline resolution — three reproduced blockers

The retained worker could not resume (`was stopped and cannot be resumed`). The
owner explicitly chose `исправь сам`; the parent implemented only these bounded
transaction corrections, without starting another agent or changing the engine.

- Terminal cleanup tolerates safe snapshot absence and retains path-safety checks.
  A released remote lease is not updated again; original receipts survive cleanup
  retries without extra apply, seed recreation, record changes or revision bumps.
- Snapshot creation bounds the full encoded envelope before root/artifact creation.
  The existing 1MiB reader policy is unchanged. Generated oversized contexts and
  exact envelope-boundary round trips are covered.
- Removal freezes a trusted canonical target through the internal orchestration
  preview port, then uses the existing prepared -> applying transition. Snapshots
  remain rollback evidence, not removal-target evidence. All local protocol
  snapshots are required before the participant's whole frozen route contribution
  is removed. Confirmed sibling contexts remain stable; unrelated cascades, direct
  routes and enabled main protocols are not globally rerouted or removed.
- Target bytes match canonical text-mode serialization (including Windows CRLF).
  Installed byte hashes are still compared exactly. Missing/invalid target evidence
  and baseline drift reject before effects. Lost apply responses preserve recovery;
  scoped rollback regenerates against latest desired users.

Fresh final-format native evidence, project `.venv`, cwd/import verified:

- Recovery RED: `bb19f3de5` failed before fixes; recovery GREEN `bd247598e`:
  **18 passed / 4.33s**.
- Removal RED `b346df7f7`: **3 failed**; additional all-protocol/snapshot guards
  failed **2 cases / 5 passed** before their corrections.
- Focused regressions plus unchanged architecture guards `b7fd66ffd`:
  **79 passed / 27.39s**.
- Final whole-tree `b5009025b`: `verify.py` (compileall, Ruff, pytest),
  `git diff --check`, and clean index check all exit **0**;
  **2756 passed / 1 Windows bash skip / 7 existing tar warnings / 128.73s**.
- Seven implementation/test SHA-256 values captured by the final command match
  the current files. Branch `dev`, HEAD `57c4ed0`; no staging/commit/deployment.
- Formatted module sizes: participant 483, store 416, removal helper 83,
  orchestration 456 lines; largest functions respectively 56/71/66/43 lines.

These three blockers are resolved; this is not whole-product acceptance. The new
restart regression replaces the participant store, not a whole live service/process.
The canonical runtime tests use real plugin/config generation and sandbox writes,
not an installed engine or a Linux/VPS. A new end-to-end lost-terminal-response
mTLS/service-restart experiment has not been performed. Active LSP probes were
inconclusive; actual Ruff/compileall/architecture/pytest gates are the evidence.
Installed-engine capability, whole-path proof, final publication/accounting,
Linux/VPS evidence and the ten semantic legacy-parity gaps remain open.
