# participant transaction checkpoint — parent rejection and recovery

Terminal child `99b0f095-6f81-4a96-ba12-1c7b21e34418` added actual typed RPC
and production transaction adapters. Broad readiness remains legitimately closed.
This checkpoint itself is not accepted for the following concrete reasons.

## final formatted gate fails

Native `architecture` failed: `hydra/bootstrap.py:311 production_application=162`
against unchanged method budget 160. Native full verification: 2734 passed,
1 Windows skip, 1 architecture failure. Reported 2736/all-green and old source
counts are stale. Extract a coherent composition responsibility, target function
<=145 after formatting and module with headroom. Do not delete blank lines,
disable formatter, weaken guards or rewrite unrelated formatting.

Re-run gates on the settled final tree, not on a pre-format/pre-compaction version.
The report must regenerate current interfaces/counts; it still says remote RPC is
absent in copied earlier interfaces while the new typed RPC is implemented.

## rejected terminal preparation revives cleaned credentials on base

Parent project-Python reproduction with current fixtures:

- `_owner(tmp, participant='base')`;
- frozen route `CascadeDefinition('route-tx', 'Route', 'exit', 'base', ['vless'])`,
  plan `cascade_id/previous=None/cascade`, request `cascade-tx/cascade_save`,
  participant base, role transit;
- `ensure_snapshot`, records begin/complete `snapshot`, `prepare` with the protected
  coordinator transfer, `rollback`, then mark the coordinator Operation failed
  with active_step None (as `_execute` does after confirmed rollback).

`credentials.exists(route.id)` is False after rollback. Calling `prepare` again
raises `cascade participant is not available for preparation`, but the same
`credentials.exists(route.id)` is now True.

Cause: `_require_operation` checks only identity/plan, not active ownership, and
`prepare` imports the seed before loading/checking the transaction's terminal
phase. The remote finalized/released record may happen to fail an earlier check;
that does not cover local base. A rejected replay must have zero mutations and
must not revive an old seed for a subsequently recreated route ID.

Validate the active frozen lease AND local transaction phase before credential or
material writes. Bind validation/mutation to atomic participant ownership so a
terminal/rollback/finalize race cannot slip between the check and import. Retain
valid idempotent prepare after preparation/apply response loss; unknown outcomes
are queried, not blindly replayed. Test base and remote roles and terminal states,
wrong scope, concurrent transition and recreated-ID behavior; verify no new file,
seed, revision or store mutation on rejection.

## snapshots contain identities, not restorable runtime content

Actual `CascadeParticipantStore.snapshot` persists only `request_digest`,
`engine_identity`, `config_identity` in the protected snapshot. Checksums and
immutability are good but a digest alone cannot restore prior runtime material.
`rollback` calls canonical apply of current state after marking rolling_back;
there is no protected saved owned overlay/material restoration input. Existing
fake apply callbacks/constant context hashes demonstrate status protocol, not
restoration of a real previous scoped context.

Complete the participant rollback ownership promised by the plan before calling
these snapshots rollback-complete. Explicitly capture the prior owned runtime
contribution/material/credential references and a canonical restore recipe before
mutation, or another actual bounded restorable artifact with equivalent scope.
The protected snapshot may contain private runtime material; AppState/public RPC
may not. Snapshot source is internal HostBackend/canonical configuration ownership,
never arbitrary request-supplied config/path/imported desired aggregate.

Rollback must remove the new owned overlay and restore the previous owned scoped
context while regenerating from the latest desired users/protocols. Never overwrite
new main desired users or other routes with a stale full AppState/config. If an
actual prior scoped context cannot be captured/restored, fail before effects rather
than pretend a hash is a snapshot. Add real canonical old-overlay -> mutate ->
failure -> rollback assertions for config rules/outbounds/subjects, preserving
unrelated direct routes and new desired users; simulate restart and failure after
mutation. Keep snapshots after individual apply until distributed finalize and
retain all recovery data on unknown outcome/failed rollback.

## scope

This is bounded transaction recovery, not a request to fake installed-engine
capabilities, whole-path success, final profiles or billing. Those remain next.
No old-product migration or fallback; unchecksummed old private snapshots remain
rejected, not an invitation to add compatibility. Do not regenerate earlier stages
or test inventory. Preserve mTLS/IP security, scoped subjects/secret repr, current
state/CAS/leases and all agent/host/git restrictions.

Actual project-.venv RED/GREEN then after-final-format architecture/Ruff/compile/
full verify/diff/index evidence. Parent independently reviews the final source.
