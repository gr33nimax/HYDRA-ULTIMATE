# managed nodes v2 — recovery of independently reproduced defects

Status: parent-owned implementation refinement of the approved replacement; not completion evidence.
No new worker or changed model is authorized by this document. Continue the retained third worker.

## immutable checkpoint

Before parent review, the stopped writer's tree was preserved outside the repository:

- directory: `C:/Users/user/AppData/Local/Temp/hydra-node-v2-core-recovered-zfkggpcu`
- tracked patch SHA-256: `d9d12426c6f07513281411cab748afabef0b4a272394b6d71f517d1601a68213`
- 64 new source/doc files ZIP SHA-256: `0f6d70be96fffd81dabc3a222742cba02e349990112508a13fc62cb2742c490a`
- branch `dev`, HEAD `57c4ed0`, clean index.

The snapshot is for preservation and reading, never a command to restore the active tree.

## 1. producer → wire → consumer accounting

Parent independently ran `record_node_counters` followed by `apply_traffic_samples`:

| process | raw bytes | exported `used_bytes` | base billed total |
| --- | ---: | ---: | ---: |
| process-one | 100 | 100 | 100 |
| process-two | 30 | 130 | 230 |

The correct total is **130**, not 230. This is a real composition bug, not a need
for another polling timer or a problem with configuration-generation fingerprints.

Canonical source: `hydra/services/managed_nodes/accounting.py`.
Producer exports a cumulative context total across process/counter restarts.
Consumer currently sums those cumulative totals under separate counter epochs.

Keep the existing producer assertions intact, including `150 + 200 -> 350` in
`test_node_counter_first_sample_and_new_runtime_epoch_preserve_all_bytes`.
Do not change test expectations to camouflage this defect. Clarify the existing
wire semantics: within one `(node, user, context, reset_epoch)`, `used_bytes` is
cumulative; `counter_epoch` identifies the observed counter lifecycle, not another
additive source of consumption. Sum separate nodes/contexts, not repeated history
inside a cumulative context. A context high-water mark over epochs is sufficient;
do not introduce an extra wire field, independent accounting registry, or divide
all traffic by two.

Add RED regressions exercising real producer outputs and DTO round trips into the
real consumer. Cover first sample, same-process increments, duplicate/stale/out-of-order
samples, process restart, raw counter reset without process restart, user reset and
late old-reset samples, and retiring a node after multiple process epochs. Both
recompute and retirement must use the same cumulative-context interpretation.
Keep read-only projections free of baseline writes. Transit/probe exclusions and
independent direct traffic on an exit remain applicable.

## 2. reproducible architecture gate

Despite the writer's report of passed guards, the parent ran project-venv pytest
against the current tree and the unchanged size guard failed:

- `hydra/bootstrap.py`: 522 lines;
- `hydra/services/managed_nodes/sync.py`: 506 lines.

Do not modify guards, compress lines/remove whitespace to evade budgets, or move
logic into a facade. Extract an actual coherent responsibility with explicit
injection and preserved dependency direction. Production wiring remains owned by
`hydra.bootstrap.production_application`; services cannot import the composition
root. Keep frozen-intent recovery and the single five-minute coordinator intact.

Before validation, print actual cwd, interpreter, imported HYDRA path, source hashes
and line counts for these modules. Use the project `.venv/Scripts/python.exe`, not
an unverified interpreter/PYTHONPATH. Explain any mismatch with earlier reported
results using evidence, not a guessed cause. Report verification for the final tree,
not a tree edited after the last command.

## 3. retained invariant proof after legacy retirement

The retirement map currently groups old files with new files. It does not give the
requested old-test-name → requirement → exact new assertion mapping. Complete that
mapping using HEAD and the preserved pre-retirement patch for source inspection
outside the active tree. Never restore the legacy product or weaken shared guards.

Concrete retired examples that need actual replacement proof:

- immutable durable snapshot/bundle storage;
- tamper/hash and oversize rejection;
- symlinked storage root, node directory, pointer/bundle/snapshot paths;
- base source-IP restriction, pinned node ID, wrong/malformed pins, missing/untrusted
  client identity, malformed/cross-node payload before effects;
- read-only status without secrets; redacted apply failure;
- uncertain apply recovery, failed rollback, future-format and revision conflicts.

Read the actual existing assertions before claiming coverage. The new loopback
transport suite has three test functions; multiple purposes may share a test, but
coverage must point to real assertions, not just the file's name.

Parent source review found a specific read-path gap to test first:

- `ManagedNodeProfileStore.commit` checks root/node-directory symlinks, but `read`
  only checks terminal pointer/bundle files;
- `ManagedNodeSnapshotStore.save` checks root symlinks, but `load` only checks its
  terminal file.

Reject traversing those symlinked directories on reads as well. Do not reuse a helper
that creates directories during a read-only status/subscription operation. Use temp
fixtures, avoid any real privileged paths, and preserve existing valid assertions.

## 4. gate and handoff

Run focused RED/GREEN; all managed-node suites plus generic `test_node_sync.py`;
unchanged architecture graph/audit/size guards; Ruff; compileall; project-Python
`verify.py`; `git diff --check`; clean index. Parent independently re-runs the gate.

The earlier background full check did not start Python because cmd.exe rejected
`./.venv/...`; it is not test evidence. The corrected background command is
`.venv\\Scripts\\python.exe verify.py`.

This checkpoint does **not** implement production cascades. Keep them fail-closed;
no fake runtime/capability table may be published as a working path. Whole-product
criterion-1 remains unsatisfied until actual two-hop runtime, profiles, probes and
single-count accounting are implemented and independently reviewed. Windows tests
are not Linux/root/SSH/VPS proof. No commit, push, deployment, extra agent/model,
privileged local operation, installer execution or unrelated cleanup is permitted.
