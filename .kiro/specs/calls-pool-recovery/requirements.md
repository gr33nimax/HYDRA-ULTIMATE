# HydraVK Calls pool recovery

## Intent

HydraVK Tunnel must never report a partial VK room pool as ready. If an enabled Calls listener has fewer than four valid, unique room links, the next normal Sync Agent cycle must rebuild the complete blue/green pool, even when periodic pool rotation is disabled. Reuse the existing full-pool rotation rather than adding single-room mutation.

A room is considered available for this change only when the local managed pool contains exactly four unique, strictly valid VK join links and its expected creator units are active. No HTTP request to VK is made: it would make health depend on external availability and does not prove that a room can be joined.

## Boundaries

**Files:** `hydra/services/calls_infrastructure.py`, `hydra/services/maintenance.py`, and focused Calls/maintenance tests.

**Out of scope:** single-room replacement, VK HTTP/API probes, creator implementation changes, new configuration flags, and actual VPS/VK integration testing.

## Acceptance

- A pool with fewer or more than four links, duplicates, or invalid links is not ready and does not make Calls report running.
- A normal Sync Agent run rebuilds an enabled incomplete pool even when scheduled periodic rotation is disabled; a complete pool still follows the existing opt-in interval policy.
- Recovery reuses the existing transactional blue/green rotation and preserves its rollback behavior.
- Focused unit tests cover partial-pool status and the normal Sync Agent recovery decision; all affected tests pass.
