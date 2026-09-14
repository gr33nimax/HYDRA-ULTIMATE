# 0001 — One Calls health controller owns targeted and scheduled rotation

## Context

A failed VK room should be replaced without recreating three healthy rooms, but Calls must retain its configured 24-hour full-pool rotation. Independent health and rotation jobs could race and create needless VK traffic.

## Decision

One Calls health controller runs under the existing operation lock. It probes rooms, confirms remote failure, performs targeted slot replacement when the daily full rotation is not due, and performs the existing full rotation when it is due. The full rotation resets probe history for the new pool.

Targeted replacement represents the pool as four independently assigned slots. It starts the failed slot in its inactive generation, verifies a new distinct link, applies the mixed four-room configuration, then stops the old slot. If creation or apply fails, it stops the staged slot and keeps the old configuration and unit.

## Consequences

Pool metadata and snapshot/restore must preserve the generation per slot. Existing legacy metadata containing one `generation` remains readable as four slots of that generation. Runtime probe state is separate from desired `AppState`.

## Links

- `.kiro/specs/calls-external-probe/requirements.md`
- `.kiro/specs/calls-external-probe/design.md`
