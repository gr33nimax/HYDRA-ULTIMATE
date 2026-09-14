# Design: rate-safe HydraVK room verification

## Overview

The Calls health controller owns all room lifecycle decisions: local pool validation, low-frequency VK TURN verification, targeted recovery of a confirmed dead room, and the existing 24-hour full-pool rotation. It serializes those decisions through the existing Calls operation lock so the mechanisms never race.

## Architecture

```text
Sync Agent (existing cadence)
  -> CallsHealthController
     -> local pool check
     -> ProbeScheduleStore selects one due slot
     -> VkTurnProbe verifies that slot
     -> ProbeScheduleStore records outcome
     -> confirmed dead slot:
        full rotation due -> CallsService.rotate_native_vk()
        otherwise         -> CallsService.replace_native_vk_slot(slot)
```

The current Sync Agent runs more slowly than one minute. To avoid adding a second timer or blocking a sync cycle, the controller starts at most one probe per maintenance run. This exceeds the requested one-minute separation; a four-room sweep is therefore spread across normal Sync Agent runs. No sleeping loop is introduced.

## Components and interfaces

### `CallsHealthController`

An application service invoked by Calls maintenance. It evaluates due probe work and the existing full-rotation deadline in one operation under the Calls lock. Its priority is: local failure recovery, confirmed remote failure, then scheduled full-pool rotation. A confirmed remote failure uses full rotation when that rotation is due in the same maintenance run; otherwise it replaces only the failed slot.

### `VkTurnProbe`

A small injected port returning a classified result: `healthy`, `dead`, `network`, `rate_limited`, `captcha`, or `error`.

Its production adapter implements the same evidence chain found in TURNVK: obtain an anonymous VK token, request call preview, obtain an anonymous call token, perform the CDN anonymous login and join request, and accept success only when the response supplies non-empty TURN username, credential, and URLs. It has bounded per-request and total timeouts, redacts all link/token values, and has no access to stored VK cookies.

### `ProbeScheduleStore`

Persists runtime-only data in a mode-`0600` file beside the Calls pool, separate from desired state and current pool metadata:

- room slot and current link hash;
- last scheduled probe timestamp/result;
- `confirmation_due_at` after one `dead` result;
- last replacement timestamp.

A changed slot hash resets its prior probe history. A normal slot is due after six hours. A dead result is due once for confirmation after 15 minutes. Network/rate-limit/CAPTCHA/error outcomes are recorded but are not dead and wait for the next normal interval. A full rotation resets all four entries.

### Per-slot creator ownership

Pool metadata moves from one pool-wide generation to four ordered slots, each holding a generation (`a`/`b`) and hash. Legacy metadata with one generation is read as four slots using that generation.

For slot `N`, targeted replacement starts only the unit from the other generation (`a-N` or `b-N`) and waits for a valid, distinct link. It stages the mixed four-slot metadata, applies the Calls configuration, and only then stops the prior unit. On any failure it stops the staged unit and restores the runtime snapshot and pre-change configuration.

A scheduled 24-hour full rotation continues to create a uniform new generation through the existing blue/green path. It is not a separate maintenance job: the controller performs it only after any due health work has been resolved or deferred.

## Rate limits and concurrency

- One normal probe per slot per six hours.
- At least 60 seconds between probe starts; existing Sync Agent cadence makes the real gap larger.
- One confirmation probe at least 15 minutes after a `dead` result.
- At most one confirmation and one targeted replacement for a slot in its six-hour window.
- One full-pool rotation per existing configured 24-hour interval.
- The existing Calls operation lock owns probes, targeted replacement, manual rotation, and scheduled full rotation. A busy lock defers work; it never overlaps creator changes.

The worst steady-state external rate is four probe operations per six hours, not a burst. Each operation itself performs multiple VK/CDN requests, so the design deliberately avoids retries for non-dead operational failures.

## Error handling

- Missing/corrupt runtime probe data resets only scheduling history, never desired Calls configuration.
- A `dead` confirmation recovery failure produces an explicit maintenance failure; it does not quietly claim recovery.
- Network, CAPTCHA, and rate-limit outcomes do not replace a room.
- Secrets and join links remain redacted from results, journal entries, and status.

## Testing strategy

Unit tests cover schedule selection, interval/backoff caps, classified results, probe-state reset after slot replacement and full rotation, mixed-slot link ordering, rollback before config apply, rollback after apply failure, full-rotation priority, and maintenance deferral on a held lock.

A Linux integration smoke is required separately for the production verifier and systemd mixed-generation slot replacement. It needs a valid public test room but is not run locally.

## Links

- `.kiro/decisions/0001-calls-slot-replacement.md`
- `.kiro/specs/calls-external-probe/requirements.md`
