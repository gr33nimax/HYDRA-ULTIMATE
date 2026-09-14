# Requirements: rate-safe HydraVK room verification

## Overview

HYDRA currently verifies only its local room-pool files and creator units. Add a rate-limited external verification that establishes whether VK accepts a room link and issues TURN connection credentials, following the evidence level used by the TURNVK checker. One Calls health controller owns the local check, external verification, targeted recovery, and existing 24-hour full-pool rotation.

## User story

As a HYDRA administrator, I want HYDRA to detect a VK room that was deleted or became unavailable remotely, prove the failure before replacing it, and retain the established 24-hour pool rotation without creating a high-frequency VK API load.

## Requirements

### R1 — Local health remains authoritative for immediate host failures

- WHEN a room link is missing, malformed, duplicated, or its creator unit is inactive THEN HYDRA SHALL mark the pool unhealthy and use the existing recovery path without waiting for an external probe.
- The external verifier SHALL NOT replace local pool validation.

### R2 — Scheduled external probing

- WHEN an enabled HydraVK pool is locally healthy THEN HYDRA SHALL schedule one external probe for each of its four rooms no more often than once per six hours.
- WHEN a four-room sweep is due THEN HYDRA SHALL start probes one at a time with at least 60 seconds between starts.
- HYDRA SHALL persist runtime-only probe timestamps and outcomes outside desired configuration state.

### R3 — External success criterion

- HYDRA SHALL classify a room as externally healthy only when the verifier confirms that the room link is accepted and TURN connection credentials are issued.
- The verifier SHALL NOT expose join links, credentials, cookies, or authorization values through status, logs, errors, or persisted desired state.
- Actual WebRTC media transfer and TURN packet exchange are out of scope for this feature.

### R4 — Failure confirmation and recovery

- WHEN a scheduled external probe reports a room as dead THEN HYDRA SHALL re-probe only that same room no earlier than 15 minutes later.
- IF the confirmation probe succeeds THEN HYDRA SHALL keep the room and record the transient failure.
- IF the confirmation probe fails and a full pool rotation is not due in that maintenance run THEN HYDRA SHALL atomically replace only that room, preserve the other three rooms, and retain rollback capability if replacement or config apply fails.
- IF the confirmation probe fails while the 24-hour full pool rotation is due THEN HYDRA SHALL perform the full rotation instead of first replacing one room.
- HYDRA SHALL not perform more than one confirmation probe or one targeted room replacement for the same room in a six-hour scheduled window.

### R5 — Scheduled full-pool rotation

- HYDRA SHALL retain the existing 24-hour full-pool rotation for enabled Calls when it is configured.
- The same Calls health controller SHALL own both scheduled full-pool rotation and health-triggered recovery; they SHALL NOT run as independent concurrent jobs.
- A successful full-pool rotation SHALL reset external probe history for all four new rooms.

### R6 — Operational behavior

- WHEN a creator operation or pool rotation is already in progress THEN HYDRA SHALL defer a due probe or room replacement rather than run concurrently.
- WHEN the external verifier encounters a network, rate-limit, CAPTCHA, or unexpected service error THEN HYDRA SHALL record a classified outcome and not treat it as proof that the room is dead.
- Status SHALL distinguish local health, last external verification time, and pending confirmation/recovery without exposing secrets.

## Out of scope

- VK HTTP page checks that do not obtain TURN credentials.
- Running arbitrary third-party binaries. The administrator approved the two public anonymous application identifiers used by the TURNVK-compatible API flow; HYDRA does not copy cookies, account credentials, or issued TURN credentials.
- Verifying real media traffic or performing WebRTC calls.
