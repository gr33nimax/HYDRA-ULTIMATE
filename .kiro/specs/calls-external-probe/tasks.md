# Tasks: rate-safe HydraVK room verification

- [x] 1. Add runtime probe contracts and persistence
  - Define classified verifier results and a mode-`0600` runtime probe store.
  - Select due slots with six-hour cadence and 15-minute confirmation backoff.
  - _Requirements: R2, R3, R4, R6_

- [x] 2. Add the production anonymous VK/OK TURN verifier
  - Implement the bounded, redacted anonymous API evidence chain behind the probe port.
  - Add unit tests for successful TURN credentials and each classified failure.
  - _Requirements: R3, R6_

- [x] 3. Support transactional mixed-generation slots
  - Read legacy pool metadata, stage an inactive slot, apply mixed links, and restore on failure.
  - Keep full blue/green rotation compatible and reset probe state after success.
  - _Requirements: R4, R5_

- [x] 4. Wire the Calls health controller into maintenance
  - Serialize probing, confirmed recovery, and the existing 24-hour rotation through the Calls lock.
  - Add status without exposing secrets.
  - _Requirements: R1, R2, R4, R5, R6_

- [x] 5. Verify focused regressions
  - Cover scheduling caps, conflict priority, rollback, and safe error classification.
  - Run focused unit tests, ruff, and relevant architecture checks.
  - _Requirements: R1-R6_
