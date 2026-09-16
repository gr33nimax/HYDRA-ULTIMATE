# 0003 — AntiDPI uses a closed evidence allowlist

## Status

accepted

## Context

AntiDPI currently turns broad TLS, kernel, UDP, auth and correlation telemetry into alerts and scores. The owner requires bans only for protocol-owned rejects with exact external-IP attribution and explicit scanner paths on decoy sites.

## Decision

Keep the antidpi compatibility identity but narrow production behavior to a closed allowlist: exact protocol reject or decoy scan leads directly to the existing ban path; every other input is discarded before persistence, scoring and notification. Remove generic observers and correlation from the enforcement path.

## Consequences

Benefits: deterministic enforcement, materially fewer Telegram messages, smaller attack surface and explainable bans. Costs: reduced visibility into generic Internet noise; newly supported protocols require production fixtures and exact attribution evidence. Existing state remains readable but legacy weak evidence cannot trigger new bans.

## Links

- .kiro/specs/antidpi-evidence-contraction/requirements.md
