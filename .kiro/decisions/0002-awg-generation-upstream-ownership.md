# 0002. Awg Generation Upstream Ownership

## Status

accepted

## Context

HYDRA manages two AmneziaWG interfaces and several client exports, while wiresock/amneziawg-install owns capability-checked 2.0, 3.0 and 3.1 migration. Reimplementing protocol directives in every renderer risks mismatched HeaderProtectionKey or RandomTrailers values and broken clients.

## Decision

Use upstream non-interactive migration and status commands as the sole generator of AWG generation-specific values. HYDRA persists only desired mode, validates and projects the upstream-generated directive subset to its second interface and compatible exports, and owns the surrounding transaction and rollback.

## Consequences

This preserves one authority for protocol secrets and capability checks. The alternative of manual Hydra generation was rejected because it duplicates upstream behavior and can create incompatible endpoints. Unsupported URI or userspace exports remain unavailable for AWG 3.x until their format and runtime are proved by versioned tests.

## Links

- .kiro/specs/awg-3x-mode-switch/requirements.md
- .kiro/specs/awg-3x-mode-switch/design.md
- <https://github.com/wiresock/amneziawg-install/blob/main/amneziawg-install.sh>
