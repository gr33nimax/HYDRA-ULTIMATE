# Architecture audit — stage 13

## Boundary status

- Privileged commands are routed through `hydra.core.host.HOST` and the bounded
  command runner in `hydra.utils.commands`; the regression guard in
  `tests/test_host_boundary_guard.py` prevents new direct `subprocess` calls.
- Plugin lifecycle changes go through the orchestrator transaction boundary;
  `tests/test_lifecycle_boundary_guard.py` rejects manager-level lifecycle
  calls.
- CLI and the supported TUI flows receive `ApplicationService` explicitly.
- State writes use the atomic migration/storage path and are covered by
  failure tests.

## Compatibility paths intentionally retained

The following are not dead code and must not be removed without a migration:

- `hydra.plugins.base.lifecycle_result` and `health_result` adapt third-party
  legacy plugins.
- `hydra.plugins.config.legacy_config_fragment` accepts persisted/plugin dicts
  from older releases.
- `ApplicationService` and menu functions keep optional fallback factories for
  external callers that still use the old function signatures.
- Protocol-specific legacy config migrations preserve existing installations.

## Final audit result

No unreviewed direct host-command bypass or duplicate lifecycle implementation
remains in production code. Telegram remains explicitly out of scope until its
adapter contract and smoke tests are implemented.
