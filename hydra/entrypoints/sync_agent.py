"""Executable adapter for one background synchronization cycle."""
from __future__ import annotations

import sys

from hydra.bootstrap import production_application
from hydra.services.sync_agent import log_event, run_sync
from hydra.services.sync_ports import default_sync_operations


def main() -> int:
    application = production_application()
    try:
        ok, message = run_sync(
            operations=default_sync_operations(
                protocols=application.protocols,
                plugin_actions=application.plugin_actions,
                apply_config=application.apply,
                check_traffic_limits=application.traffic.check_limits,
            ),
        )
    except Exception as exc:
        log_event(f"Sync failed: {exc}")
        print(f"Sync agent error: {exc}", file=sys.stderr)
        return 1
    if not ok:
        print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
