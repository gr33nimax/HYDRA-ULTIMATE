"""Dependency-neutral HYDRA removal policy and host mechanics.

Plugin inventory and plugin-specific cleanup belong to the application
service layer.  This module deliberately knows only the ordered plugin names
included in a plan and any failures already collected by its caller.
"""
from __future__ import annotations

import shutil
from collections.abc import Iterable
from pathlib import Path

from hydra.core.host import HOST
from hydra.core.state_models import AppState


SYSTEM_SERVICES = (
    "hydra-sub.service",
    "hydra-traffic-daemon.service",
    "hydra-sync-agent.service",
    "hydra-sync-agent.timer",
    "hydra-tg-admin.service",
    "hydra-antidpi.service",
    "hydra-honeypot.service",
    "hydra-caddy-source.service",
    "hydra-source-relay.service",
    "hydra-udp-source-relay.service",
    "caddy-l4.service",
    "caddy-naive.service",
    "sing-box.service",
    "telemt.service",
    "wdtt.service",
)
PROGRAM_PATHS = (
    Path("/usr/local/bin/hydra"),
    Path("/usr/local/bin/sing-box"),
    Path("/usr/local/bin/caddy-l4"),
    Path("/opt/hydra"),
    Path("/opt/HYDRA-ULTIMATE"),
)
DATA_PATHS = (
    Path("/etc/hydra"),
    Path("/etc/sing-box"),
    Path("/etc/caddy-l4"),
    Path("/var/lib/hydra"),
    Path("/var/log/hydra"),
    Path("/var/log/caddy-l4"),
)
CRON_PATHS = (
    Path("/etc/cron.d/hydra-traffic"),
    Path("/etc/cron.d/telemt-stats"),
)


def uninstall_plan(
    state: AppState,
    *,
    keep_data: bool = False,
    plugin_names: Iterable[str] = (),
) -> dict:
    """Build a serializable plan from application-supplied plugin inventory."""
    del state  # Retained for compatibility with the released public signature.
    paths = [*PROGRAM_PATHS, *CRON_PATHS]
    if not keep_data:
        paths.extend(DATA_PATHS)
    return {
        "plugins": list(plugin_names),
        "services": list(SYSTEM_SERVICES),
        "paths": [str(path) for path in paths],
        "keep_data": keep_data,
    }


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)


def uninstall_hydra(
    state: AppState,
    *,
    confirmed: bool,
    dry_run: bool = False,
    keep_data: bool = False,
    plugin_names: Iterable[str] = (),
    initial_failures: Iterable[str] = (),
) -> dict:
    """Remove HYDRA host resources after application-level cleanup.

    ``plugin_names`` and ``initial_failures`` are dependency-neutral extension
    points for outer application orchestration. Existing callers may continue
    using the released arguments; management adapters should use their
    configured application boundary so plugin cleanup is composed.
    """
    plan = uninstall_plan(
        state,
        keep_data=keep_data,
        plugin_names=plugin_names,
    )
    if dry_run:
        return {"ok": True, "dry_run": True, **plan}
    if not confirmed:
        raise ValueError(
            "uninstall requires --yes; use --dry-run to inspect the plan",
        )

    failures = list(initial_failures)
    for service in SYSTEM_SERVICES:
        for action in ("stop", "disable", "reset-failed"):
            HOST.run(["systemctl", action, service], capture_output=True)
        unit = HOST.paths.systemd_dir / service
        try:
            unit.unlink(missing_ok=True)
        except OSError as exc:
            failures.append(f"{unit}: {exc}")
    HOST.run(["systemctl", "daemon-reload"], capture_output=True)

    try:
        from hydra.core.network_tuning import rollback_network_tuning

        rollback_network_tuning()
    except Exception as exc:
        failures.append(f"network tuning: {exc}")

    for raw_path in plan["paths"]:
        path = Path(raw_path)
        try:
            _remove_path(path)
        except OSError as exc:
            failures.append(f"{path}: {exc}")

    return {
        "ok": not failures,
        "dry_run": False,
        "removed": plan,
        "failures": failures,
    }


__all__ = [
    "CRON_PATHS",
    "DATA_PATHS",
    "PROGRAM_PATHS",
    "SYSTEM_SERVICES",
    "uninstall_hydra",
    "uninstall_plan",
]
