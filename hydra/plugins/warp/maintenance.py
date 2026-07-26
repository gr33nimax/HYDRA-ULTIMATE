"""Declarative background-maintenance adapter for the WARP plugin."""
from __future__ import annotations

from hydra.contracts import BackupResource
from hydra.plugins.base import MaintenanceTask
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.warp import observation
from hydra.plugins.warp.constants import (
    WARP_EXTERNAL_CACHE,
    WGCF_ACCOUNT,
    WGCF_PROFILE,
)


WARP_MAINTENANCE_TASKS = (
    MaintenanceTask(
        action="update_external_rules",
        due_query="external_rules_update_due",
        enabled_flag="sync_warp_enabled",
        title="🔄 Автообновление списков WARP",
        description="Раз в 24 часа скачивать свежие правила WARP",
        apply_on_success=True,
    ),
)
WARP_BACKUP_RESOURCES = (
    BackupResource(str(WGCF_ACCOUNT), "file"),
    BackupResource(str(WGCF_PROFILE), "file"),
)


class WarpMaintenanceMixin:
    """Expose scheduler queries while keeping the plugin facade compact."""

    @staticmethod
    def external_rules_update_due(
        *,
        state: PluginStateAccess | None = None,
        forced: bool = False,
    ) -> bool:
        del state
        return observation.external_rules_update_due(
            WARP_EXTERNAL_CACHE,
            forced=forced,
        )


__all__ = [
    "WARP_BACKUP_RESOURCES",
    "WARP_MAINTENANCE_TASKS",
    "WarpMaintenanceMixin",
]
