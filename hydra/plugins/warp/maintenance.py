"""Declarative background-maintenance adapter for the WARP plugin."""

from __future__ import annotations

from hydra.plugins.base import MaintenanceTask
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.warp import observation, rules
from hydra.plugins.warp.constants import WARP_EXTERNAL_CACHE


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


class WarpMaintenanceMixin:
    """Expose scheduler queries while keeping the plugin facade compact."""

    @staticmethod
    def external_rules_update_due(
        *,
        state: PluginStateAccess | None = None,
        forced: bool = False,
    ) -> bool:
        enabled_keys: tuple[str, ...] = ()
        if state is not None:
            enabled_keys = tuple(rules.enabled_external_keys(state))
        return observation.external_rules_update_due(
            WARP_EXTERNAL_CACHE,
            enabled_keys=enabled_keys,
            forced=forced,
        )


__all__ = [
    "WARP_MAINTENANCE_TASKS",
    "WarpMaintenanceMixin",
]
