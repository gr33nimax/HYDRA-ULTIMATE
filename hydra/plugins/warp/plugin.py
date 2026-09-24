"""Stable WarpPlugin facade over cohesive WARP implementation modules."""

from __future__ import annotations

import socket
from hydra.core.host import HOST
from hydra.plugins.base import (
    BasePlugin,
    ConfigFragment,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.warp import (
    catalog,
    configuration,
    observation,
    parsing,
    routing_catalog,
    rules,
)
from hydra.plugins.warp.constants import (
    DEFAULT_WARP_DOMAINS,
    EXTERNAL_LISTS,
    LEGACY_WGCF_PATHS,
    RUSSIA_TLD_SUFFIXES,
    WARP_CATALOG_CACHE,
    WARP_EXTERNAL_CACHE,
    WARP_PROFILES_DIR,
)
from hydra.plugins.warp.maintenance import WARP_MAINTENANCE_TASKS, WarpMaintenanceMixin


class WarpPlugin(WarpMaintenanceMixin, BasePlugin):
    meta = PluginMeta(
        name="warp",
        description=("Cloudflare WARP (MASQUE): выборочное туннелирование через сеть Cloudflare"),
        category=PluginCategory.ENHANCEMENT,
        version="3.0.0",
        actions=(
            "delete_local_profile",
            "update_external_rules",
        ),
        queries=(
            "external_rules_update_due",
            "external_sources",
            "manager_observation",
            "routing_catalog",
        ),
        maintenance_tasks=WARP_MAINTENANCE_TASKS,
    )

    @staticmethod
    def external_sources() -> dict[str, dict[str, str]]:
        """Return the cached rule catalogue, or its builtin copy."""
        return observation.external_sources(
            catalog.load_sources(WARP_CATALOG_CACHE),
        )

    @staticmethod
    def routing_catalog(
        *,
        list_targets: dict | None = None,
        local_lists: dict | None = None,
    ) -> list[dict]:
        """Group the catalogue into menu categories carrying their destination."""
        return routing_catalog.category_menu(
            catalog.load_sources(WARP_CATALOG_CACHE),
            list_targets,
            local_lists,
        )

    @staticmethod
    def manager_observation() -> dict[str, object]:
        return observation.manager_observation(WARP_PROFILES_DIR)

    @staticmethod
    def delete_local_profile(*, name: str) -> bool:
        return observation.delete_local_profile(WARP_PROFILES_DIR, name=name)

    def install(self) -> bool:
        """Prepare the transport: the core owns the device, HYDRA owns the lists."""
        print("  WARP готов к работе: устройство Cloudflare регистрирует ядро")
        lists_ok, message = self.preload_external_rules()
        if not lists_ok:
            print(f"  Не удалось обновить каталог WARP: {message}")
        return True

    def uninstall(self) -> bool:
        # Retain the rule cache: reinstall() calls uninstall() before restoring
        # selected routes, and must not silently turn those routes into direct.
        removed = observation.remove_legacy_install(LEGACY_WGCF_PATHS)
        # Nothing else is touched on purpose: the core keeps terminating WARP, so
        # removing the plugin must not take the device away from it.
        if removed:
            print("  Остатки прежнего установщика wgcf удалены")
        else:
            print("  Прежней схемы на хосте нет — удалять нечего")
        return True

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        return configuration.configure_warp(
            state,
            profiles_dir=WARP_PROFILES_DIR,
            external_cache=WARP_EXTERNAL_CACHE,
            default_domains=DEFAULT_WARP_DOMAINS,
            russia_suffixes=RUSSIA_TLD_SUFFIXES,
            parse_config=parsing.parse_wg_conf,
            parse_endpoint=parsing.parse_endpoint,
            validate_domain=parsing.is_valid_domain,
            validate_ip=parsing.is_ip_or_cidr,
            resolve_host=socket.gethostbyname,
        )

    def status(self, state: PluginStateAccess | None = None) -> PluginStatus:
        from hydra.core.singbox import is_running

        installed = False
        enabled = False
        if state is not None:
            plugin_state = state.protocols.get("warp")
            if plugin_state:
                installed = plugin_state.installed
                enabled = plugin_state.enabled
        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=enabled and is_running(),
        )

    def preload_external_rules(self) -> tuple[bool, str]:
        """Refresh the catalogue without deleting cached rules selected in state."""
        if not catalog.refresh_due(WARP_CATALOG_CACHE):
            return True, "Каталог списков актуален"
        return catalog.refresh_sources(WARP_CATALOG_CACHE, host=HOST)

    def update_external_rules(
        self,
        state: PluginStateAccess,
    ) -> tuple[bool, str]:
        note = ""
        if catalog.refresh_due(WARP_CATALOG_CACHE):
            refreshed, message = catalog.refresh_sources(
                WARP_CATALOG_CACHE,
                host=HOST,
            )
            if not refreshed:
                note = f"{message} "
        ok, message = rules.update_external_rules(
            state,
            catalog=catalog.load_sources(WARP_CATALOG_CACHE),
            cache=WARP_EXTERNAL_CACHE,
            host=HOST,
            validate_ip=parsing.is_ip_or_cidr,
            validate_domain=parsing.is_valid_domain,
        )
        return ok, note + message
