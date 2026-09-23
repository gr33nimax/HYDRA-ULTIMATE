"""Stable WarpPlugin facade over cohesive WARP implementation modules."""

from __future__ import annotations

import contextlib
import socket
from hydra.core.host import HOST
from hydra.core.state_models import AppState, PluginState
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
            "remove_legacy_install",
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
        return observation.manager_observation(
            WARP_PROFILES_DIR,
            LEGACY_WGCF_PATHS,
        )

    @staticmethod
    def delete_local_profile(*, name: str) -> bool:
        return observation.delete_local_profile(WARP_PROFILES_DIR, name=name)

    @staticmethod
    def remove_legacy_install() -> list[str]:
        """Drop what the retired wgcf installer left on this host."""
        return observation.remove_legacy_install(LEGACY_WGCF_PATHS)

    def install(self) -> bool:
        """Nothing to install: the core registers the WARP device itself."""
        lists_ok, message = self.preload_external_rules()
        if not lists_ok:
            print(f"  Не удалось заранее загрузить списки WARP: {message}")
        return True

    def uninstall(self) -> bool:
        with contextlib.suppress(OSError):
            WARP_EXTERNAL_CACHE.unlink(missing_ok=True)
        observation.remove_legacy_install(LEGACY_WGCF_PATHS)
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

        enabled = False
        if state is not None:
            plugin_state = state.protocols.get("warp")
            if plugin_state:
                enabled = plugin_state.enabled
        return PluginStatus(
            installed=True,
            enabled=enabled,
            running=enabled and is_running(),
        )

    def preload_external_rules(self) -> tuple[bool, str]:
        state = AppState(
            protocols={
                "warp": PluginState(
                    config={
                        "list_targets": {f"ext:{key}": "warp" for key in EXTERNAL_LISTS},
                    }
                )
            }
        )
        return self.update_external_rules(state)

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
