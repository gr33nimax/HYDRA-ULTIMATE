"""Stable WarpPlugin facade over cohesive WARP implementation modules."""
from __future__ import annotations

import re
import socket
from pathlib import Path
from hydra.core.host import HOST
from hydra.core.state_models import AppState, PluginState
from hydra.plugins.base import (
    BasePlugin, ConfigFragment, PluginCategory, PluginMeta, PluginStatus,
)
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.warp import configuration, observation, parsing, rules, runtime
from hydra.plugins.warp.constants import (
    DEFAULT_WARP_DOMAINS,
    EXTERNAL_LISTS,
    WARP_EXTERNAL_CACHE,
    WARP_INTERFACE,
    WARP_PROFILES_DIR,
    WGCF_ACCOUNT,
    WGCF_BIN,
    WGCF_PROFILE,
)
from hydra.plugins.warp.maintenance import (
    WARP_BACKUP_RESOURCES, WARP_MAINTENANCE_TASKS, WarpMaintenanceMixin,
)
RUSSIA_TLD_SUFFIXES = [".su", ".ru", ".рф", ".xn--p1ai"]

class WarpPlugin(WarpMaintenanceMixin, BasePlugin):
    meta = PluginMeta(
        name="warp",
        description="Cloudflare WARP: выборочное туннелирование через сеть Cloudflare",
        category=PluginCategory.ENHANCEMENT,
        version="2.1.0",
        actions=(
            "delete_local_profile",
            "remove_local_profile",
            "recreate_local_profile",
            "restore_local_profile",
            "snapshot_local_profile",
            "update_external_rules",
        ),
        queries=(
            "external_rules_update_due",
            "external_sources",
            "manager_observation",
        ),
        maintenance_tasks=WARP_MAINTENANCE_TASKS,
        backup_resources=WARP_BACKUP_RESOURCES,
    )
    @staticmethod
    def external_sources() -> dict[str, dict[str, str]]:
        return observation.external_sources(EXTERNAL_LISTS)

    @staticmethod
    def manager_observation() -> dict[str, object]:
        return observation.manager_observation(WARP_PROFILES_DIR, WGCF_PROFILE)

    @staticmethod
    def delete_local_profile(*, name: str) -> bool:
        return observation.delete_local_profile(WARP_PROFILES_DIR, name=name)
    def install(self) -> bool:
        existing = WGCF_PROFILE.exists() and WGCF_BIN.exists()
        installed = runtime.install(
            host=HOST, binary=WGCF_BIN, profile=WGCF_PROFILE,
            account=WGCF_ACCOUNT,
        )
        if not installed:
            return False
        lists_ok, message = self.preload_external_rules()
        if not lists_ok:
            print(f"  Не удалось заранее загрузить списки WARP: {message}")
            if not existing:
                with Path("/var/log/hydra/warp_install.log").open("a", encoding="utf-8") as log:
                    log.write(f"External lists preload failed: {message}\n")
        return lists_ok
    def uninstall(self) -> bool:
        return runtime.uninstall(
            host=HOST, binary=WGCF_BIN, profile=WGCF_PROFILE,
            account=WGCF_ACCOUNT, cache=WARP_EXTERNAL_CACHE,
        )

    @staticmethod
    def remove_local_profile() -> None:
        runtime.remove_local_profile(WGCF_PROFILE, WGCF_ACCOUNT)
    @staticmethod
    def snapshot_local_profile() -> tuple[bytes | None, bytes | None]:
        return runtime.snapshot_local_profile(WGCF_PROFILE, WGCF_ACCOUNT)
    @staticmethod
    def restore_local_profile(snapshot: tuple[bytes | None, bytes | None]) -> None:
        runtime.restore_local_profile(
            snapshot, profile=WGCF_PROFILE, account=WGCF_ACCOUNT, host=HOST,
        )

    def recreate_local_profile(self) -> bool:
        snapshot = self.snapshot_local_profile()
        self.remove_local_profile()
        if self.install():
            return True
        self.remove_local_profile()
        self.restore_local_profile(snapshot)
        return False

    def _load_warp_config(self) -> dict | None:
        return parsing.load_warp_config(
            WGCF_PROFILE, parse_config=self._parse_wg_conf,
            validate_ip=self._is_ip_or_cidr,
        )

    def _parse_wg_conf(self, text: str) -> dict | None:
        return parsing.parse_wg_conf(text)
    @staticmethod
    def _parse_endpoint(raw_endpoint: str) -> tuple[str, int] | None:
        return parsing.parse_endpoint(raw_endpoint)

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        return configuration.configure_warp(
            state,
            profiles_dir=WARP_PROFILES_DIR,
            external_cache=WARP_EXTERNAL_CACHE,
            default_domains=DEFAULT_WARP_DOMAINS,
            russia_suffixes=RUSSIA_TLD_SUFFIXES,
            parse_config=self._parse_wg_conf,
            parse_endpoint=self._parse_endpoint,
            validate_domain=self._is_valid_domain,
            validate_ip=self._is_ip_or_cidr,
            resolve_host=socket.gethostbyname,
            load_default_profile=self._load_warp_config,
        )

    def status(self, state: PluginStateAccess | None = None) -> PluginStatus:
        from hydra.core.singbox import is_running
        return runtime.status(
            state, profile=WGCF_PROFILE, profiles_dir=WARP_PROFILES_DIR,
            singbox_running=is_running,
        )

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        return {}

    def on_enable(self, state: PluginStateAccess) -> None:
        pass

    def on_disable(self, state: PluginStateAccess) -> None:
        pass

    @staticmethod
    def _is_ip_or_cidr(token: str) -> bool:
        return parsing.is_ip_or_cidr(token)

    @staticmethod
    def _is_valid_domain(token: str) -> bool:
        if not token or len(token) > 253:
            return False
        leading_dot = token.startswith(".")
        try:
            body = token.removeprefix(".").encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return False
        normalized = f".{body}" if leading_dot else body
        suffix = r"\.[a-zA-Z0-9-]{2,63}"
        domain = r"\.?[a-zA-Z0-9][-a-zA-Z0-9._]*\.[a-zA-Z0-9-]{2,63}"
        return re.fullmatch(suffix, normalized) is not None or (
            re.fullmatch(domain, normalized) is not None
        )

    def preload_external_rules(self) -> tuple[bool, str]:
        state = AppState(protocols={"warp": PluginState(config={
            "list_targets": {f"ext:{key}": "warp" for key in EXTERNAL_LISTS},
        })})
        return self.update_external_rules(state)

    def update_external_rules(
        self, state: PluginStateAccess,
    ) -> tuple[bool, str]:
        return rules.update_external_rules(
            state, catalog=EXTERNAL_LISTS, cache=WARP_EXTERNAL_CACHE, host=HOST,
            validate_ip=self._is_ip_or_cidr,
            validate_domain=self._is_valid_domain,
        )
