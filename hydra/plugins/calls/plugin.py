"""Sing-Box Extended native Calls transport configuration."""
from __future__ import annotations

from hydra.contracts import (
    BackupResource,
    CallConfigSource,
    ConfigFragment,
    UnavailableCallConfigSource,
)
from hydra.plugins.base import (
    BasePlugin,
    HealthResult,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.context import PluginStateAccess


class CallsPlugin(BasePlugin):
    """Contribute one fixed VK call inbound to the shared Sing-Box runtime."""

    meta = PluginMeta(
        name="calls",
        display_name="Calls · VK",
        description="Экспериментальный TCP/UDP-прокси через VK Calls",
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
        central_apply=True,
        required_commands=("sing-box",),
        subscription_enabled=False,
        connection_source="none",
        config_defaults=(("read_buffer", 32768),),
        backup_resources=(
            BackupResource("/var/lib/hydra/calls/vk", "tree", owner="calls"),
        ),
    )

    def __init__(self, source: CallConfigSource | None = None) -> None:
        self._source = source or UnavailableCallConfigSource()

    def install(self) -> bool:
        return self._source.feature_supported()

    def uninstall(self) -> bool:
        return True

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        desired = state.protocols.get(self.meta.name) if state is not None else None
        enabled = bool(desired and desired.enabled)
        supported = self._source.feature_supported()
        ready = bool(
            self._source.load_native_join_link()
            and self._source.load_vk_cookies()
        )
        running = bool(enabled and ready and self._source.singbox_running())
        return PluginStatus(
            installed=supported,
            enabled=enabled,
            running=running,
            info={"platform": "vk", "configured": ready},
        )

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        desired = state.protocols.get(self.meta.name)
        if desired is None or not desired.enabled:
            return ConfigFragment()
        cookies = self._source.load_vk_cookies()
        join_link = self._source.load_native_join_link()
        if not cookies:
            raise ValueError("VK cookies are not configured")
        if not join_link:
            raise ValueError("native VK call join link is not configured")
        read_buffer = int(desired.config.get("read_buffer", 32768))
        if not 4096 <= read_buffer <= 4 * 1024 * 1024:
            raise ValueError("Calls read_buffer must be between 4096 and 4194304")
        return ConfigFragment(
            inbounds=[
                {
                    "type": "call",
                    "tag": "calls-vk-in",
                    "platform": "vk",
                    "read_buffer": read_buffer,
                    "cookies": cookies,
                    "join_link": join_link,
                },
            ],
        )

    def healthcheck_for_state(self, state: PluginStateAccess) -> HealthResult:
        desired = state.protocols.get(self.meta.name)
        if desired is None or not desired.enabled:
            return HealthResult(True)
        checks = {
            "feature_supported": self._source.feature_supported(),
            "cookies_ready": bool(self._source.load_vk_cookies()),
            "join_link_ready": bool(self._source.load_native_join_link()),
            "singbox_running": self._source.singbox_running(),
        }
        healthy = all(checks.values())
        return HealthResult(
            healthy,
            "" if healthy else "native VK Calls prerequisites are not ready",
            "ok" if healthy else "error",
            checks,
        )


__all__ = ["CallsPlugin"]
