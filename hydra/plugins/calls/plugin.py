"""Hydracore native VK-parasite Calls transport configuration."""
from __future__ import annotations

import json

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
from hydra.plugins.calls.configuration import (
    CALL_MODE_VK_PARASITE,
    DEFAULT_CALL_PORT,
    DEFAULT_ROOM_COUNT,
    call_mode,
    vk_parasite_inbound,
    vk_parasite_outbound,
)
from hydra.plugins.context import PluginStateAccess


class CallsPlugin(BasePlugin):
    """Contribute the authenticated VK Calls listener to Hydracore."""

    meta = PluginMeta(
        name="calls",
        display_name="Hydra VK Tunnel",
        description="Экспериментальный TCP/UDP-прокси через VK Calls",
        subscription_profile_name="Обход БС",
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
        central_apply=True,
        required_commands=("sing-box",),
        subscription_enabled=False,
        hydra_v2_subscription_enabled=True,
        connection_source="tracked",
        config_defaults=(
            ("mode", CALL_MODE_VK_PARASITE),
            ("room_count", DEFAULT_ROOM_COUNT),
            ("listen_port", DEFAULT_CALL_PORT),
        ),
        backup_resources=(
            BackupResource("/var/lib/hydra/calls/vk", "tree", owner="calls"),
            BackupResource(
                "/etc/systemd/system/hydra-headless-creator-vk-calls@.service",
                "file",
                owner="calls",
            ),
        ),
    )

    def __init__(self, source: CallConfigSource | None = None) -> None:
        self._source = source or UnavailableCallConfigSource()

    def install(self) -> bool:
        return self._source.vk_parasite_supported()

    def uninstall(self) -> bool:
        return True

    def on_enable(self, state: PluginStateAccess) -> None:
        call_mode(state)
        inbound = vk_parasite_inbound(state)
        from hydra.utils.firewall import open_udp, port_is_open

        port = int(inbound["listen_port"])
        if not port_is_open("udp", port):
            open_udp(port, "hydra-calls-vk")

    def on_disable(self, state: PluginStateAccess) -> None:
        call_mode(state)
        desired = state.protocols.get(self.meta.name)
        if desired is None:
            return
        from hydra.utils.firewall import close_udp

        close_udp(
            int(desired.config.get("listen_port", DEFAULT_CALL_PORT)),
            "hydra-calls-vk",
        )

    def snapshot(self, state: PluginStateAccess):
        desired = state.protocols.get(self.meta.name)
        if desired is None:
            return None
        call_mode(state)
        port = int(vk_parasite_inbound(state)["listen_port"])
        from hydra.utils.firewall import port_is_open

        return {"port": port, "was_open": port_is_open("udp", port)}

    def apply(self, state: PluginStateAccess) -> bool:
        desired = state.protocols.get(self.meta.name)
        if desired is None:
            return True
        from hydra.utils.firewall import close_udp, open_udp, port_is_open

        call_mode(state)
        if desired.enabled:
            port = int(vk_parasite_inbound(state)["listen_port"])
            if not port_is_open("udp", port):
                open_udp(port, "hydra-calls-vk")
        else:
            raw_port = desired.config.get("listen_port")
            if type(raw_port) is int and 1 <= raw_port <= 65535:
                close_udp(raw_port, "hydra-calls-vk")
        return True

    def rollback(self, state: PluginStateAccess, snapshot) -> bool:
        del state
        if not isinstance(snapshot, dict):
            return True
        port = snapshot.get("port")
        was_open = snapshot.get("was_open")
        if type(port) is not int or type(was_open) is not bool:
            return False
        from hydra.utils.firewall import close_udp, open_udp, port_is_open

        is_open = port_is_open("udp", port)
        if was_open and not is_open:
            open_udp(port, "hydra-calls-vk")
        elif not was_open and is_open:
            close_udp(port, "hydra-calls-vk")
        return True

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        desired = state.protocols.get(self.meta.name) if state is not None else None
        enabled = bool(desired and desired.enabled)
        supported = self._source.vk_parasite_supported()
        mode = call_mode(state) if state is not None else CALL_MODE_VK_PARASITE
        ready = (
            bool(self._source.load_native_join_links())
            and supported
        )
        running = bool(enabled and ready and self._source.singbox_running())
        return PluginStatus(
            installed=supported,
            enabled=enabled,
            running=running,
            info={
                "platform": "vk",
                "mode": mode,
                "transport": "four_lane_kcp_v9",
                "lanes": 4,
                "configured": ready,
            },
        )

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        desired = state.protocols.get(self.meta.name)
        if desired is None or not desired.enabled:
            return ConfigFragment()
        call_mode(state)
        if not self._source.vk_parasite_supported():
            raise ValueError("installed core does not support VK Calls parasite wire v9")
        return ConfigFragment(inbounds=[vk_parasite_inbound(state)])

    def generate_client_config(self, user, state: PluginStateAccess) -> str:
        """Return the remote-safe VK Calls joiner used by subscriptions."""
        desired = state.protocols.get(self.meta.name)
        if desired is None or not desired.enabled:
            return ""
        call_mode(state)
        if not self._source.vk_parasite_supported():
            raise ValueError("installed core does not support VK Calls parasite wire v9")
        outbound = vk_parasite_outbound(
            user,
            state,
            self._source.load_native_join_links(),
        )
        return json.dumps({
            "outbounds": [outbound],
            "route": {"final": outbound["tag"]},
        }, ensure_ascii=False, separators=(",", ":"))

    def healthcheck_for_state(self, state: PluginStateAccess) -> HealthResult:
        desired = state.protocols.get(self.meta.name)
        if desired is None or not desired.enabled:
            return HealthResult(True)
        call_mode(state)
        checks = {
            "feature_supported": self._source.vk_parasite_supported(),
            "join_links_ready": bool(self._source.load_native_join_links()),
            "singbox_running": self._source.singbox_running(),
        }
        healthy = all(checks.values())
        return HealthResult(
            healthy,
            "" if healthy else "native VK Calls four-lane prerequisites are not ready",
            "ok" if healthy else "error",
            checks,
        )


__all__ = ["CallsPlugin"]
