"""Sing-Box Extended native Calls transport configuration."""
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
    CALL_MODE_MULTI_USER,
    CALL_MODE_P2P,
    DEFAULT_CALL_PORT,
    call_mode,
    multi_user_inbound,
    multi_user_outbound,
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
        hydra_v2_subscription_enabled=True,
        connection_source="none",
        config_defaults=(("mode", CALL_MODE_P2P), ("read_buffer", 32768)),
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
        return self._source.feature_supported()

    def uninstall(self) -> bool:
        return True

    def on_enable(self, state: PluginStateAccess) -> None:
        if call_mode(state) != CALL_MODE_MULTI_USER:
            return
        inbound = multi_user_inbound(state)
        from hydra.utils.firewall import open_udp, port_is_open

        port = int(inbound["listen_port"])
        if not port_is_open("udp", port):
            open_udp(port, "hydra-calls-vk")

    def on_disable(self, state: PluginStateAccess) -> None:
        if call_mode(state) != CALL_MODE_MULTI_USER:
            return
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
        mode = call_mode(state)
        raw_port = desired.config.get("listen_port")
        if mode == CALL_MODE_MULTI_USER:
            port = int(multi_user_inbound(state)["listen_port"])
        elif type(raw_port) is int and 1 <= raw_port <= 65535:
            port = raw_port
        else:
            return None
        from hydra.utils.firewall import port_is_open

        return {"port": port, "was_open": port_is_open("udp", port)}

    def apply(self, state: PluginStateAccess) -> bool:
        desired = state.protocols.get(self.meta.name)
        if desired is None:
            return True
        from hydra.utils.firewall import close_udp, open_udp, port_is_open

        if call_mode(state) == CALL_MODE_MULTI_USER:
            port = int(multi_user_inbound(state)["listen_port"])
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
        supported = self._source.feature_supported()
        mode = call_mode(state) if state is not None else CALL_MODE_P2P
        ready = (
            bool(self._source.load_native_join_links())
            and self._source.multi_user_supported()
            if mode == CALL_MODE_MULTI_USER
            else bool(
                self._source.load_native_join_link()
                and self._source.load_vk_cookies()
            )
        )
        running = bool(enabled and ready and self._source.singbox_running())
        return PluginStatus(
            installed=supported,
            enabled=enabled,
            running=running,
            info={"platform": "vk", "mode": mode, "configured": ready},
        )

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        desired = state.protocols.get(self.meta.name)
        if desired is None or not desired.enabled:
            return ConfigFragment()
        mode = call_mode(state)
        if mode == CALL_MODE_MULTI_USER:
            if not self._source.multi_user_supported():
                raise ValueError("installed core does not support VK Calls multi_user")
            return ConfigFragment(inbounds=[multi_user_inbound(state)])
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

    def generate_client_config(self, user, state: PluginStateAccess) -> str:
        """Return the remote-safe VK Calls joiner used by subscriptions."""
        desired = state.protocols.get(self.meta.name)
        if desired is None or not desired.enabled:
            return ""
        mode = call_mode(state)
        if mode == CALL_MODE_MULTI_USER:
            outbound = multi_user_outbound(
                user,
                state,
                self._source.load_native_join_links(),
            )
            return json.dumps({
                "outbounds": [outbound],
                "route": {"final": outbound["tag"]},
            }, ensure_ascii=False, separators=(",", ":"))
        join_link = self._source.load_native_join_link()
        if not join_link:
            raise ValueError("native VK call join link is not configured")
        read_buffer = int(desired.config.get("read_buffer", 32768))
        if not 4096 <= read_buffer <= 4 * 1024 * 1024:
            raise ValueError(
                "Calls read_buffer must be between 4096 and 4194304",
            )
        return json.dumps({
            "outbounds": [{
                "type": "call",
                "tag": "call-vk-out",
                "platform": "vk",
                "read_buffer": read_buffer,
                "join_link": join_link,
            }],
            "route": {"final": "call-vk-out"},
        }, ensure_ascii=False, separators=(",", ":"))

    def healthcheck_for_state(self, state: PluginStateAccess) -> HealthResult:
        desired = state.protocols.get(self.meta.name)
        if desired is None or not desired.enabled:
            return HealthResult(True)
        mode = call_mode(state)
        if mode == CALL_MODE_MULTI_USER:
            checks = {
                "feature_supported": self._source.multi_user_supported(),
                "join_links_ready": bool(self._source.load_native_join_links()),
                "singbox_running": self._source.singbox_running(),
            }
            healthy = all(checks.values())
            return HealthResult(
                healthy,
                "" if healthy else "native VK Calls multi-user prerequisites are not ready",
                "ok" if healthy else "error",
                checks,
            )
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
