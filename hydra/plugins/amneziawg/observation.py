"""Read-only status, traffic, and connected-peer queries for AmneziaWG."""
from __future__ import annotations

import time

from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess

from .constants import AWG_INTERFACE, AWG_INTERFACE_1


class AwgObservationMixin:
    """Observe host/runtime facts without mutating desired or runtime state."""

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        runtime_installed = self._installed()
        installed = False
        enabled = False
        if state is not None:
            protocol = state.protocols.get("amneziawg")
            if protocol:
                installed = bool(protocol.installed and runtime_installed)
                enabled = bool(protocol.enabled and installed)
        port = 0
        if installed:
            try:
                port = self._current_port()
            except Exception:
                pass
        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=(
                enabled
                and (
                    self._is_up()
                    or self._is_up_iface(AWG_INTERFACE_1)
                )
            ),
            port=port,
        )

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        """Return aggregate transfer bytes keyed by user email."""
        if not self._installed():
            return {}
        public_to_email = {}
        for user in state.users:
            if user.blocked:
                continue
            desktop = user.credentials.get("amneziawg", {})
            mobile = user.credentials.get("amneziawg_mobile", {})
            if desktop.get("public_key"):
                public_to_email[desktop["public_key"]] = user.email
            if mobile.get("public_key"):
                public_to_email[mobile["public_key"]] = user.email

        result: dict[str, int] = {}
        for interface in self._active_interfaces():
            transfer = self._awg("show", interface, "transfer")
            if transfer.returncode != 0:
                continue
            for line in transfer.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                public_key, received, sent = parts[:3]
                email = public_to_email.get(public_key)
                if email:
                    result[email] = (
                        result.get(email, 0) + int(received) + int(sent)
                    )
        return result

    def connected_clients(
        self,
        state: PluginStateAccess | None = None,
    ) -> list[dict]:
        """Return recently active peers grouped across both profiles."""
        if not self._installed():
            return []
        peer_map: dict[str, str | tuple[str, str]] = dict(self._peer_map)
        if state:
            peer_map = self._peer_map_from_state(state)

        now = int(time.time())
        grouped: dict[str, dict] = {}
        for interface in self._active_interfaces():
            dump = self._awg("show", interface, "dump")
            if dump.returncode != 0:
                continue
            for line in dump.stdout.strip().splitlines()[1:]:
                self._merge_active_peer(
                    grouped,
                    peer_map,
                    interface,
                    line,
                    now,
                )
        return list(grouped.values())

    def _active_interfaces(self) -> list[str]:
        interfaces = [AWG_INTERFACE]
        if self._is_up_iface(AWG_INTERFACE_1):
            interfaces.append(AWG_INTERFACE_1)
        return interfaces

    @staticmethod
    def _peer_map_from_state(
        state: PluginStateAccess,
    ) -> dict[str, str | tuple[str, str]]:
        peer_map: dict[str, str | tuple[str, str]] = {}
        for user in state.users:
            desktop = user.credentials.get("amneziawg", {})
            mobile = user.credentials.get("amneziawg_mobile", {})
            if desktop.get("public_key"):
                peer_map[desktop["public_key"]] = user.email
            if mobile.get("public_key"):
                peer_map[mobile["public_key"]] = user.email
        return peer_map

    @staticmethod
    def _merge_active_peer(
        grouped: dict[str, dict],
        peer_map: dict[str, str | tuple[str, str]],
        interface: str,
        line: str,
        now: int,
    ) -> None:
        parts = line.split("\t")
        if len(parts) < 8:
            return
        public_key = parts[0]
        handshake = int(parts[4]) if parts[4].isdigit() else 0
        email = peer_map.get(public_key, "?")
        if isinstance(email, tuple):
            email = email[0]
        if email == "?" or handshake <= 0 or now - handshake > 180:
            return

        item = grouped.setdefault(
            email,
            {
                "email": email,
                "profiles": [],
                "endpoint": parts[2],
                "last_handshake": handshake,
                "online": True,
                "rx": 0,
                "tx": 0,
                "traffic_scope": "interface",
            },
        )
        item["profiles"].append(
            "Mobile" if interface == AWG_INTERFACE_1 else "Desktop"
        )
        item["last_handshake"] = max(item["last_handshake"], handshake)
        item["rx"] += int(parts[5]) if parts[5].isdigit() else 0
        item["tx"] += int(parts[6]) if parts[6].isdigit() else 0
