"""Pure desired-state rendering and network selection for AmneziaWG.

Everything here is derived from desired state: the core serves the tunnel, so there is no
interface file to read, reconcile or rewrite.
"""

from __future__ import annotations

import ipaddress
from typing import Any, TYPE_CHECKING

from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess

from .constants import (
    DEFAULT_NETWORK,
    DEFAULT_PORT,
    DEFAULT_PORT_1,
    KNOWN_SUBNETS,
    PREFERRED_SUBNETS,
)


def _profile_name(profile_name: str, default: int) -> int:
    return DEFAULT_PORT_1 if profile_name == "mobile" else default


class AwgConfigurationMixin:
    """Render server configs without touching host runtime or desired state."""

    if TYPE_CHECKING:

        def __getattr__(self, name: str) -> Any:
            """Static dependency seam for configuration rendering."""
            ...

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        """One endpoint per enabled profile; the core owns the whole traffic path."""
        return ConfigFragment(endpoints=self.server_endpoints(state))

    @staticmethod
    def _profile_config(
        state: PluginStateAccess,
        profile_name: str,
    ) -> dict | None:
        protocol = state.protocols.get("amneziawg")
        if protocol is None:
            return None
        profiles = protocol.config.get("profiles")
        if not isinstance(profiles, dict):
            return None
        profile = profiles.get(profile_name)
        return profile if isinstance(profile, dict) else None

    def _network_for_profile(
        self,
        state: PluginStateAccess,
        profile_name: str,
        default_network: str,
    ) -> tuple[str, str, str]:
        """Return the profile's base, server octet and network, all from desired state."""
        network = None
        profile = self._profile_config(state, profile_name)
        if profile is not None:
            network = self._normalize_profile_network(profile.get("network"))
        if not network:
            protocol = state.protocols.get("amneziawg")
            if profile_name == "desktop" and protocol is not None:
                network = self._normalize_profile_network(protocol.config.get("network"))
        if not network:
            network = default_network

        base = network.rsplit(".", 1)[0]
        server_octet = "1"
        if profile is not None:
            address = str(profile.get("address") or "").strip()
            match = ipaddress.ip_interface(address).ip if _is_address(address) else None
            if match is not None and ".".join(str(match).split(".")[:3]) == base:
                server_octet = str(match).split(".")[3]
        return base, server_octet, network

    def _profile_port(self, state: PluginStateAccess, profile_name: str) -> int:
        """The port the core listens on for this profile."""
        default = _profile_name(profile_name, DEFAULT_PORT)
        profile = self._profile_config(state, profile_name)
        return self._normalize_port((profile or {}).get("port"), default)

    def _obfuscation(
        self,
        state: PluginStateAccess,
        profile_name: str = "desktop",
    ) -> dict[str, str]:
        """The obfuscation the core serves for this profile, as it is stored."""
        profile = self._profile_config(state, profile_name) or {}
        obfuscation = profile.get("obfuscation")
        if not isinstance(obfuscation, dict):
            return {}
        return {str(key): str(value) for key, value in obfuscation.items() if value not in (None, "")}

    def _resolve_network(self, state: PluginStateAccess) -> str:
        """Select an unused /24 without mutating desired state."""
        protocol = state.protocols.get("amneziawg")
        used = self._used_networks(state)
        if protocol:
            configured = self._normalize_profile_network(protocol.config.get("network"))
            if configured and self._is_network_free(configured, used):
                return configured
        for network in PREFERRED_SUBNETS:
            if self._is_network_free(network, used):
                return network
        for second_octet in range(100, 256):
            for third_octet in range(256):
                candidate = ipaddress.ip_network(
                    f"10.{second_octet}.{third_octet}.0/24",
                    strict=False,
                )
                if self._is_network_free(str(candidate), used):
                    return str(candidate)
        return "10.100.0.0/24"

    @staticmethod
    def _normalize_profile_network(network: object) -> str | None:
        try:
            parsed = ipaddress.ip_network(str(network), strict=False)
        except (TypeError, ValueError):
            return None
        if parsed.version != 4 or parsed.prefixlen != 24:
            return None
        return str(parsed)

    @staticmethod
    def _normalize_port(port: object, default: int) -> int:
        try:
            parsed = int(str(port))
        except (TypeError, ValueError):
            return default
        return parsed if 1 <= parsed <= 65535 else default

    @staticmethod
    def _is_network_free(network: object, used: list[str]) -> bool:
        try:
            candidate = ipaddress.ip_network(str(network), strict=False)
        except (TypeError, ValueError):
            return False
        for raw_network in used:
            try:
                occupied = ipaddress.ip_network(str(raw_network), strict=False)
            except (TypeError, ValueError):
                continue
            if candidate.overlaps(occupied):
                return False
        return True

    @staticmethod
    def _used_networks(state: PluginStateAccess) -> list[str]:
        candidates: list[object] = list(KNOWN_SUBNETS)
        for name, protocol in state.protocols.items():
            if name != "amneziawg" and protocol.config.get("network"):
                candidates.append(protocol.config["network"])
        used: list[str] = []
        for raw_network in candidates:
            try:
                network = ipaddress.ip_network(str(raw_network), strict=False)
            except (TypeError, ValueError):
                continue
            normalized = str(network)
            if normalized not in used:
                used.append(normalized)
        return used


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_interface(value)
    except (TypeError, ValueError):
        return False
    return True
