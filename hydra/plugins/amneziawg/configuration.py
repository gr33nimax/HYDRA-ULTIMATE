"""Pure desired-state rendering and network selection for AmneziaWG."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from hydra.plugins.base import ConfigFragment
from hydra.plugins.context import PluginStateAccess

from .constants import (
    AWG_INTERFACE,
    AWG_INTERFACE_1,
    DEFAULT_NETWORK,
    DEFAULT_OBFUSCATION,
    DEFAULT_PORT,
    DEFAULT_PORT_1,
    KNOWN_SUBNETS,
    OBFUSCATION_KEYS_EXTENDED,
    PREFERRED_SUBNETS,
)


def interface_prefix(text: str) -> str:
    """Return only the ``[Interface]`` portion of a WireGuard config."""
    out: list[str] = []
    for line in text.splitlines():
        if line.strip() == "[Peer]" or line.strip().startswith("### "):
            break
        out.append(line)
    return "\n".join(out).strip()


class AwgConfigurationMixin:
    """Render server configs without touching host runtime or desired state."""

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        desktop_conf = self._conf_path("desktop")
        mobile_conf = self._conf_path("mobile")
        desktop = self._profile_config(state, "desktop")
        mobile = self._profile_config(state, "mobile")
        has_desktop_source = desktop_conf.exists() or bool(
            desktop and desktop.get("server_private_key")
        )

        pending_desktop = None
        pending_mobile = None
        peer_map: dict[str, tuple[str, str]] = {}
        if has_desktop_source:
            pending_desktop = self._generate_config_for_iface(
                state,
                conf_path=desktop_conf,
                profile_name="desktop",
                default_network=DEFAULT_NETWORK,
                profile=desktop,
                peer_map=peer_map,
            )
        if mobile is not None:
            pending_mobile = self._generate_config_for_iface(
                state,
                conf_path=mobile_conf,
                profile_name="mobile",
                default_network="10.68.68.0/24",
                profile=mobile,
                peer_map=peer_map,
            )

        # Publish only a complete render, so one failing profile cannot leave
        # another profile pending from a half-completed configure pass.
        self._pending_conf = pending_desktop
        self._pending_conf_1 = pending_mobile
        self._peer_map = peer_map

        interfaces = [AWG_INTERFACE] if pending_desktop else []
        if pending_mobile:
            interfaces.append(AWG_INTERFACE_1)
        return ConfigFragment(nft_tproxy_ifaces=interfaces)

    def _generate_config_for_iface(
        self,
        state: PluginStateAccess,
        conf_path: Path,
        profile_name: str,
        default_network: str,
        *,
        profile: dict | None = None,
        peer_map: dict[str, tuple[str, str]] | None = None,
    ) -> str:
        existing_ips = self._existing_peer_ips_for_conf(conf_path)
        base, server_octet, _ = self._network_for_profile(
            state,
            conf_path,
            profile_name,
            default_network,
        )
        interface_block = self._reconciled_interface_block(
            conf_path,
            profile_name,
            profile,
            base,
            server_octet,
        )
        used = set(existing_ips.values()) | {server_octet}
        blocks = [interface_block.rstrip(), ""]

        for user in state.users:
            if user.blocked:
                continue
            keys = self._existing_keys(user, profile_name)
            if keys is None:
                raise RuntimeError(
                    f"AmneziaWG credentials for {user.email!r}/{profile_name} "
                    "were not provisioned by the user/profile command phase"
                )
            public_key = keys["public_key"]
            octet = existing_ips.get(public_key)
            if octet is None:
                octet = self._first_free(used)
                used.add(octet)
            if peer_map is not None:
                peer_map[public_key] = (
                    user.email,
                    "Mobile" if profile_name == "mobile" else "Desktop",
                )
            blocks.extend(
                (
                    f"### {user.email}",
                    "[Peer]",
                    f"PublicKey = {public_key}",
                    f"PresharedKey = {keys['preshared_key']}",
                    f"AllowedIPs = {base}.{octet}/32",
                    "",
                )
            )
        return "\n".join(blocks) + "\n"

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

    @staticmethod
    def _interface_prefix(text: str) -> str:
        return interface_prefix(text)

    @staticmethod
    def _replace_directive(block: str, key: str, value: object) -> str:
        rendered = f"{key} = {value}"
        pattern = rf"^{re.escape(key)}\s*=.*$"
        if re.search(pattern, block, re.M):
            return re.sub(pattern, rendered, block, flags=re.M)
        return f"{block.rstrip()}\n{rendered}" if block.strip() else rendered

    def _reconciled_interface_block(
        self,
        conf_path: Path,
        profile_name: str,
        profile: dict | None,
        base: str,
        server_octet: str,
    ) -> str:
        """Overlay desired profile fields onto an existing interface block."""
        text = conf_path.read_text(encoding="utf-8") if conf_path.exists() else ""
        block = self._interface_prefix(text)
        if not re.search(r"^\[Interface\]\s*$", block, re.M):
            block = f"[Interface]\n{block}" if block else "[Interface]"

        existing_private = re.search(r"^PrivateKey\s*=\s*(\S+)", block, re.M)
        desired_private = str((profile or {}).get("server_private_key") or "").strip()
        private_key = desired_private or (
            existing_private.group(1) if existing_private else ""
        )
        if not private_key:
            raise RuntimeError(
                f"AmneziaWG {profile_name} server key was not provisioned"
            )

        default_port = DEFAULT_PORT_1 if profile_name == "mobile" else DEFAULT_PORT
        port = self._normalize_port((profile or {}).get("port"), default_port)
        block = self._replace_directive(block, "PrivateKey", private_key)
        block = self._replace_directive(
            block,
            "Address",
            f"{base}.{server_octet}/24",
        )
        block = self._replace_directive(block, "ListenPort", port)

        desired_mtu = (profile or {}).get("mtu")
        if desired_mtu is not None:
            block = self._replace_directive(block, "MTU", desired_mtu)
        elif not re.search(r"^MTU\s*=", block, re.M):
            block = self._replace_directive(
                block,
                "MTU",
                1280 if profile_name == "mobile" else 1420,
            )

        desired_obfuscation = (
            (profile or {}).get("obfuscation")
            if isinstance((profile or {}).get("obfuscation"), dict)
            else None
        )
        if desired_obfuscation is not None:
            for key in OBFUSCATION_KEYS_EXTENDED:
                block = re.sub(
                    rf"^{re.escape(key)}\s*=.*\n?",
                    "",
                    block,
                    flags=re.M,
                )
            for key in OBFUSCATION_KEYS_EXTENDED:
                value = desired_obfuscation.get(key)
                if value not in (None, ""):
                    block = self._replace_directive(block, key, value)
        elif not conf_path.exists():
            for key, value in DEFAULT_OBFUSCATION.items():
                block = self._replace_directive(block, key, value)
        return block.strip()

    def _interface_block_for_conf(
        self,
        conf_path: Path,
        base: str,
        server_octet: str,
    ) -> str:
        text = conf_path.read_text(encoding="utf-8") if conf_path.exists() else ""
        block = self._interface_prefix(text)
        address = f"Address = {base}.{server_octet}/24"
        if re.search(r"^Address\s*=", block, re.M):
            return re.sub(r"^Address\s*=.*$", address, block, flags=re.M)
        return f"{block.rstrip()}\n{address}" if block.strip() else address

    def _interface_block(self) -> str:
        conf_path = self._conf_path("desktop")
        text = conf_path.read_text(encoding="utf-8") if conf_path.exists() else ""
        lines: list[str] = []
        for line in text.splitlines():
            if line.strip() == "[Peer]" or line.strip().startswith("### "):
                break
            lines.append(line)
        return "\n".join(lines)

    @staticmethod
    def _existing_peer_ips_for_conf(conf_path: Path) -> dict[str, str]:
        if not conf_path.exists():
            return {}
        result: dict[str, str] = {}
        current_public_key = None
        for raw_line in conf_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            public_key = re.match(r"PublicKey\s*=\s*(\S+)", line)
            if public_key:
                current_public_key = public_key.group(1)
                continue
            allowed_ip = re.match(
                r"AllowedIPs\s*=\s*(\d+)\.(\d+)\.(\d+)\.(\d+)",
                line,
            )
            if allowed_ip and current_public_key:
                result[current_public_key] = allowed_ip.group(4)
                current_public_key = None
        return result

    def _network_for_profile(
        self,
        state: PluginStateAccess,
        conf_path: Path,
        profile_name: str,
        default_network: str,
    ) -> tuple[str, str, str]:
        network = None
        profile = self._profile_config(state, profile_name)
        if profile is not None:
            network = self._normalize_profile_network(profile.get("network"))
        if not network and conf_path.exists():
            match = re.search(
                r"Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.",
                conf_path.read_text(encoding="utf-8"),
            )
            if match:
                network = (
                    f"{match.group(1)}.{match.group(2)}.{match.group(3)}.0/24"
                )
        if not network:
            network = default_network

        base = network.rsplit(".", 1)[0]
        server_octet = "1"
        if conf_path.exists():
            match = re.search(
                r"Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.(\d+)",
                conf_path.read_text(encoding="utf-8"),
            )
            if match and ".".join(match.groups()[:3]) == base:
                server_octet = match.group(4)
        return base, server_octet, network

    def _network(self, state: PluginStateAccess) -> tuple[str, str, str]:
        return self._network_for_profile(
            state,
            self._conf_path("desktop"),
            "desktop",
            DEFAULT_NETWORK,
        )

    def _resolve_network(self, state: PluginStateAccess) -> str:
        """Select an unused /24 without mutating desired state."""
        protocol = state.protocols.get("amneziawg")
        used = self._used_networks(state)
        if protocol:
            configured = self._normalize_profile_network(
                protocol.config.get("network")
            )
            if configured and self._is_network_free(configured, used):
                return configured

        conf_path = self._conf_path("desktop")
        if conf_path.exists():
            match = re.search(
                r"Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.",
                conf_path.read_text(encoding="utf-8"),
            )
            if match:
                network = (
                    f"{match.group(1)}.{match.group(2)}.{match.group(3)}.0/24"
                )
                if self._is_network_free(network, used):
                    return network
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
            parsed = int(port)
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

    @staticmethod
    def _first_free(used: set[str]) -> str:
        for octet in range(2, 255):
            if str(octet) not in used:
                return str(octet)
        return "254"

    @staticmethod
    def _obfuscation_for_conf(conf_path: Path) -> dict[str, str]:
        text = conf_path.read_text(encoding="utf-8") if conf_path.exists() else ""
        block = interface_prefix(text)
        result: dict[str, str] = {}
        for key in OBFUSCATION_KEYS_EXTENDED:
            match = re.search(rf"^{key}\s*=\s*(\S+)", block, re.M)
            if match:
                result[key] = match.group(1)
        return result

    def _obfuscation(self) -> dict[str, str]:
        return self._obfuscation_for_conf(self._conf_path("desktop"))
