"""AmneziaWG credentials and desired-state profile commands."""
from __future__ import annotations

import re
from pathlib import Path

from hydra.core.host import HOST
from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess

from .configuration import interface_prefix
from .constants import (
    AWG_INTERFACE,
    AWG_INTERFACE_1,
    AWG_UNIT,
    DEFAULT_NETWORK,
    DEFAULT_OBFUSCATION,
    DEFAULT_PORT,
    DEFAULT_PORT_1,
)


class AwgProfileMixin:
    """Own key material and profile mutations, never host reconciliation."""

    def _generate_keys(self) -> dict[str, str]:
        """Generate one complete key bundle without mutating desired state."""
        private_key = self._generate_private_key()
        public_result = self._awg("pubkey", _input=private_key)
        if public_result.returncode != 0:
            public_result = HOST.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
            )
        preshared_result = self._awg("genpsk")
        if preshared_result.returncode != 0:
            preshared_result = HOST.run(
                ["wg", "genpsk"],
                capture_output=True,
                text=True,
            )
        public_key = public_result.stdout.strip()
        preshared_key = preshared_result.stdout.strip()
        if not private_key or not public_key or not preshared_key:
            raise RuntimeError("AmneziaWG key generation returned an empty key")
        return {
            "private_key": private_key,
            "public_key": public_key,
            "preshared_key": preshared_key,
        }

    def _generate_private_key(self) -> str:
        result = self._awg("genkey")
        if result.returncode != 0:
            result = HOST.run(
                ["wg", "genkey"],
                capture_output=True,
                text=True,
            )
        private_key = result.stdout.strip()
        if not private_key:
            raise RuntimeError("AmneziaWG private-key generation failed")
        return private_key

    def _provision_user_keys(
        self,
        user: User,
        profile: str = "desktop",
    ) -> dict[str, str]:
        """Provision credentials during an explicit mutation lifecycle."""
        existing = self._existing_keys(user, profile)
        if existing is not None:
            return existing
        credentials = self._generate_keys()
        credential_name = (
            "amneziawg" if profile == "desktop" else f"amneziawg_{profile}"
        )
        user.credentials[credential_name] = credentials
        return credentials

    @staticmethod
    def _existing_keys(user: User, profile: str = "desktop") -> dict | None:
        """Read fully provisioned credentials without mutating query state."""
        credential_name = (
            "amneziawg" if profile == "desktop" else f"amneziawg_{profile}"
        )
        credentials = user.credentials.get(credential_name)
        required = {"private_key", "public_key", "preshared_key"}
        if not isinstance(credentials, dict) or not required <= credentials.keys():
            return None
        return credentials

    def _server_pubkey_for_conf(self, conf_path: Path) -> str:
        text = conf_path.read_text(encoding="utf-8") if conf_path.exists() else ""
        match = re.search(
            r"PrivateKey\s*=\s*(\S+)",
            interface_prefix(text),
        )
        if not match:
            return ""
        result = self._awg("pubkey", _input=match.group(1))
        if result.returncode != 0:
            result = HOST.run(
                ["wg", "pubkey"],
                input=match.group(1),
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return ""
        return result.stdout.strip()

    @staticmethod
    def _generate_obfuscation(
        preset: str,
        *,
        default_strategy: str,
    ) -> dict[str, str]:
        from hydra.plugins.amneziawg.presets import (
            LEGACY_PRESET_MAP,
            STRATEGIES,
            generate_params,
        )

        strategy = default_strategy
        carrier = None
        if ":" in preset:
            strategy, carrier = preset.split(":", 1)
            if carrier == "generic":
                carrier = None
        elif preset in STRATEGIES:
            strategy = preset
        elif preset in LEGACY_PRESET_MAP:
            strategy, carrier = LEGACY_PRESET_MAP[preset]
        else:
            strategy = preset
        return generate_params(strategy=strategy, carrier=carrier)

    @staticmethod
    def _private_key_from_conf(conf_path: Path) -> str:
        if not conf_path.exists():
            return ""
        match = re.search(
            r"^PrivateKey\s*=\s*(\S+)",
            interface_prefix(conf_path.read_text(encoding="utf-8")),
            re.M,
        )
        return match.group(1) if match else ""

    @staticmethod
    def _port_from_conf(conf_path: Path, default: int) -> int:
        if not conf_path.exists():
            return default
        match = re.search(
            r"^ListenPort\s*=\s*(\d+)",
            interface_prefix(conf_path.read_text(encoding="utf-8")),
            re.M,
        )
        if not match:
            return default
        port = int(match.group(1))
        return port if 1 <= port <= 65535 else default

    def _materialize_desktop_profile(
        self,
        state: PluginStateAccess,
    ) -> dict:
        """Create a desired desktop snapshot during an explicit command."""
        protocol = state.protocols["amneziawg"]
        desired = self._profile_config(state, "desktop") or {}
        conf_path = self._conf_path("desktop")
        _, _, runtime_network = self._network_for_profile(
            state,
            conf_path,
            "desktop",
            DEFAULT_NETWORK,
        )
        configured_network = self._normalize_profile_network(
            desired.get("network") or protocol.config.get("network")
        )
        resolved_network = (
            runtime_network
            if conf_path.exists()
            else self._resolve_network(state)
        )
        configured_obfuscation = (
            desired.get("obfuscation")
            if isinstance(desired.get("obfuscation"), dict)
            else protocol.config.get("obfuscation")
        )
        obfuscation = (
            dict(configured_obfuscation)
            if isinstance(configured_obfuscation, dict)
            else self._obfuscation()
        )
        if not obfuscation:
            obfuscation = dict(DEFAULT_OBFUSCATION)
        private_key = str(
            desired.get("server_private_key")
            or protocol.config.get("server_private_key")
            or self._private_key_from_conf(conf_path)
            or ""
        )
        if not private_key:
            private_key = self._generate_private_key()
        port = self._normalize_port(
            desired.get("port")
            or protocol.port
            or self._port_from_conf(conf_path, DEFAULT_PORT),
            DEFAULT_PORT,
        )
        materialized = {
            "interface": str(desired.get("interface") or AWG_INTERFACE),
            "port": port,
            "preset": str(
                desired.get("preset")
                or protocol.config.get("preset")
                or "default"
            ),
            "network": configured_network or resolved_network,
            "server_private_key": private_key,
            "obfuscation": obfuscation,
        }
        if desired.get("mtu") is not None:
            materialized["mtu"] = desired["mtu"]
        return materialized

    def get_profiles(self, state: PluginStateAccess) -> list[dict]:
        """Return normalized desktop/mobile desired profiles."""
        protocol = state.protocols.get("amneziawg")
        profiles = protocol.config.get("profiles") if protocol else None
        if isinstance(profiles, dict) and profiles:
            result = []
            for name, profile in profiles.items():
                if name not in {"desktop", "mobile"} or not isinstance(profile, dict):
                    continue
                mobile = name == "mobile"
                default_interface = AWG_INTERFACE_1 if mobile else AWG_INTERFACE
                default_port = DEFAULT_PORT_1 if mobile else DEFAULT_PORT
                default_network = (
                    "10.68.68.0/24" if mobile else DEFAULT_NETWORK
                )
                obfuscation = profile.get("obfuscation")
                result.append(
                    {
                        "name": name,
                        "label": "Mobile" if mobile else "Desktop",
                        "interface": str(
                            profile.get("interface") or default_interface
                        ),
                        "unit": (
                            f"awg-quick@"
                            f"{profile.get('interface') or default_interface}"
                        ),
                        "port": self._normalize_port(
                            profile.get("port"),
                            default_port,
                        ),
                        "preset": str(profile.get("preset") or "default"),
                        "network": (
                            self._normalize_profile_network(
                                profile.get("network")
                            )
                            or default_network
                        ),
                        "obfuscation": (
                            dict(obfuscation)
                            if isinstance(obfuscation, dict)
                            else {}
                        ),
                    }
                )
            if result:
                return result

        _, _, network = self._network(state)
        return [
            {
                "name": "desktop",
                "label": "Desktop",
                "interface": AWG_INTERFACE,
                "unit": AWG_UNIT,
                "port": self._current_port(),
                "preset": "default",
                "network": network,
                "obfuscation": self._obfuscation(),
            }
        ]

    def add_profile(
        self,
        name: str,
        preset: str,
        state: PluginStateAccess,
    ) -> bool:
        """Add a mobile profile to desired state without touching runtime."""
        if name != "mobile":
            return False
        protocol = state.protocols.get("amneziawg")
        if protocol is None:
            return False
        profiles = self._copied_profiles(protocol.config.get("profiles"))
        if "mobile" in profiles:
            return True

        desktop = self._materialize_desktop_profile(state)
        profiles["desktop"] = desktop
        network = self._mobile_network(state, desktop)
        server_private_key = self._generate_private_key()
        obfuscation = self._generate_obfuscation(
            preset,
            default_strategy="mobile",
        )
        pending_credentials = self._missing_profile_credentials(state)
        profiles["mobile"] = {
            "interface": AWG_INTERFACE_1,
            "port": DEFAULT_PORT_1,
            "preset": preset,
            "network": network,
            "server_private_key": server_private_key,
            "obfuscation": obfuscation,
            "mtu": 1280,
        }
        protocol.config["profiles"] = profiles
        for user, credential_name, credentials in pending_credentials:
            user.credentials[credential_name] = credentials
        return True

    @staticmethod
    def _copied_profiles(raw_profiles: object) -> dict[str, dict]:
        if not isinstance(raw_profiles, dict):
            return {}
        return {
            key: dict(value)
            for key, value in raw_profiles.items()
            if isinstance(value, dict)
        }

    def _mobile_network(
        self,
        state: PluginStateAccess,
        desktop: dict,
    ) -> str:
        used_networks = self._used_networks(state)
        desktop_network = self._normalize_profile_network(desktop.get("network"))
        if desktop_network and desktop_network not in used_networks:
            used_networks.append(desktop_network)
        preferred = "10.68.68.0/24"
        if self._is_network_free(preferred, used_networks):
            return preferred
        for second_octet in range(100, 256):
            for third_octet in range(256):
                candidate = f"10.{second_octet}.{third_octet}.0/24"
                if self._is_network_free(candidate, used_networks):
                    return candidate
        return preferred

    def _missing_profile_credentials(
        self,
        state: PluginStateAccess,
    ) -> list[tuple[User, str, dict[str, str]]]:
        pending: list[tuple[User, str, dict[str, str]]] = []
        for user in state.users:
            if user.blocked:
                continue
            if self._existing_keys(user, "desktop") is None:
                pending.append((user, "amneziawg", self._generate_keys()))
            if self._existing_keys(user, "mobile") is None:
                pending.append(
                    (user, "amneziawg_mobile", self._generate_keys())
                )
        return pending

    def remove_profile(
        self,
        name: str,
        state: PluginStateAccess,
    ) -> bool:
        """Remove the mobile profile from desired state only."""
        if name != "mobile":
            return False
        protocol = state.protocols.get("amneziawg")
        if protocol is None:
            return False
        profiles = protocol.config.get("profiles")
        if not isinstance(profiles, dict) or "mobile" not in profiles:
            return False
        del profiles["mobile"]
        for user in state.users:
            user.credentials.pop("amneziawg_mobile", None)
        return True

    def rotate_obfuscation(
        self,
        state: PluginStateAccess,
        profile: str = None,
        preset: str = None,
    ) -> bool:
        """Rotate desired obfuscation; runtime changes happen in ``apply``."""
        profile_name = profile or "desktop"
        if profile_name not in {"desktop", "mobile"}:
            return False
        protocol = state.protocols.get("amneziawg")
        if protocol is None:
            return False
        profiles = self._copied_profiles(protocol.config.get("profiles"))
        current = profiles.get(profile_name)
        if not isinstance(current, dict):
            if profile_name == "mobile":
                return False
            current = self._materialize_desktop_profile(state)
        elif profile_name == "desktop":
            current = self._materialize_desktop_profile(state)

        selected_preset = preset or str(current.get("preset") or "default")
        new_params = self._generate_obfuscation(
            selected_preset,
            default_strategy=(
                "wired" if profile_name == "desktop" else "mobile"
            ),
        )
        pending_credentials = [
            (user, self._generate_keys())
            for user in state.users
            if not user.blocked
            and self._existing_keys(user, profile_name) is None
        ]
        current["preset"] = selected_preset
        current["obfuscation"] = new_params
        profiles[profile_name] = current
        protocol.config["profiles"] = profiles
        credential_name = (
            "amneziawg"
            if profile_name == "desktop"
            else f"amneziawg_{profile_name}"
        )
        for user, credentials in pending_credentials:
            user.credentials[credential_name] = credentials
        return True

    def _provision_user_profiles(
        self,
        user: User,
        state: PluginStateAccess,
    ) -> None:
        self._provision_user_keys(user, "desktop")
        if self._profile_config(state, "mobile") is not None:
            self._provision_user_keys(user, "mobile")

    def on_user_add(self, user: User, state: PluginStateAccess) -> None:
        self._provision_user_profiles(user, state)

    def on_user_remove(self, user: User, state: PluginStateAccess) -> None:
        pass

    def on_user_block(self, user: User, state: PluginStateAccess) -> None:
        if not user.blocked:
            self._provision_user_profiles(user, state)
