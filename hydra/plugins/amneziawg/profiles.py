"""AmneziaWG credentials and desired-state profile commands."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from hydra.core.state_models import User
from hydra.plugins.context import PluginStateAccess

from .constants import (
    DEFAULT_NETWORK,
    DEFAULT_OBFUSCATION,
    DEFAULT_PORT,
    DEFAULT_PORT_1,
    ENDPOINT_TAG_DESKTOP,
    ENDPOINT_TAG_MOBILE,
    MOBILE_NETWORK,
)
from .keys import generate_preshared_key, generate_private_key, public_key


class AwgProfileMixin:
    """Own key material and profile mutations, never host reconciliation."""

    if TYPE_CHECKING:

        def __getattr__(self, name: str) -> Any:
            """Static dependency seam for desired profile operations."""
            ...

    def _generate_keys(self) -> dict[str, str]:
        """Generate one complete key bundle without mutating desired state."""
        private_key = self._generate_private_key()
        return {
            "private_key": private_key,
            "public_key": public_key(private_key),
            "preshared_key": generate_preshared_key(),
        }

    @staticmethod
    def _generate_private_key() -> str:
        """A fresh server or client private key."""
        return generate_private_key()

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
        credential_name = "amneziawg" if profile == "desktop" else f"amneziawg_{profile}"
        user.credentials[credential_name] = credentials
        return credentials

    def _existing_keys(self, user: User, profile: str = "desktop") -> dict | None:
        """Read fully provisioned credentials without mutating query state."""
        credential_name = "amneziawg" if profile == "desktop" else f"amneziawg_{profile}"
        credentials = user.credentials.get(credential_name)
        required = {"private_key", "public_key", "preshared_key"}
        if not isinstance(credentials, dict) or not required <= credentials.keys():
            return None
        return credentials

    @staticmethod
    def _generate_obfuscation(
        preset: str,
        *,
        default_strategy: str,
        protocol_mode: str = "2.0",
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
        return generate_params(strategy=strategy, carrier=carrier, protocol_mode=protocol_mode)

    def _materialize_desktop_profile(
        self,
        state: PluginStateAccess,
    ) -> dict:
        """Create a desired desktop snapshot during an explicit command."""
        protocol = state.protocols["amneziawg"]
        desired = self._profile_config(state, "desktop") or {}
        configured_network = self._normalize_profile_network(desired.get("network") or protocol.config.get("network"))
        configured_obfuscation = (
            desired.get("obfuscation")
            if isinstance(desired.get("obfuscation"), dict)
            else protocol.config.get("obfuscation")
        )
        obfuscation = (
            dict(configured_obfuscation)
            if isinstance(configured_obfuscation, dict) and configured_obfuscation
            else dict(DEFAULT_OBFUSCATION)
        )
        private_key = str(desired.get("server_private_key") or protocol.config.get("server_private_key") or "").strip()
        if not private_key:
            private_key = self._generate_private_key()
        materialized = {
            "interface": str(desired.get("interface") or ENDPOINT_TAG_DESKTOP),
            "port": self._normalize_port(
                desired.get("port") or protocol.port,
                DEFAULT_PORT,
            ),
            "preset": str(desired.get("preset") or protocol.config.get("preset") or "default"),
            "network": configured_network or self._resolve_network(state),
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
                default_interface = ENDPOINT_TAG_MOBILE if mobile else ENDPOINT_TAG_DESKTOP
                default_port = DEFAULT_PORT_1 if mobile else DEFAULT_PORT
                default_network = MOBILE_NETWORK if mobile else DEFAULT_NETWORK
                obfuscation = profile.get("obfuscation")
                result.append(
                    {
                        "name": name,
                        "label": "Mobile" if mobile else "Desktop",
                        "interface": str(profile.get("interface") or default_interface),
                        "port": self._normalize_port(
                            profile.get("port"),
                            default_port,
                        ),
                        "preset": str(profile.get("preset") or "default"),
                        "network": (self._normalize_profile_network(profile.get("network")) or default_network),
                        "obfuscation": (dict(obfuscation) if isinstance(obfuscation, dict) else {}),
                    }
                )
            if result:
                return result

        return [
            {
                "name": "desktop",
                "label": "Desktop",
                "interface": ENDPOINT_TAG_DESKTOP,
                "port": self._profile_port(state, "desktop"),
                "preset": "default",
                "network": self._network_for_profile(state, "desktop", DEFAULT_NETWORK)[2],
                "obfuscation": self._obfuscation(state, "desktop"),
            }
        ]

    def get_issued_profiles(self, state: PluginStateAccess) -> list[dict]:
        """Return only profiles with a server key and an issued user peer."""
        issued = []
        for profile in self.get_profiles(state):
            name = str(profile["name"])
            desired = self._profile_config(state, name) or {}
            if not str(desired.get("server_private_key") or "").strip():
                continue
            if any(
                (credentials := self._existing_keys(user, name)) is not None
                and str(credentials.get("address_octet") or "").strip()
                for user in state.users
                if not user.blocked
            ):
                issued.append(profile)
        return issued

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
            protocol_mode=str(protocol.config.get("protocol_mode", "2.0")),
        )
        pending_credentials = self._missing_profile_credentials(state)
        profiles["mobile"] = {
            "interface": ENDPOINT_TAG_MOBILE,
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
    def _copied_profiles(raw_profiles: object) -> dict[str, Any]:
        if not isinstance(raw_profiles, dict):
            return {}
        return {key: dict(value) for key, value in raw_profiles.items() if isinstance(value, dict)}

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
                pending.append((user, "amneziawg_mobile", self._generate_keys()))
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
        profile: str | None = None,
        preset: str | None = None,
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
            default_strategy=("wired" if profile_name == "desktop" else "mobile"),
            protocol_mode=str(protocol.config.get("protocol_mode", "2.0")),
        )
        pending_credentials = [
            (user, self._generate_keys())
            for user in state.users
            if not user.blocked and self._existing_keys(user, profile_name) is None
        ]
        current["preset"] = selected_preset
        current["obfuscation"] = new_params
        profiles[profile_name] = current
        protocol.config["profiles"] = profiles
        credential_name = "amneziawg" if profile_name == "desktop" else f"amneziawg_{profile_name}"
        for user, credentials in pending_credentials:
            user.credentials[credential_name] = credentials
        self._provision_missing_octets(state)
        return True

    def _provision_missing_octets(self, state: PluginStateAccess) -> int:
        """Give every user of every served profile a tunnel address.

        The interface file used to carry these addresses and the core reads none of it: a peer
        without an address cannot be projected into an endpoint, nor handed to a client, which is
        what made a profile created after the move deliver nothing at all. An address that was
        already issued is never moved.
        """
        protocol = state.protocols.get("amneziawg")
        if protocol is None:
            return 0
        profiles = protocol.config.get("profiles")
        if not isinstance(profiles, dict):
            return 0
        assigned = 0
        for profile_name, default_network in (
            ("desktop", DEFAULT_NETWORK),
            ("mobile", MOBILE_NETWORK),
        ):
            if profile_name not in profiles:
                continue
            _, server_octet, _ = self._network_for_profile(state, profile_name, default_network)
            credential_name = "amneziawg" if profile_name == "desktop" else f"amneziawg_{profile_name}"
            used = {server_octet}
            pending: list[dict] = []
            for user in state.users:
                credentials = user.credentials.get(credential_name)
                if not isinstance(credentials, dict):
                    continue
                octet = str(credentials.get("address_octet") or "").strip()
                if octet:
                    used.add(octet)
                else:
                    pending.append(credentials)
            for credentials in pending:
                octet = self._first_free(used)
                credentials["address_octet"] = octet
                used.add(octet)
                assigned += 1
        return assigned

    def on_enable(self, state: PluginStateAccess) -> None:
        """Make "enabled" mean "serving": a host without a profile gets one, and its users addresses.

        Enabling AmneziaWG used to set the flags and leave the core with nothing to serve: the screen
        said "работает" while no endpoint existed, and no client could be handed anything.
        """
        protocol = state.protocols.get("amneziawg")
        if protocol is None:
            return
        profile = self._profile_config(state, "desktop")
        if not isinstance(profile, dict) or not str(profile.get("server_private_key") or "").strip():
            profiles = self._copied_profiles(protocol.config.get("profiles"))
            profiles["desktop"] = self._materialize_desktop_profile(state)
            protocol.config["profiles"] = profiles
        for user in state.users:
            if not user.blocked and self._existing_keys(user, "desktop") is None:
                user.credentials["amneziawg"] = self._generate_keys()
        self._provision_missing_octets(state)

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
        self._provision_missing_octets(state)

    def on_user_remove(self, user: User, state: PluginStateAccess) -> None:
        pass

    def on_user_block(self, user: User, state: PluginStateAccess) -> None:
        if not user.blocked:
            self._provision_user_profiles(user, state)
