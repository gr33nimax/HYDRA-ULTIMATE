"""Server projection: desired state drawn as the WireGuard endpoints the core serves.

The endpoint *is* the server side of the tunnel. Every field comes from desired state — there is no
interface file to fall back to, and no second source that could disagree with what clients are handed.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from hydra.plugins.context import PluginStateAccess

from .constants import DEFAULT_MTU, PROFILE_NETWORKS
from .directives import canonical_mode
from .endpoints import amnezia_block, build_endpoint, build_peer


class AwgProjectionMixin:
    """Project one profile's state onto the endpoint the core serves."""

    if TYPE_CHECKING:

        def __getattr__(self, name: str) -> Any:
            """Static dependency seam for the projection."""
            ...

    def server_endpoints(self, state: PluginStateAccess) -> list[dict]:
        """One endpoint per profile that carries a server key, peers from the users' credentials."""
        protocol = state.protocols.get("amneziawg")
        mode = canonical_mode(protocol.config.get("protocol_mode", "2.0") if protocol else "2.0")
        endpoints: list[dict] = []
        for profile_name, default_network in PROFILE_NETWORKS.items():
            profile = self._profile_config(state, profile_name)
            if not isinstance(profile, dict):
                continue
            private_key = str(profile.get("server_private_key") or "").strip()
            if not private_key:
                continue
            base, server_octet, _ = self._network_for_profile(
                state,
                profile_name,
                default_network,
            )
            stored_generation = profile.get("generation")
            generation = dict(stored_generation) if isinstance(stored_generation, dict) else {}
            used = {server_octet}
            peers: list[dict] = []
            for user in state.users:
                if user.blocked:
                    continue
                keys = self._existing_keys(user, profile_name)
                if keys is None:
                    continue
                # The octet is written where the credentials are provisioned: a peer without one is a
                # peer HYDRA has not issued an address for, and guessing here would hand the server a
                # peer the client cannot use.
                octet = str(keys.get("address_octet") or "").strip()
                if not octet or octet in used:
                    continue
                used.add(octet)
                peers.append(
                    build_peer(
                        public_key=keys["public_key"],
                        preshared_key=keys.get("preshared_key"),
                        address=f"{base}.{octet}/32",
                    ),
                )
            endpoints.append(
                build_endpoint(
                    tag=f"awg-{profile_name}",
                    address=f"{base}.{server_octet}/24",
                    private_key=private_key,
                    port=self._profile_port(state, profile_name),
                    mtu=self._profile_mtu(profile),
                    peers=peers,
                    amnezia=amnezia_block(
                        self._obfuscation(state, profile_name),
                        generation,
                        mode,
                    ),
                ),
            )
        return endpoints

    @staticmethod
    def _profile_mtu(profile: dict) -> str:
        """The MTU this profile serves, or what HYDRA hands out by default."""
        return str(profile.get("mtu") or "").strip() or DEFAULT_MTU
