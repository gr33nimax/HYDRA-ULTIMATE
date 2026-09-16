"""Desired-state command for AWG generation changes.

The core serves the tunnel, so a mode change is the shape of the endpoint's amnezia object: HYDRA
regenerates it, the command service applies and verifies it, and nothing shells out to an installer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TYPE_CHECKING

from hydra.core.singbox import SINGBOX_CONFIG
from hydra.plugins.context import PluginStateAccess

from . import presets as awg_presets
from .directives import canonical_mode
from .endpoints import generate_generation_material


def _generation_of_amnezia(amnezia: object) -> str | None:
    """Read one served amnezia block's generation, or None when it carries no material."""
    if not isinstance(amnezia, dict) or not amnezia:
        return None
    if "random_trailers" in amnezia:
        return "3.1"
    if "header_protection_key" in amnezia:
        return "3.0"
    return "2.0"


def served_generation(config_path: Path | None = None) -> str:
    """The generation the core is actually configured with, read back from its configuration.

    This is the authoritative answer for a served host: the installer's status talks about a scheme
    that is no longer in play.
    """
    path = config_path or SINGBOX_CONFIG
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "unavailable"
    endpoints = payload.get("endpoints") if isinstance(payload, dict) else None
    if not isinstance(endpoints, list):
        return "unavailable"
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or endpoint.get("type") != "wireguard":
            continue
        generation = _generation_of_amnezia(endpoint.get("amnezia"))
        if generation is not None:
            return generation
    return "unavailable"


class AwgProtocolModeMixin:
    """Keep desired mode aligned with the generation the core is configured with."""

    if TYPE_CHECKING:

        def __getattr__(self, name: str) -> Any:
            """Static dependency seam for the mode command."""
            ...

    @staticmethod
    def desired_protocol_mode(state: PluginStateAccess) -> str:
        protocol = state.protocols.get("amneziawg")
        raw = protocol.config.get("protocol_mode", "2.0") if protocol else "2.0"
        return canonical_mode(raw)

    def protocol_mode_status(self, state: PluginStateAccess) -> dict[str, Any]:
        """Return a redacted mode and export-capability projection."""
        desired = self.desired_protocol_mode(state)
        observed = served_generation()
        protocol = state.protocols.get("amneziawg")
        profiles = protocol.config.get("profiles") if protocol else None
        desktop = profiles.get("desktop") if isinstance(profiles, dict) else None
        legacy_strategy = desktop.get("preset", "custom") if isinstance(desktop, dict) else "custom"
        return {
            "desired": desired,
            "observed": observed,
            "legacy_strategy": legacy_strategy,
            "exports": self.export_capabilities(state),
        }

    def _stored_generation(self, state: PluginStateAccess) -> str:
        """The generation the material HYDRA keeps describes, which is what the projection emits."""
        protocol = state.protocols.get("amneziawg")
        profiles = protocol.config.get("profiles") if protocol else None
        if not isinstance(profiles, dict):
            return "2.0"
        for profile in profiles.values():
            if not isinstance(profile, dict):
                continue
            material = profile.get("generation")
            if not isinstance(material, dict) or not material:
                continue
            if "RandomTrailers" in material:
                return "3.1"
            if "HeaderProtectionKey" in material:
                return "3.0"
        return "2.0"

    @staticmethod
    def _generation_flags_are(state: PluginStateAccess, target: str) -> bool:
        """Whether every profile carries the flags the target generation means.

        Without this, a switch that has only flags to repair looks like a no-op: a profile stored as
        3.1 with cookies still on would keep serving a pair that is not 3.1 at all.
        """
        protocol = state.protocols.get("amneziawg")
        profiles = protocol.config.get("profiles") if protocol else None
        if not isinstance(profiles, dict):
            return True
        for profile in profiles.values():
            if not isinstance(profile, dict):
                continue
            stored = profile.get("generation")
            material = stored if isinstance(stored, dict) else {}
            if target == "3.1":
                if not material.get("RandomTrailers") or not material.get("DisableCookies"):
                    return False
            elif target == "3.0":
                if "RandomTrailers" in material or "DisableCookies" in material:
                    return False
        return True

    def _set_served_generation(self, state: PluginStateAccess, target: str) -> bool:
        """Switch the generation of the host the core serves.

        Entering 3.x fills in the material a profile does not carry yet, and leaving 3.x keeps it,
        which makes a return free. Values the operator already has are never replaced.
        """
        protocol = state.protocols.get("amneziawg")
        if protocol is None:
            raise RuntimeError("AmneziaWG configuration is missing")
        if (
            self.desired_protocol_mode(state) == target
            and self._stored_generation(state) == target
            and self._generation_flags_are(state, target)
        ):
            return False
        profiles = protocol.config.get("profiles")
        if not isinstance(profiles, dict) or not profiles:
            raise RuntimeError("AmneziaWG has no profile to switch")
        for profile in profiles.values():
            if not isinstance(profile, dict):
                continue
            stored = profile.get("generation")
            material = dict(stored) if isinstance(stored, dict) else {}
            if target != "2.0":
                # A profile drawn under 2.0 may carry paddings the third generation cannot use:
                # header protection reads each of them as its nonce, so they are raised to the floor
                # here instead of making the whole switch fail on a value nobody chose deliberately.
                obfuscation = profile.get("obfuscation")
                if isinstance(obfuscation, dict):
                    profile["obfuscation"] = awg_presets.lift_paddings_for_mode(obfuscation, target)
                for key, value in generate_generation_material(target).items():
                    material.setdefault(key, value)
                if target == "3.1":
                    # The generation *is* this pair and it is not the operator's to vary: random
                    # trailers on, cookies off. A profile carrying the other combination serves
                    # something that is not 3.1, and the links of this generation say so.
                    material["RandomTrailers"] = True
                    material["DisableCookies"] = True
                elif target == "3.0":
                    # 3.0 replaced obfuscation with header protection and nothing else: the two 3.1
                    # fields describe a shape this generation does not have.
                    material.pop("RandomTrailers", None)
                    material.pop("DisableCookies", None)
            if material:
                profile["generation"] = material
        protocol.config["protocol_mode"] = target
        return True

    def set_protocol_mode(self, state: PluginStateAccess, mode: object) -> bool:
        """Persist the desired generation; the command service applies and verifies it."""
        protocol = state.protocols.get("amneziawg")
        if protocol is None or not protocol.installed:
            raise RuntimeError("AmneziaWG is not installed")
        return self._set_served_generation(state, canonical_mode(mode))
