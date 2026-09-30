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
    """Read one served amnezia block's generation, or None when it carries no material.

    The 3.1 pair *is* the generation, so both fields have to be served for the answer to be 3.1;
    an endpoint carrying only ``random_trailers`` is the mixed shape an earlier release could
    write, and calling it 3.1 is what kept a cookies-enabled server looking correctly configured.
    """
    if not isinstance(amnezia, dict) or not amnezia:
        return None
    if "random_trailers" in amnezia and "disable_cookies" in amnezia:
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

    @staticmethod
    def _paddings_below_floor(state: PluginStateAccess, target: str) -> bool:
        """Whether a served profile carries a padding the generation cannot use.

        The floor is part of what a generation means: header protection reads each padding
        as its nonce, so a profile that stored 3.1 while keeping ``S3=0`` serves a mode it
        cannot carry. Leaving this out of the readiness check is what let such a host
        answer "already 3.1" and fail on the next apply.

        This is the *repair* trigger, so it looks only at paddings that are present and
        below the floor — a value the profile simply omits is the materializer's business.
        The final verdict on whether a profile is servable is :meth:`mode_readiness`.
        """
        protocol = state.protocols.get("amneziawg")
        profiles = protocol.config.get("profiles") if protocol else None
        if not isinstance(profiles, dict) or str(target).strip() in ("", "2.0"):
            return False
        for profile in profiles.values():
            if not isinstance(profile, dict):
                continue
            obfuscation = profile.get("obfuscation")
            if not isinstance(obfuscation, dict):
                continue
            for field in ("S1", "S2", "S3", "S4"):
                raw = obfuscation.get(field)
                if raw is None:
                    continue
                try:
                    value = int(str(raw).strip())
                except (TypeError, ValueError):
                    return True
                if value < awg_presets.AWG3_PADDING_MIN:
                    return True
        return False

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
            and not self._paddings_below_floor(state, target)
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

    def mode_readiness(self, state: PluginStateAccess, target: str) -> tuple[bool, str]:
        """Whether local material can actually serve ``target``, with the reason it cannot."""
        protocol = state.protocols.get("amneziawg")
        if protocol is None:
            return False, "AmneziaWG configuration is missing"
        profiles = protocol.config.get("profiles")
        if not isinstance(profiles, dict) or not profiles:
            return False, "no profile is defined"
        if self.desired_protocol_mode(state) != target:
            return False, "the desired mode was not stored"
        if self._stored_generation(state) != target:
            return False, "profiles carry no generation material for this mode"
        if not self._generation_flags_are(state, target):
            return False, "profile generation flags do not match this mode"
        for name, profile in sorted(profiles.items()):
            if not isinstance(profile, dict):
                return False, f"profile {name} is invalid"
            obfuscation = profile.get("obfuscation")
            if not isinstance(obfuscation, dict):
                return False, f"profile {name} has no obfuscation"
            valid, reason = awg_presets.validate_params(obfuscation, target)
            if not valid:
                return False, f"profile {name}: {reason}"
        return True, ""

    def prepare_node_config(self, state: PluginStateAccess, config: dict[str, Any]) -> bool:
        """Make the local generation match the mode a node was told to serve.

        The mode is a shape of local material, not a value to store: profiles, their
        padding floor and the generation flags. A node has no console, so it must be able
        to create a missing profile and to repair a profile that already claims the mode
        without carrying what it means. Material that is already legal is kept.
        """
        protocol = state.protocols.get("amneziawg")
        if protocol is None or not protocol.installed:
            raise ValueError("AmneziaWG is not installed")
        target = canonical_mode(config.get("protocol_mode", self.desired_protocol_mode(state)))
        profiles = protocol.config.get("profiles")
        if not isinstance(profiles, dict) or not profiles:
            copied = self._copied_profiles(protocol.config.get("profiles"))
            copied["desktop"] = self._materialize_desktop_profile(state)
            protocol.config["profiles"] = copied
            self._provision_missing_octets(state)
        self._set_served_generation(state, target)
        ready, reason = self.mode_readiness(state, target)
        if not ready:
            raise ValueError(f"AmneziaWG cannot serve {target}: {reason}")
        return True
