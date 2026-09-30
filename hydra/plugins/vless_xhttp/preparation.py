"""Node-side preparation of the VLESS certificate or Reality material.

A node receives ``security`` and ``domain`` as plain public settings, but those choose
which local material the endpoint owns: the Reality keypair and the borrowed handshake, or
the certificate domain and its decoy route. Both are command-owned, so writing the value
is not enough — and a config that already claims a mode without carrying the material it
means has to be repaired instead of trusted.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from .security import (
    DECOY_ROUTE_KEY,
    DEFAULT_HANDSHAKE,
    HANDSHAKE_CONFIG_KEY,
    MODE_REALITY,
    MODE_TLS,
    PASSTHROUGH_ROUTE_KEY,
    handshake_target,
    normalize_domain,
    validate_handshake,
    validate_security,
)


class VlessNodePreparationMixin:
    """Keep the endpoint's TLS material in line with the requested public settings."""

    if TYPE_CHECKING:

        def __getattr__(self, name: str) -> Any:
            """Static dependency seam: ``set_security`` comes from the plugin."""
            ...

    @staticmethod
    def _security_is_ready(config: Mapping[str, object], mode: str, domain: str) -> tuple[bool, str]:
        """Whether local material can really serve the requested security mode."""
        if str(config.get("security", MODE_TLS)) != mode:
            return False, "the stored security mode differs"
        if mode == MODE_REALITY:
            if not str(config.get("reality_private_key", "")).strip():
                return False, "the Reality private key is missing"
            if not str(config.get("reality_public_key", "")).strip():
                return False, "the Reality public key is missing"
            if not isinstance(config.get(PASSTHROUGH_ROUTE_KEY), dict):
                return False, "the Reality passthrough route is missing"
            try:
                current = handshake_target(config)
            except ValueError:
                return False, "the Reality handshake is missing or invalid"
            if domain and current != domain:
                return False, "the Reality handshake differs from the requested host"
            return True, ""
        if domain and str(config.get("domain", "")).strip().lower().rstrip(".") != domain:
            return False, "the certificate domain differs from the requested one"
        if not isinstance(config.get(DECOY_ROUTE_KEY), dict):
            return False, "the certificate decoy route is missing"
        return True, ""

    def prepare_node_config(self, state, config: Mapping[str, object]) -> bool:
        """Make the certificate or Reality material match a node's public settings."""
        protocol = state.protocols.get("vless")
        if protocol is None:
            raise ValueError("VLESS is not installed")
        local = protocol.config
        mode = validate_security(config.get("security", local.get("security", MODE_TLS)))
        requested = str(config.get("domain", "") or "").strip()
        if mode == MODE_REALITY:
            domain = validate_handshake(requested or local.get(HANDSHAKE_CONFIG_KEY) or DEFAULT_HANDSHAKE)
        else:
            if not requested and not str(local.get("domain", "") or "").strip():
                raise ValueError("VLESS in TLS mode needs its own domain")
            try:
                domain = normalize_domain(requested or local.get("domain", ""))
            except ValueError as exc:
                raise ValueError(f"VLESS in TLS mode needs a valid domain: {exc}") from None
        ready, _ = self._security_is_ready(local, mode, domain)
        if not ready:
            self.set_security(state, mode, handshake=domain, domain=domain)
        ready, reason = self._security_is_ready(protocol.config, mode, domain)
        if not ready:
            raise ValueError(f"VLESS cannot serve {mode}: {reason}")
        return True


__all__ = ["VlessNodePreparationMixin"]
