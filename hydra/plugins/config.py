"""Typed configuration boundary shared by HYDRA plugins."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypeAlias

from hydra.core.errors import ConfigurationError


JsonObject: TypeAlias = dict[str, Any]


@dataclass
class ConfigFragment:
    """A plugin contribution to the generated runtime configuration."""

    inbounds: list[JsonObject] = field(default_factory=list)
    outbounds: list[JsonObject] = field(default_factory=list)
    route_rules: list[JsonObject] = field(default_factory=list)
    nft_tproxy_ports: list[int] = field(default_factory=list)
    nft_tproxy_ifaces: list[str] = field(default_factory=list)
    endpoints: list[JsonObject] = field(default_factory=list)
    dns: JsonObject = field(default_factory=dict)

    def is_empty(self) -> bool:
        return not any(
            (
                self.inbounds,
                self.outbounds,
                self.route_rules,
                self.nft_tproxy_ports,
                self.nft_tproxy_ifaces,
                self.endpoints,
                self.dns,
            )
        )


class FragmentValidationError(ConfigurationError):
    """A plugin returned a structurally invalid configuration fragment."""


def validate_fragment(fragment: ConfigFragment) -> None:
    """Reject malformed plugin output before it reaches Sing-Box or nftables."""
    if not isinstance(fragment, ConfigFragment):
        raise FragmentValidationError(
            f"expected ConfigFragment, got {type(fragment).__name__}"
        )

    for field_name in ("inbounds", "outbounds", "route_rules", "endpoints"):
        values = getattr(fragment, field_name)
        if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
            raise FragmentValidationError(f"{field_name} must be a list of objects")

    if not isinstance(fragment.dns, dict):
        raise FragmentValidationError("dns must be an object")

    if not isinstance(fragment.nft_tproxy_ports, list) or any(
        isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
        for port in fragment.nft_tproxy_ports
    ):
        raise FragmentValidationError("nft_tproxy_ports must contain ports from 1 to 65535")

    if not isinstance(fragment.nft_tproxy_ifaces, list) or any(
        not isinstance(iface, str) or not iface.strip()
        for iface in fragment.nft_tproxy_ifaces
    ):
        raise FragmentValidationError("nft_tproxy_ifaces must contain non-empty names")
