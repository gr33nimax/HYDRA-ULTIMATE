"""Dependency-neutral configuration contracts shared by core and plugins."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import TypeAlias

from hydra.contracts.errors import ConfigurationError


JsonPrimitive: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonPrimitive | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
PluginConfig: TypeAlias = JsonObject


class FragmentValidationError(ConfigurationError):
    """A plugin returned a structurally invalid configuration fragment."""


def validate_json_value(value: object, *, path: str = "config") -> None:
    """Reject non-JSON values before configuration reaches persistence/runtime."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate_json_value(item, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise FragmentValidationError(f"{path} keys must be strings")
            validate_json_value(item, path=f"{path}.{key}")
        return
    raise FragmentValidationError(
        f"{path} contains unsupported value {type(value).__name__}"
    )


def validate_json_object(value: object, *, path: str = "config") -> None:
    """Validate a JSON object and all values nested below it."""
    if not isinstance(value, dict):
        raise FragmentValidationError(f"{path} must be an object")
    validate_json_value(value, path=path)


def normalize_plugin_config(value: object, *, path: str = "config") -> PluginConfig:
    """Copy and validate a legacy dict before storing it in application state."""
    validate_json_object(value, path=path)
    return copy.deepcopy(value)


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

    def as_dict(self) -> JsonObject:
        return {
            "inbounds": self.inbounds,
            "outbounds": self.outbounds,
            "route_rules": self.route_rules,
            "nft_tproxy_ports": self.nft_tproxy_ports,
            "nft_tproxy_ifaces": self.nft_tproxy_ifaces,
            "endpoints": self.endpoints,
            "dns": self.dns,
        }


def validate_fragment(fragment: ConfigFragment) -> None:
    """Reject malformed plugin output before it reaches Sing-Box or nftables."""
    if not isinstance(fragment, ConfigFragment):
        raise FragmentValidationError(
            f"expected ConfigFragment, got {type(fragment).__name__}"
        )

    for field_name in ("inbounds", "outbounds", "route_rules", "endpoints"):
        values = getattr(fragment, field_name)
        if not isinstance(values, list) or any(
            not isinstance(item, dict) for item in values
        ):
            raise FragmentValidationError(f"{field_name} must be a list of objects")

    validate_json_object(fragment.dns, path="dns")
    for field_name in ("inbounds", "outbounds", "route_rules", "endpoints"):
        for index, item in enumerate(getattr(fragment, field_name)):
            validate_json_object(item, path=f"{field_name}[{index}]")
    for index, inbound in enumerate(fragment.inbounds):
        for field_name in ("type", "tag"):
            value = inbound.get(field_name)
            if not isinstance(value, str) or not value.strip():
                raise FragmentValidationError(
                    f"inbounds[{index}].{field_name} must be a non-empty string",
                )
        if "listen" in inbound and (
            not isinstance(inbound["listen"], str)
            or not inbound["listen"].strip()
        ):
            raise FragmentValidationError(
                f"inbounds[{index}].listen must be a non-empty string",
            )
        if "listen_port" in inbound:
            port = inbound["listen_port"]
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                raise FragmentValidationError(
                    f"inbounds[{index}].listen_port must be between 1 and 65535",
                )
        if "tls" in inbound and not isinstance(inbound["tls"], dict):
            raise FragmentValidationError(
                f"inbounds[{index}].tls must be an object",
            )

    if not isinstance(fragment.nft_tproxy_ports, list) or any(
        isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
        for port in fragment.nft_tproxy_ports
    ):
        raise FragmentValidationError(
            "nft_tproxy_ports must contain ports from 1 to 65535"
        )

    if not isinstance(fragment.nft_tproxy_ifaces, list) or any(
        not isinstance(iface, str) or not iface.strip()
        for iface in fragment.nft_tproxy_ifaces
    ):
        raise FragmentValidationError(
            "nft_tproxy_ifaces must contain non-empty names"
        )


__all__ = [
    "ConfigFragment",
    "FragmentValidationError",
    "JsonObject",
    "JsonPrimitive",
    "JsonValue",
    "PluginConfig",
    "normalize_plugin_config",
    "validate_fragment",
    "validate_json_object",
    "validate_json_value",
]
