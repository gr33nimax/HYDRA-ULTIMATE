"""Persisted state owned by the standalone headless creator subsystem."""
from __future__ import annotations

from dataclasses import dataclass, field

from hydra.contracts import JsonValue, PluginConfig, validate_json_object


@dataclass
class HeadlessCreatorConfig:
    """Provider-neutral desired configuration for creator integrations."""

    providers: dict[str, PluginConfig] = field(default_factory=dict)


def validate_raw_headless_creator(raw: object) -> None:
    """Validate the serialized creator subtree before dataclass conversion."""
    if not isinstance(raw, dict):
        raise ValueError("state field 'headless_creator' must be an object")
    providers = raw.get("providers", {})
    if not isinstance(providers, dict):
        raise ValueError("headless_creator.providers must be an object")
    _validate_providers(providers)


def validate_headless_creator(config: HeadlessCreatorConfig) -> None:
    """Validate provider names and JSON-compatible provider configuration."""
    if not isinstance(config.providers, dict):
        raise ValueError("headless_creator.providers must be an object")
    _validate_providers(config.providers)


def _validate_providers(providers: dict) -> None:
    for name, provider in providers.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("headless creator providers must have a name")
        if not isinstance(provider, dict):
            raise ValueError(f"headless creator provider {name} must be an object")
        try:
            validate_json_object(provider, path=f"headless_creator.providers.{name}")
        except Exception as exc:
            raise ValueError(str(exc)) from exc


def get_creator_provider(
    config: HeadlessCreatorConfig,
    name: str,
) -> PluginConfig:
    """Return a provider config, creating its canonical entry if necessary."""
    return config.providers.setdefault(name, {})


__all__ = [
    "HeadlessCreatorConfig",
    "get_creator_provider",
    "validate_headless_creator",
    "validate_raw_headless_creator",
]
