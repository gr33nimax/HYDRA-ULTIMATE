"""Persisted state owned by the standalone headless creator subsystem."""
from __future__ import annotations

from dataclasses import dataclass, field

from hydra.contracts import JsonValue, PluginConfig, validate_json_object


DEFAULT_QWDTT_ROOM_COUNT = 4
MIN_QWDTT_ROOM_COUNT = 1
MAX_QWDTT_ROOM_COUNT = 16
DEFAULT_QWDTT_REFRESH_INTERVAL = 86_400
MIN_QWDTT_REFRESH_INTERVAL = 3_600
MAX_QWDTT_REFRESH_INTERVAL = 86_400


@dataclass
class HeadlessCreatorConfig:
    """Provider configuration and desired state of creator consumers."""

    providers: dict[str, PluginConfig] = field(default_factory=dict)
    consumers: dict[str, PluginConfig] = field(default_factory=dict)


def validate_raw_headless_creator(raw: object) -> None:
    """Validate the serialized creator subtree before dataclass conversion."""
    if not isinstance(raw, dict):
        raise ValueError("state field 'headless_creator' must be an object")
    providers = raw.get("providers", {})
    if not isinstance(providers, dict):
        raise ValueError("headless_creator.providers must be an object")
    _validate_providers(providers)
    consumers = raw.get("consumers", {})
    if not isinstance(consumers, dict):
        raise ValueError("headless_creator.consumers must be an object")
    _validate_consumers(consumers)


def validate_headless_creator(config: HeadlessCreatorConfig) -> None:
    """Validate provider names and JSON-compatible provider configuration."""
    if not isinstance(config.providers, dict):
        raise ValueError("headless_creator.providers must be an object")
    _validate_providers(config.providers)
    if not isinstance(config.consumers, dict):
        raise ValueError("headless_creator.consumers must be an object")
    _validate_consumers(config.consumers)


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


def _validate_consumers(consumers: dict) -> None:
    for name, consumer in consumers.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("headless creator consumers must have a name")
        if not isinstance(consumer, dict):
            raise ValueError(f"headless creator consumer {name} must be an object")
        try:
            validate_json_object(consumer, path=f"headless_creator.consumers.{name}")
        except Exception as exc:
            raise ValueError(str(exc)) from exc
        if name == "qwdtt":
            _validate_qwdtt_consumer(consumer)


def _validate_qwdtt_consumer(config: dict) -> None:
    provider = config.get("provider", "vk")
    if not isinstance(provider, str) or not provider.strip():
        raise ValueError("headless_creator.consumers.qwdtt.provider must be a name")
    for key in ("pool_enabled", "legacy_creator_reinstall_required"):
        if key in config and type(config[key]) is not bool:
            raise ValueError(f"headless_creator.consumers.qwdtt.{key} must be boolean")
    normalize_qwdtt_room_count(config.get("room_count", DEFAULT_QWDTT_ROOM_COUNT))
    interval = config.get(
        "refresh_interval_seconds",
        DEFAULT_QWDTT_REFRESH_INTERVAL,
    )
    if (
        type(interval) is not int
        or not MIN_QWDTT_REFRESH_INTERVAL <= interval <= MAX_QWDTT_REFRESH_INTERVAL
    ):
        raise ValueError(
            "headless_creator.consumers.qwdtt.refresh_interval_seconds must be "
            "between 1 and 24 hours",
        )


def normalize_qwdtt_room_count(value: object) -> int:
    if (
        type(value) is not int
        or not MIN_QWDTT_ROOM_COUNT <= value <= MAX_QWDTT_ROOM_COUNT
    ):
        raise ValueError(
            "qWDTT room count must be between "
            f"{MIN_QWDTT_ROOM_COUNT} and {MAX_QWDTT_ROOM_COUNT}",
        )
    return value


def get_creator_provider(
    config: HeadlessCreatorConfig,
    name: str,
) -> PluginConfig:
    """Return a provider config, creating its canonical entry if necessary."""
    return config.providers.setdefault(name, {})


def get_creator_consumer(
    config: HeadlessCreatorConfig,
    name: str,
) -> PluginConfig:
    """Return a consumer config, creating its canonical entry if necessary."""
    return config.consumers.setdefault(name, {})


__all__ = [
    "DEFAULT_QWDTT_REFRESH_INTERVAL",
    "DEFAULT_QWDTT_ROOM_COUNT",
    "HeadlessCreatorConfig",
    "MAX_QWDTT_REFRESH_INTERVAL",
    "MAX_QWDTT_ROOM_COUNT",
    "MIN_QWDTT_REFRESH_INTERVAL",
    "MIN_QWDTT_ROOM_COUNT",
    "get_creator_consumer",
    "get_creator_provider",
    "normalize_qwdtt_room_count",
    "validate_headless_creator",
    "validate_raw_headless_creator",
]
