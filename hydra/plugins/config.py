"""Compatibility exports for the dependency-neutral configuration contracts."""
from hydra.contracts import (
    ConfigFragment,
    ConfigurationError,
    FragmentValidationError,
    JsonObject,
    JsonPrimitive,
    JsonValue,
    PluginConfig,
    normalize_plugin_config,
    validate_fragment,
    validate_json_object,
    validate_json_value,
)

__all__ = [
    "ConfigFragment",
    "ConfigurationError",
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
