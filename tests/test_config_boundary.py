import pytest

from hydra.core.state import AppState, PluginState, validate_state
from hydra.plugins.config import (
    ConfigFragment,
    FragmentValidationError,
    normalize_plugin_config,
    validate_fragment,
)


def test_config_fragment_serializes_through_typed_json_boundary():
    fragment = ConfigFragment(inbounds=[{"type": "direct", "nested": {"enabled": True}}])
    validate_fragment(fragment)
    assert fragment.as_dict()["inbounds"][0]["nested"]["enabled"] is True


def test_config_fragment_rejects_non_json_values():
    fragment = ConfigFragment(inbounds=[{"bad": object()}])
    with pytest.raises(FragmentValidationError):
        validate_fragment(fragment)


def test_state_rejects_non_json_plugin_config():
    state = AppState(protocols={"demo": PluginState(config={"bad": object()})})
    with pytest.raises(ValueError, match="unsupported value"):
        validate_state(state)


def test_legacy_config_adapter_copies_valid_dict():
    source = {"domain": "example.com", "options": {"enabled": True}}
    normalized = normalize_plugin_config(source)
    source["options"]["enabled"] = False
    assert normalized["options"]["enabled"] is True
