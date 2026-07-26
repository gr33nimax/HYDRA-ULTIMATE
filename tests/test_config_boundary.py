import pytest

from hydra.contracts import (
    ConfigFragment as ContractConfigFragment,
    FragmentValidationError as ContractFragmentValidationError,
    PluginConfig as ContractPluginConfig,
    validate_fragment as contract_validate_fragment,
)
from hydra.core.errors import ConfigurationError
from hydra.core.state import AppState, PluginState, validate_state
from hydra.plugins.base import ConfigFragment as BaseConfigFragment
from hydra.plugins.config import (
    ConfigFragment,
    ConfigurationError as LegacyConfigurationError,
    FragmentValidationError,
    PluginConfig,
    normalize_plugin_config,
    validate_fragment,
)


def test_config_fragment_serializes_through_typed_json_boundary():
    fragment = ConfigFragment(
        inbounds=[
            {
                "type": "direct",
                "tag": "direct-in",
                "nested": {"enabled": True},
            },
        ],
    )
    validate_fragment(fragment)
    assert fragment.as_dict()["inbounds"][0]["nested"]["enabled"] is True


def test_config_fragment_rejects_non_json_values():
    fragment = ConfigFragment(inbounds=[{"bad": object()}])
    with pytest.raises(FragmentValidationError):
        validate_fragment(fragment)


@pytest.mark.parametrize("port", [True, 0, 65536, "443"])
def test_config_fragment_rejects_invalid_inbound_ports(port):
    fragment = ConfigFragment(
        inbounds=[
            {
                "type": "demo",
                "tag": "demo-in",
                "listen_port": port,
            },
        ],
    )

    with pytest.raises(FragmentValidationError, match="listen_port"):
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


def test_legacy_plugin_contract_imports_reexport_neutral_objects():
    assert ConfigFragment is ContractConfigFragment is BaseConfigFragment
    assert LegacyConfigurationError is ConfigurationError
    assert FragmentValidationError is ContractFragmentValidationError
    assert issubclass(FragmentValidationError, ConfigurationError)
    assert PluginConfig is ContractPluginConfig
    assert validate_fragment is contract_validate_fragment
