"""TSK-001: каркас протокола VLESS через внешний CDN."""

from unittest.mock import patch

import pytest

from hydra.core.state import AppState
from hydra.core.state_models import PluginState
from hydra.plugins.defaults import default_plugins
from hydra.contracts.vless_cdn import (
    DEFAULT_XHTTP_PATH,
    MIN_PATH_SEGMENTS,
    normalize_hostname,
    normalize_path,
)
from hydra.plugins.vless_cdn.plugin import PROTOCOL_NAME, VlessCdnPlugin
from hydra.services.protocol_setup import normalize_protocol_config


def _state() -> AppState:
    """Состояние с нашим протоколом и соседним, который не должен меняться.

    Framework подставляет значения по умолчанию при подготовке включения
    (`normalize_protocol_config`, отдельно покрыт тестом ниже); здесь те же
    значения кладутся напрямую, чтобы тест плагина не зависел от сервисов.
    """
    state = AppState()
    state.protocols[PROTOCOL_NAME] = PluginState(
        config={key: value for key, value in VlessCdnPlugin.meta.config_defaults},
    )
    state.protocols["snell"] = PluginState(enabled=True, config={"mode": "v5"})
    return state


def test_plugin_is_registered_with_unique_defaults():
    plugins = list(default_plugins())
    ours = [plugin for plugin in plugins if plugin.meta.name == PROTOCOL_NAME]

    assert len(ours) == 1
    assert isinstance(ours[0], VlessCdnPlugin)
    keys = [key for key, _value in ours[0].meta.config_defaults]
    assert len(keys) == len(set(keys))
    for expected in ("cdn_domain", "origin_host", "xhttp_path", "core_port"):
        assert expected in keys


def test_defaults_are_seeded_by_the_framework_path():
    seeded = normalize_protocol_config({}, VlessCdnPlugin.meta.config_defaults)

    assert seeded["xhttp_path"] == DEFAULT_XHTTP_PATH
    assert seeded["core_port"] == 0
    assert seeded["cdn_domain"] == ""

    # Значения по умолчанию не должны делиться между состояниями.
    seeded["region_country_code"] = "FI"
    fresh = normalize_protocol_config({}, VlessCdnPlugin.meta.config_defaults)
    assert fresh["region_country_code"] == ""


def test_configure_contributes_nothing_before_the_route_exists():
    fragment = VlessCdnPlugin().configure(_state())

    assert fragment.is_empty()
    assert fragment.inbounds == []


@pytest.mark.parametrize("value", ["/api/media/session", "/api/media/session/"])
def test_path_is_normalized_to_one_canonical_form(value):
    assert normalize_path(value) == DEFAULT_XHTTP_PATH


@pytest.mark.parametrize(
    "value",
    ["", "api/media/session", "/api/session", "/assets/logo.png", "/api/ media/session", "/"],
)
def test_path_rejects_what_would_break_the_route(value):
    with pytest.raises(ValueError):
        normalize_path(value)


def test_path_needs_at_least_three_segments():
    assert MIN_PATH_SEGMENTS == 3
    with pytest.raises(ValueError):
        normalize_path("/api/session")


@pytest.mark.parametrize(
    "value",
    ["", "https://cdn.example.com", "cdn.example.com/path", "localhost", "a..b", "cdn example.com"],
)
def test_hostname_rejects_what_acme_could_not_validate(value):
    with pytest.raises(ValueError):
        normalize_hostname(value, field="CDN-домен")


def test_hostname_is_lowercased_and_keeps_its_dots():
    assert normalize_hostname("CDN.Example.COM.", field="CDN-домен") == "cdn.example.com"


def test_commands_write_only_their_own_protocol():
    state = _state()
    plugin = VlessCdnPlugin()

    assert plugin.set_cdn_domain(state, "cdn.example.com") is True
    assert plugin.set_origin_host(state, "Origin.Example.com") is True
    assert plugin.set_path(state, "/api/media/session/") is True

    config = state.protocols[PROTOCOL_NAME].config
    assert config["cdn_domain"] == "cdn.example.com"
    assert config["origin_host"] == "origin.example.com"
    assert config["xhttp_path"] == DEFAULT_XHTTP_PATH
    assert state.protocols["snell"].config == {"mode": "v5"}
    assert state.protocols["snell"].enabled is True


def test_refused_command_leaves_state_untouched():
    state = _state()
    plugin = VlessCdnPlugin()

    assert plugin.set_origin_host(state, "not a host") is False
    assert plugin.set_path(state, "/vless") is False

    config = state.protocols[PROTOCOL_NAME].config
    assert config.get("origin_host", "") == ""
    assert config["xhttp_path"] == DEFAULT_XHTTP_PATH


def test_command_without_a_state_entry_is_refused():
    assert VlessCdnPlugin().set_cdn_domain(AppState(), "cdn.example.com") is False


def test_install_requires_the_kernel():
    plugin = VlessCdnPlugin()

    with patch("hydra.core.singbox.is_installed", return_value=False):
        assert plugin.install() is False
    with patch("hydra.core.singbox.is_installed", return_value=True):
        assert plugin.install() is True


def test_summary_and_status_report_what_the_operator_set():
    state = _state()
    plugin = VlessCdnPlugin()
    plugin.set_cdn_domain(state, "cdn.example.com")
    plugin.set_origin_host(state, "origin.example.com")
    state.protocols[PROTOCOL_NAME].enabled = True

    assert plugin.get_summary(state) == {
        "cdn_domain": "cdn.example.com",
        "origin_host": "origin.example.com",
        "xhttp_path": DEFAULT_XHTTP_PATH,
        "core_port": 0,
        "ready": True,
    }

    status = plugin.status(state)
    assert status.enabled is True
    assert status.running is True
    assert status.info["origin_host"] == "origin.example.com"


def test_status_is_not_running_until_both_names_are_set():
    state = _state()
    plugin = VlessCdnPlugin()
    state.protocols[PROTOCOL_NAME].enabled = True

    assert plugin.status(state).running is False
    assert plugin.get_summary(state)["ready"] is False
