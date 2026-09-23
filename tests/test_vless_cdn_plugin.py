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


# ── cam_source_url (TSK-07) ───────────────────────────────────────────────


def test_camera_source_defaults_to_empty_and_is_listed():
    keys = [key for key, _value in VlessCdnPlugin.meta.config_defaults]
    assert "cam_source_url" in keys
    assert dict(VlessCdnPlugin.meta.config_defaults)["cam_source_url"] == ""


def test_an_empty_camera_source_clears_it():
    state = _state()
    plugin = VlessCdnPlugin()

    assert plugin.set_cam_source_url(state, "https://1.1.1.1/cam.m3u8") is True
    assert plugin.set_cam_source_url(state, "   ") is True
    assert state.protocols[PROTOCOL_NAME].config["cam_source_url"] == ""


@pytest.mark.parametrize(
    "url",
    ["https://1.1.1.1/live/stream.m3u8", "rtsp://1.1.1.1:554/stream", "http://1.1.1.1/mjpg/video.mjpg"],
)
def test_a_public_source_is_accepted(url):
    # go2rtc ретранслирует любой из этих входов; проверяем только форму + SSRF.
    state = _state()
    plugin = VlessCdnPlugin()

    assert plugin.set_cam_source_url(state, url) is True
    assert state.protocols[PROTOCOL_NAME].config["cam_source_url"] == url


def test_a_hostname_source_is_accepted_when_it_resolves_publicly():
    state = _state()
    plugin = VlessCdnPlugin()
    resolve = lambda _host: ["93.184.216.34"]  # noqa: E731

    assert plugin.set_cam_source_url(state, "https://cam.example/live/stream.m3u8", resolve=resolve) is True


def test_a_hostname_source_that_resolves_privately_is_refused():
    state = _state()
    plugin = VlessCdnPlugin()
    resolve = lambda _host: ["10.0.0.5"]  # noqa: E731

    assert plugin.set_cam_source_url(state, "https://cam.example/live/stream.m3u8", resolve=resolve) is False
    assert state.protocols[PROTOCOL_NAME].config["cam_source_url"] == ""


@pytest.mark.parametrize(
    "url",
    [
        "ftp://cam.example/x.m3u8",
        "file:///etc/passwd",
        "http://10.0.0.1/x.m3u8",
        "https://127.0.0.1/x.m3u8",
        "https://192.168.0.10/x.m3u8",
        "not a url",
    ],
)
def test_a_refused_camera_source_leaves_the_config_untouched(url):
    state = _state()
    plugin = VlessCdnPlugin()

    assert plugin.set_cam_source_url(state, url) is False
    assert state.protocols[PROTOCOL_NAME].config["cam_source_url"] == ""


def test_camera_source_command_without_a_state_entry_is_refused():
    assert VlessCdnPlugin().set_cam_source_url(AppState(), "https://1.1.1.1/x.m3u8") is False
