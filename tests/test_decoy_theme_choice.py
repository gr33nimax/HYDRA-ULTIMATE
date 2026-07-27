"""Operator-facing selection of a protocol's decoy site."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from hydra.core.sni_router import _collect_backends
from hydra.core.state import AppState, PluginState
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.decoy_support import supports_decoy_theme
from hydra.plugins.hysteria2.plugin import Hysteria2Plugin
from hydra.plugins.naive.plugin import NaivePlugin
from hydra.plugins.snell.plugin import SnellPlugin
from hydra.plugins.trusttunnel.plugin import TrustTunnelPlugin
from hydra.plugins.vless_xhttp.plugin import ROUTE_CONFIG_KEY, VlessXhttpPlugin
from hydra.ui._menus import decoy_theme, protocol_activation


DECOY_PLUGINS = (
    (NaivePlugin, "landing"),
    (AnyTLSPlugin, "blog"),
    (TrustTunnelPlugin, "docs"),
    (Hysteria2Plugin, "status"),
    (VlessXhttpPlugin, "media"),
)


@pytest.mark.parametrize(("plugin_type", "default"), DECOY_PLUGINS)
def test_every_decoy_protocol_declares_the_command_and_its_default(
    plugin_type,
    default,
):
    plugin = plugin_type()

    assert supports_decoy_theme(plugin)
    assert plugin.decoy_default_theme == default
    assert dict(plugin.meta.config_defaults)["decoy_theme"] == default


def test_protocol_without_a_decoy_does_not_offer_the_command():
    assert not supports_decoy_theme(SnellPlugin())


@pytest.mark.parametrize(("plugin_type", "_default"), DECOY_PLUGINS)
def test_set_decoy_theme_validates_before_it_mutates(plugin_type, _default):
    plugin = plugin_type()
    name = plugin.meta.name
    state = AppState(protocols={name: PluginState(config={"domain": "a.example.com"})})

    with pytest.raises(ValueError, match="Unknown decoy theme"):
        plugin.set_decoy_theme(state, "not-a-theme")
    assert "decoy_theme" not in state.protocols[name].config

    assert plugin.set_decoy_theme(state, "Portfolio")
    assert state.protocols[name].config["decoy_theme"] == "portfolio"
    assert plugin.decoy_theme(state) == "portfolio"


def _mux_state() -> AppState:
    state = AppState()
    state.network.domain = "naive.example.com"
    state.protocols["anytls"] = PluginState(
        enabled=True,
        installed=True,
        config={"domain": "anytls.example.com", "decoy_theme": "cafe"},
    )
    state.protocols["vless"] = PluginState(
        enabled=True,
        installed=True,
        config={
            "domain": "xhttp.example.com",
            "decoy_theme": "shop",
            "xhttp_path": "/xhttp",
            ROUTE_CONFIG_KEY: VlessXhttpPlugin.route_config(),
        },
    )
    return state


def test_configured_theme_reaches_the_caddy_backends():
    backends = {
        backend["name"]: backend
        for backend in _collect_backends(_mux_state())
    }

    assert backends["anytls"]["decoy_theme"] == "cafe"
    assert backends["vless"]["decoy_theme"] == "shop"


def test_route_metadata_theme_is_only_a_fallback():
    state = _mux_state()
    state.protocols["vless"].config.pop("decoy_theme")

    backends = {
        backend["name"]: backend
        for backend in _collect_backends(state)
    }

    assert backends["vless"]["decoy_theme"] == "media"


def test_invalid_configured_theme_is_rejected_before_apply():
    state = _mux_state()
    state.protocols["vless"].config["decoy_theme"] = "not-a-theme"

    with pytest.raises(ValueError, match="decoy_theme is not supported"):
        _collect_backends(state)


def test_menu_row_shows_the_configured_theme():
    plugin = AnyTLSPlugin()
    desired = PluginState(config={"decoy_theme": "gallery"})

    label, value = decoy_theme.decoy_option(plugin, desired)

    assert label == "🎭 Сайт-заглушка"
    assert value == decoy_theme.theme_label("gallery")
    assert decoy_theme.decoy_option(SnellPlugin(), desired) is None


def test_menu_row_falls_back_to_the_plugin_default():
    plugin = Hysteria2Plugin()

    assert decoy_theme.current_theme(plugin, PluginState()) == "status"
    assert decoy_theme.current_theme(
        plugin,
        PluginState(config={"decoy_theme": "nonsense"}),
    ) == "status"


def test_choosing_a_theme_goes_through_the_plugin_command():
    plugin = AnyTLSPlugin()
    state = AppState(protocols={"anytls": PluginState()})
    app = MagicMock()
    app.plugin_command.return_value = True

    with patch.object(decoy_theme, "menu", return_value="1"), patch.object(
        decoy_theme,
        "prompt",
        return_value="",
    ):
        decoy_theme.open_decoy_menu(state, plugin, app)

    app.plugin_command.assert_called_once()
    arguments = app.plugin_command.call_args
    assert arguments[0][1:] == ("anytls", "set_decoy_theme")
    assert arguments[1]["theme"] in decoy_theme.THEMES


def test_cancelling_the_chooser_changes_nothing():
    plugin = AnyTLSPlugin()
    state = AppState(protocols={"anytls": PluginState()})
    app = MagicMock()

    with patch.object(decoy_theme, "menu", return_value="0"):
        decoy_theme.open_decoy_menu(state, plugin, app)

    app.plugin_command.assert_not_called()


def _activation_app(state: AppState) -> MagicMock:
    app = MagicMock()
    app.admin.load_state.return_value = state
    return app


def test_activation_asks_for_the_theme_once():
    plugin = AnyTLSPlugin()
    state = AppState(
        protocols={"anytls": PluginState(config={"domain": "a.example.com"})},
    )
    app = _activation_app(state)
    asked: list[str] = []

    def choose(current: str) -> str:
        asked.append(current)
        return "conference"

    assert protocol_activation.prepare_interactive_activation(
        state,
        plugin,
        app,
        ask=MagicMock(return_value="a.example.com"),
        report_error=MagicMock(),
        choose_decoy=choose,
    )
    assert protocol_activation.prepare_interactive_activation(
        state,
        plugin,
        app,
        ask=MagicMock(return_value="a.example.com"),
        report_error=MagicMock(),
        choose_decoy=choose,
    )

    assert asked == ["blog"]
    assert state.protocols["anytls"].config["decoy_theme"] == "conference"


def test_headless_activation_never_prompts_or_writes_a_theme():
    plugin = AnyTLSPlugin()
    state = AppState(
        protocols={"anytls": PluginState(config={"domain": "a.example.com"})},
    )
    app = _activation_app(state)

    assert protocol_activation.prepare_interactive_activation(
        state,
        plugin,
        app,
        ask=MagicMock(return_value="a.example.com"),
        report_error=MagicMock(),
    )

    assert "decoy_theme" not in state.protocols["anytls"].config
