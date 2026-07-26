from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from hydra.core.state import AppState, PluginState
from hydra.plugins.anytls.plugin import AnyTLSPlugin
from hydra.plugins.hysteria2.plugin import Hysteria2Plugin
from hydra.plugins.naive.plugin import NaivePlugin
from hydra.plugins.shadowtls.plugin import ShadowTLSPlugin
from hydra.plugins.trusttunnel.plugin import TrustTunnelPlugin
from hydra.plugins.vless_xhttp.plugin import VlessXhttpPlugin
from hydra.ui._menus.protocol_activation import (
    prepare_interactive_activation,
    run_lifecycle_action,
)


DOMAIN_TLS_PLUGINS = (
    (NaivePlugin, "network"),
    (AnyTLSPlugin, "protocol"),
    (TrustTunnelPlugin, "protocol"),
    (Hysteria2Plugin, "protocol"),
    (VlessXhttpPlugin, "protocol"),
)


def _activation_app(*, calls: list[str] | None = None):
    events = calls if calls is not None else []
    return SimpleNamespace(
        admin=SimpleNamespace(
            save_state=lambda _state: events.append("save"),
        ),
        protocols=SimpleNamespace(
            install=lambda _state, _name: events.append("install") or True,
            enable=lambda _state, _name: events.append("enable") or True,
            disable=lambda _state, _name: events.append("disable") or True,
        ),
        plugin_command=Mock(return_value=True),
        apply_error=lambda: "",
    )


@pytest.mark.parametrize(("plugin_type", "source"), DOMAIN_TLS_PLUGINS)
def test_all_certificate_domain_transports_collect_domain_before_activation(
    plugin_type,
    source,
):
    plugin = plugin_type()
    name = plugin.meta.name
    state = AppState(protocols={name: PluginState()})
    calls: list[str] = []
    app = _activation_app(calls=calls)
    ask = Mock(return_value=f"{name}.Example.COM.")

    assert prepare_interactive_activation(
        state,
        plugin,
        app,
        ask=ask,
        report_error=Mock(),
    )

    assert plugin.meta.needs_domain is True
    assert plugin.meta.capabilities.tls_domain_source == source
    expected = f"{name}.example.com"
    if source == "network":
        assert state.network.domain == expected
    else:
        assert state.protocols[name].config["domain"] == expected
    assert calls == ["save"]


@pytest.mark.parametrize(("plugin_type", "_source"), DOMAIN_TLS_PLUGINS)
def test_domain_setup_runs_before_install_and_enable(plugin_type, _source):
    plugin = plugin_type()
    name = plugin.meta.name
    state = AppState(protocols={name: PluginState()})
    desired = state.protocols[name]
    calls: list[str] = []
    errors: list[str] = []
    pause = Mock()

    run_lifecycle_action(
        state,
        plugin,
        desired,
        _activation_app(calls=calls),
        ask=Mock(return_value=f"{name}.example.com"),
        report_error=errors.append,
        report_info=lambda _message: None,
        report_success=lambda _message: None,
        pause=pause,
    )

    assert calls == ["save", "install", "enable"]
    assert errors == []
    pause.assert_called_once_with("Нажмите Enter")


def test_invalid_domain_stops_before_install():
    state = AppState(protocols={"trusttunnel": PluginState()})
    calls: list[str] = []
    errors: list[str] = []

    run_lifecycle_action(
        state,
        TrustTunnelPlugin(),
        state.protocols["trusttunnel"],
        _activation_app(calls=calls),
        ask=Mock(return_value="https://bad domain"),
        report_error=errors.append,
        report_info=lambda _message: None,
        report_success=lambda _message: None,
        pause=Mock(),
    )

    assert calls == []
    assert errors == [
        "Для trusttunnel нужен корректный домен без схемы и пробелов",
    ]


def test_activation_error_is_reported_inside_tui_instead_of_reaching_root():
    state = AppState(protocols={"naive": PluginState()})
    app = _activation_app()
    app.protocols.enable = Mock(side_effect=ValueError("certificate failed"))
    errors: list[str] = []

    run_lifecycle_action(
        state,
        NaivePlugin(),
        state.protocols["naive"],
        app,
        ask=Mock(return_value="naive.example.com"),
        report_error=errors.append,
        report_info=lambda _message: None,
        report_success=lambda _message: None,
        pause=Mock(),
    )

    assert errors == [
        "Ошибка настройки или активации naive: certificate failed",
    ]


def test_shadowtls_collects_mandatory_handshake_sni_before_activation():
    state = AppState(protocols={"shadowtls": PluginState()})
    app = _activation_app()

    with patch(
        "hydra.ui._menus.shadowtls_settings.choose_shadowtls_sni",
        return_value="www.example.com",
    ):
        assert prepare_interactive_activation(
            state,
            ShadowTLSPlugin(),
            app,
            ask=Mock(),
            report_error=Mock(),
        )

    app.plugin_command.assert_called_once_with(
        state,
        "shadowtls",
        "set_handshake_sni",
        value="www.example.com",
    )
