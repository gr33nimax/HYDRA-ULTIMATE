from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import ANY, MagicMock, patch

from hydra.core.state_models import AppState, PluginState
from hydra.plugins.base import PluginStatus
from hydra.plugins.vless_xhttp import presets
from hydra.ui._menus import extended_protocol_vless, vless_xhttp_profiles
from hydra.ui._menus.plugin_dispatch import SPECIAL_PLUGIN_MENUS


def _state() -> AppState:
    return AppState(
        protocols={
            "vless": PluginState(
                installed=True,
                enabled=True,
                config={
                    "domain": "xhttp.example.com",
                    "xhttp_path": "/xhttp",
                    "xhttp_mode": "stream-up",
                },
            ),
        },
    )


def _plugin() -> SimpleNamespace:
    return SimpleNamespace(
        meta=SimpleNamespace(
            name="vless",
            display_name="VLESS + XHTTP",
            description="VLESS over XHTTP",
        ),
    )


def _app(state: AppState) -> MagicMock:
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.protocols.status.return_value = PluginStatus(
        installed=True,
        enabled=True,
        running=True,
        port=443,
    )
    app.plugin_query.return_value = {
        "preset": "balanced",
        "mode": "stream-up",
        "path": "/xhttp",
    }
    app.plugin_command.return_value = True
    return app


def test_vless_uses_a_specialised_anytls_style_menu():
    state = _state()
    app = _app(state)
    captured: dict[str, object] = {}

    def choose(options, title):
        captured["options"] = options
        captured["title"] = title
        return "0"

    with patch.object(extended_protocol_vless, "clear"), patch.object(
        extended_protocol_vless,
        "protocol_status_panel",
    ) as status_panel, patch.object(
        extended_protocol_vless,
        "menu",
        side_effect=choose,
    ):
        extended_protocol_vless._menu_vless(state, _plugin(), app)

    assert "vless" in SPECIAL_PLUGIN_MENUS
    labels = [row[1] for row in captured["options"]]
    assert labels[:4] == [
        "⏸️  Выключить",
        "📊 Трафик протокола",
        "🌐 Профиль транспорта",
        "⚙️  Настройки XHTTP",
    ]
    details = status_panel.call_args.kwargs["details"]
    assert ("Домен", "xhttp.example.com") in details
    assert ("TLS-режим", ANY) not in details or any(
        label == "TLS-режим" for label, _value in details
    )
    assert ("Режим XHTTP", "stream-up") in details
    assert any(label == "Профиль XHTTP" for label, _value in details)
    app.plugin_query.assert_called_once_with(
        "vless",
        "get_tuning",
        state=state,
    )


def test_vless_profile_menu_applies_a_named_profile_directly():
    state = _state()
    app = _app(state)

    with patch.object(
        vless_xhttp_profiles,
        "clear",
    ), patch.object(
        vless_xhttp_profiles,
        "panel",
    ) as profile_panel, patch.object(
        vless_xhttp_profiles,
        "menu",
        side_effect=["2", "0"],
    ), patch.object(
        vless_xhttp_profiles,
        "prompt",
        return_value="",
    ):
        vless_xhttp_profiles.open_menu(state, app)

    profile_panel.assert_called()
    app.plugin_command.assert_called_once_with(
        state,
        "vless",
        "set_preset",
        preset=list(presets.PRESETS)[1],
    )


def test_vless_profile_menu_reports_transaction_failure():
    state = _state()
    app = _app(state)
    app.plugin_command.return_value = False
    app.apply_error.return_value = "применение откатилось"

    with patch.object(
        vless_xhttp_profiles,
        "clear",
    ), patch.object(
        vless_xhttp_profiles,
        "panel",
    ), patch.object(
        vless_xhttp_profiles,
        "menu",
        side_effect=["2", "0"],
    ), patch.object(
        vless_xhttp_profiles,
        "prompt",
        return_value="",
    ), patch.object(
        vless_xhttp_profiles,
        "error",
    ) as report_error:
        vless_xhttp_profiles.open_menu(state, app)

    report_error.assert_called_once_with("применение откатилось")


def test_vless_specialised_menu_opens_profiles_directly():
    state = _state()
    app = _app(state)

    with patch.object(
        extended_protocol_vless,
        "clear",
    ), patch.object(
        extended_protocol_vless,
        "protocol_status_panel",
    ), patch.object(
        extended_protocol_vless,
        "menu",
        side_effect=["3", "0"],
    ), patch.object(
        extended_protocol_vless,
        "open_profiles_menu",
    ) as open_profiles:
        extended_protocol_vless._menu_vless(state, _plugin(), app)

    open_profiles.assert_called_once_with(state, app)


def test_vless_specialised_menu_keeps_advanced_settings_available():
    state = _state()
    app = _app(state)
    plugin = _plugin()

    with patch.object(
        extended_protocol_vless,
        "clear",
    ), patch.object(
        extended_protocol_vless,
        "protocol_status_panel",
    ), patch.object(
        extended_protocol_vless,
        "menu",
        side_effect=["4", "0"],
    ), patch.object(
        extended_protocol_vless,
        "open_settings_menu",
    ) as open_settings:
        extended_protocol_vless._menu_vless(state, plugin, app)

    open_settings.assert_called_once_with(state, plugin, app)


def test_vless_reinstall_failure_is_reported_without_leaving_the_tui():
    state = _state()
    app = _app(state)
    app.protocols.reinstall.side_effect = ValueError("public IP is unknown")

    with patch.object(
        extended_protocol_vless,
        "clear",
    ), patch.object(
        extended_protocol_vless,
        "protocol_status_panel",
    ), patch.object(
        extended_protocol_vless,
        "menu",
        side_effect=["8", "0"],
    ), patch.object(
        extended_protocol_vless,
        "confirm",
        return_value=True,
    ), patch.object(
        extended_protocol_vless,
        "prompt",
    ), patch.object(
        extended_protocol_vless,
        "error",
    ) as report_error:
        extended_protocol_vless._menu_vless(state, _plugin(), app)

    report_error.assert_called_once_with(
        "Ошибка переустановки VLESS: public IP is unknown",
    )
