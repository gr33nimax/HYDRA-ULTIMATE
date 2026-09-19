"""Меню протокола: установка, отказ при неполной установке, регистрация."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from hydra.contracts import JsonValue
from hydra.core.state import AppState
from hydra.core.state_models import PluginState
from hydra.plugins.vless_cdn.plugin import PROTOCOL_NAME, VlessCdnPlugin
from hydra.services.vless_cdn_install import InstallOutcome
from hydra.ui._menus import extended_protocol_vless_cdn as menu
from hydra.ui._menus import plugin_dispatch

PROVISIONED: dict[str, JsonValue] = {
    "cdn_domain": "cdn.example.com",
    "origin_host": "origin.example.com",
    "xhttp_path": "/api/media/session",
    "core_port": 20449,
    "cert_file": "/etc/letsencrypt/live/origin.example.com/fullchain.pem",
    "key_file": "/etc/letsencrypt/live/origin.example.com/privkey.pem",
    "encryption_private_key": "private-key",
    "encryption_public_key": "public-key",
}


def _answers(*values: str):
    """Ответы оператора по порядку; дальше пустые нажатия Enter."""
    pending = list(values)
    return lambda *args, **kwargs: pending.pop(0) if pending else ""


def test_the_protocol_has_its_own_menu():
    handler = plugin_dispatch.SPECIAL_PLUGIN_MENUS.get("vless_cdn")

    assert handler is not None, "без записи в диспетчере оператор протокол не увидит"
    assert callable(handler)


def test_enabling_without_installation_is_refused_before_the_mux():
    plugin = VlessCdnPlugin()
    state = AppState(protocols={PROTOCOL_NAME: PluginState(enabled=False, config={})})

    with pytest.raises(ValueError, match="не установлен"):
        plugin.on_enable(state)


def test_enabling_a_provisioned_protocol_passes():
    plugin = VlessCdnPlugin()
    state = AppState(protocols={PROTOCOL_NAME: PluginState(config=dict(PROVISIONED))})

    plugin.on_enable(state)


def test_a_half_provisioned_protocol_names_what_is_missing():
    plugin = VlessCdnPlugin()
    config = {key: value for key, value in PROVISIONED.items() if key != "cert_file"}
    state = AppState(protocols={PROTOCOL_NAME: PluginState(config=config)})

    with pytest.raises(ValueError, match="cert_file"):
        plugin.on_enable(state)


def test_install_forwards_a_bad_answer_to_the_application_use_case():
    state = AppState()
    app = MagicMock()
    app.provision_vless_cdn.return_value = InstallOutcome(ok=False, detail="Origin-имя некорректно")
    messages: list[str] = []

    with (
        patch.object(menu, "prompt", side_effect=_answers("cdn.example.com", "bad host")),
        patch.object(menu, "error", side_effect=lambda text: messages.append(str(text))),
        patch.object(menu, "info"),
        patch.object(menu, "success"),
    ):
        menu._install(state, MagicMock(), app)

    app.provision_vless_cdn.assert_called_once_with(
        state,
        cdn_domain="cdn.example.com",
        origin_host="bad host",
    )
    assert any("Origin-имя" in text for text in messages)
    assert state.protocols.get(PROTOCOL_NAME) is None


def test_install_delegates_the_entire_runtime_transaction_to_application():
    state = AppState()
    app = MagicMock()
    app.provision_vless_cdn.return_value = InstallOutcome(
        ok=True,
        cdn_domain="cdn.example.com",
        origin_host="origin.example.com",
        xhttp_path="/api/media/session",
        core_port=20449,
        certificate_until="2027-01-02 03:04 UTC",
    )

    with (
        patch.object(menu, "prompt", side_effect=_answers("cdn.example.com", "origin.example.com")),
        patch.object(menu, "success"),
        patch.object(menu, "info"),
        patch.object(menu, "error") as reported,
    ):
        menu._install(state, MagicMock(), app)

    app.provision_vless_cdn.assert_called_once_with(
        state,
        cdn_domain="cdn.example.com",
        origin_host="origin.example.com",
    )
    reported.assert_not_called()


def test_install_reports_a_timer_failure_from_application():
    state = AppState()
    app = MagicMock()
    app.provision_vless_cdn.return_value = InstallOutcome(ok=False, detail="site timer installation failed")
    messages: list[str] = []

    with (
        patch.object(menu, "prompt", side_effect=_answers("cdn.example.com", "origin.example.com")),
        patch.object(menu, "error", side_effect=lambda text: messages.append(str(text))),
        patch.object(menu, "info"),
        patch.object(menu, "success"),
    ):
        menu._install(state, MagicMock(), app)

    assert any("timer" in text for text in messages)


def test_install_reports_an_apply_failure_from_application():
    state = AppState()
    app = MagicMock()
    app.provision_vless_cdn.return_value = InstallOutcome(ok=False, detail="caddy validate failed")
    messages: list[str] = []

    with (
        patch.object(menu, "prompt", side_effect=_answers("cdn.example.com", "origin.example.com")),
        patch.object(menu, "error", side_effect=lambda text: messages.append(str(text))),
        patch.object(menu, "info"),
        patch.object(menu, "success"),
    ):
        menu._install(state, MagicMock(), app)

    assert any("caddy validate failed" in text for text in messages)
