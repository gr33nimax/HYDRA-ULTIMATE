"""Меню протокола: установка, отказ при неполной установке, регистрация."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hydra.contracts import JsonValue
from hydra.core.state import AppState
from hydra.core.state_models import PluginState, User
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


def test_install_refuses_a_bad_answer_and_touches_nothing():
    state = AppState()
    messages: list[str] = []

    with (
        patch.object(menu, "prompt", side_effect=_answers("cdn.example.com", "bad host")),
        patch.object(menu, "error", side_effect=lambda text: messages.append(str(text))),
        patch.object(menu, "info"),
        patch.object(menu, "success"),
        patch.object(menu, "install_site_timer") as timer,
    ):
        menu._install(state, MagicMock(), MagicMock())

    assert any("Origin-имя" in text for text in messages)
    timer.assert_not_called()
    assert state.protocols.get(PROTOCOL_NAME) is None


def test_install_wires_the_certificate_then_the_timer_then_the_page(tmp_path):
    state = AppState()
    app = MagicMock()
    app.admin.save_state.return_value = True
    order: list[str] = []

    def fake_install(target: AppState, *, cdn_domain: str, origin_host: str) -> InstallOutcome:
        order.append("certificate")
        target.protocols[PROTOCOL_NAME] = PluginState(
            config={**PROVISIONED, "cdn_domain": cdn_domain, "origin_host": origin_host},
        )
        return InstallOutcome(
            ok=True,
            cdn_domain=cdn_domain,
            origin_host=origin_host,
            xhttp_path="/api/media/session",
            core_port=20449,
            certificate_until="2027-01-02 03:04 UTC",
        )

    def fake_timer() -> bool:
        order.append("timer")
        return True

    def fake_refresh(*_args, **_kwargs) -> Path:
        order.append("page")
        return tmp_path / "index.html"

    with (
        patch.object(menu, "prompt", side_effect=_answers("cdn.example.com", "origin.example.com")),
        patch.object(menu, "install_protocol", side_effect=fake_install),
        patch.object(menu, "install_site_timer", side_effect=fake_timer),
        patch.object(menu, "refresh_site", side_effect=fake_refresh),
        patch.object(menu, "success"),
        patch.object(menu, "info"),
        patch.object(menu, "error") as reported,
    ):
        menu._install(state, MagicMock(), app)

    assert order == ["certificate", "timer", "page"], "порядок шагов установки"
    reported.assert_not_called()
    app.admin.save_state.assert_called_once()


def test_install_stops_when_the_timer_cannot_be_installed(tmp_path):
    state = AppState()
    app = MagicMock()
    app.admin.save_state.return_value = True
    messages: list[str] = []

    with (
        patch.object(menu, "prompt", side_effect=_answers("cdn.example.com", "origin.example.com")),
        patch.object(
            menu,
            "install_protocol",
            side_effect=lambda target, **_kwargs: InstallOutcome(
                ok=True,
                cdn_domain="cdn.example.com",
                origin_host="origin.example.com",
                xhttp_path="/api/media/session",
                core_port=20449,
            ),
        ),
        patch.object(menu, "install_site_timer", return_value=False),
        patch.object(menu, "refresh_site") as refresh,
        patch.object(menu, "error", side_effect=lambda text: messages.append(str(text))),
        patch.object(menu, "info"),
        patch.object(menu, "success"),
    ):
        menu._install(state, MagicMock(), app)

    refresh.assert_not_called()
    assert any("таймер" in text for text in messages)


def test_profile_needs_a_user_to_belong_to():
    state = AppState(protocols={PROTOCOL_NAME: PluginState(config=dict(PROVISIONED))})

    with pytest.raises(ValueError, match="активного пользователя"):
        menu._first_user(state)

    state.users = [User(email="reader@example.com", uuid="u1", blocked=True)]
    with pytest.raises(ValueError, match="активного пользователя"):
        menu._first_user(state)

    state.users.append(User(email="live@example.com", uuid="u2"))
    assert menu._first_user(state).email == "live@example.com"
