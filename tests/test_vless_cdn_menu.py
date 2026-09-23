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


def test_toggle_delegates_to_the_cdn_application_operation():
    app = MagicMock()
    enabled = PluginState(enabled=True)

    getattr(menu, "_set_enabled")(AppState(), enabled, app)

    app.disable_vless_cdn.assert_called_once()
    app.protocols.disable.assert_not_called()


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


# ── Пункт режима медиа и ввод источника ────────────────────────────────────────


def _provisioned_state(**overrides: JsonValue) -> AppState:
    config: dict[str, JsonValue] = dict(PROVISIONED)
    config.update(overrides)
    return AppState(protocols={PROTOCOL_NAME: PluginState(enabled=True, config=config)})


def test_the_menu_offers_the_media_mode_item_once_provisioned():
    state = _provisioned_state()
    app = MagicMock()
    app.admin.load_state.return_value = state
    captured: dict[str, list[tuple[str, str, str]]] = {}

    def fake_menu(options, title):
        captured["options"] = options
        return "0"  # выходим сразу — важен состав пунктов и панель

    with (
        patch.object(menu, "clear"),
        patch.object(menu, "menu", side_effect=fake_menu),
        patch.object(menu, "protocol_status_panel") as panel,
    ):
        menu._menu_vless_cdn(state, VlessCdnPlugin(), app)

    keys = [key for key, _, _ in captured["options"]]
    assert "6" in keys, "без пункта режим не переключить"
    assert "5" in keys

    # Панель обязана показать режим и его состояние: иначе настройка невидимая.
    details = dict(panel.call_args.kwargs["details"])
    assert details["Режим медиа"] == "Видео"
    assert "НЕ ЗАДАН" in details["Источник"]


def test_the_panel_shows_the_photo_state_instead_of_the_source():
    state = _provisioned_state(media_mode="photo", image_refresh_error="download failed")
    app = MagicMock()
    app.admin.load_state.return_value = state

    with (
        patch.object(menu, "clear"),
        patch.object(menu, "menu", return_value="0"),
        patch.object(menu, "protocol_status_panel") as panel,
    ):
        menu._menu_vless_cdn(state, VlessCdnPlugin(), app)

    details = dict(panel.call_args.kwargs["details"])
    assert details["Режим медиа"] == "Фото"
    assert "download failed" in details["Фото региона"], "ошибка загрузки фото должна быть видна"


@pytest.mark.parametrize(("choice", "expected"), [("1", "video"), ("2", "photo")])
def test_the_mode_item_applies_the_choice(choice, expected):
    state = AppState()
    app = MagicMock()
    app.set_vless_cdn_mode.return_value = True
    messages: list[str] = []

    with (
        patch.object(menu, "menu", return_value=choice),
        patch.object(menu, "prompt"),
        patch.object(menu, "success", side_effect=lambda text: messages.append(str(text))),
    ):
        menu._set_mode(state, MagicMock(), app)

    app.set_vless_cdn_mode.assert_called_once_with(state, expected)
    assert messages, "оператор должен увидеть, что режим сменился"


def test_backing_out_of_the_mode_item_changes_nothing():
    app = MagicMock()

    with patch.object(menu, "menu", return_value="0"), patch.object(menu, "prompt"):
        menu._set_mode(AppState(), MagicMock(), app)

    app.set_vless_cdn_mode.assert_not_called()


def test_the_mode_item_reports_a_failed_switch():
    app = MagicMock()
    app.set_vless_cdn_mode.return_value = False
    messages: list[str] = []

    with (
        patch.object(menu, "menu", return_value="2"),
        patch.object(menu, "prompt"),
        patch.object(menu, "error", side_effect=lambda text: messages.append(str(text))),
    ):
        menu._set_mode(AppState(), MagicMock(), app)

    assert messages, "молчаливый отказ выглядел бы как успех"


def test_the_source_prompt_documents_the_format_and_reports_refusal():
    state = AppState()
    app = MagicMock()
    app.set_vless_cdn_camera.return_value = False
    shown: list[str] = []
    errors: list[str] = []

    with (
        patch.object(menu, "prompt", return_value="https://www.youtube.com/watch?v=abc"),
        patch.object(menu, "info", side_effect=lambda text: shown.append(str(text))),
        patch.object(menu, "error", side_effect=lambda text: errors.append(str(text))),
    ):
        menu._set_camera(state, MagicMock(), app)

    app.set_vless_cdn_camera.assert_called_once_with(state, "https://www.youtube.com/watch?v=abc")
    text = "\n".join(shown)
    assert "rtsp://" in text and "m3u8" in text, "формат должен быть показан до ввода"
    assert "H264" in text, "про кодек иначе не узнать"
    assert "YouTube" in text and "MJPEG" in text, "отказ объявляется заранее, а не после"
    assert errors and "YouTube" in errors[0]
