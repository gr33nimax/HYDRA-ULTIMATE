"""VLESS CDN must not bypass the application lifecycle boundary."""

from __future__ import annotations

from unittest.mock import MagicMock

from hydra.core.state_models import AppState, PluginState
from hydra.plugins.vless_cdn.plugin import PROTOCOL_NAME
from hydra.services import application
from hydra.services.application import ApplicationService
from hydra.services.vless_cdn_install import InstallOutcome


def _app(*, apply: bool = True) -> tuple[ApplicationService, MagicMock, MagicMock, MagicMock]:
    protocols = MagicMock()
    apply_config = MagicMock(return_value=apply)
    admin = MagicMock()
    app = ApplicationService(
        users=MagicMock(),
        protocols=protocols,
        apply_config=apply_config,
        last_apply_error=lambda: "caddy validate failed",
        plugin_statuses=MagicMock(),
        admin=admin,
    )
    return app, protocols, apply_config, admin


def _stage(state: AppState, **_kwargs: object) -> InstallOutcome:
    state.protocols[PROTOCOL_NAME] = PluginState(
        config={"cdn_domain": "cdn.example.com", "cert_file": "cert.pem"},
    )
    return InstallOutcome(ok=True, cdn_domain="cdn.example.com")


def test_provision_rolls_back_state_when_apply_fails(monkeypatch) -> None:
    app, _protocols, apply_config, _admin = _app(apply=False)
    state = AppState()
    timer = MagicMock()

    monkeypatch.setattr(application, "install_protocol", _stage)
    monkeypatch.setattr(application, "install_site_timer", timer)

    outcome = app.provision_vless_cdn(
        state,
        cdn_domain="cdn.example.com",
        origin_host="origin.example.com",
    )

    assert outcome.ok is False
    assert "caddy validate failed" in outcome.detail
    assert PROTOCOL_NAME not in state.protocols
    timer.assert_not_called()
    assert apply_config.call_count == 2, "staged config and restored snapshot are both applied"


def test_provision_persists_page_metadata_only_after_the_page_is_built(monkeypatch) -> None:
    app, _protocols, _apply_config, admin = _app()
    state = AppState()
    timer = MagicMock(return_value=True)
    page = MagicMock()

    monkeypatch.setattr(application, "install_protocol", _stage)
    monkeypatch.setattr(application, "install_site_timer", timer)
    monkeypatch.setattr(application, "refresh_site", page)

    outcome = app.provision_vless_cdn(
        state,
        cdn_domain="cdn.example.com",
        origin_host="origin.example.com",
    )

    assert outcome.ok is True
    timer.assert_called_once_with()
    page.assert_called_once_with(state)
    assert admin.save_state.call_count == 2


def test_failed_timer_cleanup_restores_the_protocol(monkeypatch) -> None:
    app, protocols, apply_config, _admin = _app()
    state = AppState(protocols={PROTOCOL_NAME: PluginState(config={"cert_file": "cert.pem"})})

    def uninstall(target: AppState, _name: str) -> bool:
        target.protocols[PROTOCOL_NAME].config = {}
        return True

    protocols.uninstall.side_effect = uninstall
    monkeypatch.setattr(application, "remove_site_timer", lambda: False)
    restore_timer = MagicMock(return_value=True)
    monkeypatch.setattr(application, "install_site_timer", restore_timer)

    assert app.uninstall_vless_cdn(state) is False
    assert state.protocols[PROTOCOL_NAME].config == {"cert_file": "cert.pem"}
    restore_timer.assert_called_once_with()
    assert apply_config.call_count == 1
