"""VLESS CDN must not bypass the application lifecycle boundary."""

from __future__ import annotations

from unittest.mock import MagicMock

from hydra.core.state_models import AppState, PluginState
from hydra.plugins.vless_cdn.plugin import PROTOCOL_NAME
from hydra.services import application
from hydra.services.application import ApplicationService
from hydra.services.vless_cdn_install import InstallOutcome, VlessCdnLifecycleOperations


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


def test_generic_uninstall_removes_the_cdn_timer(monkeypatch) -> None:
    operations = MagicMock()
    operations.uninstall_plugin.return_value = True
    remove_timer = MagicMock(return_value=True)

    monkeypatch.setattr("hydra.services.vless_cdn_install.remove_site_timer", remove_timer)

    assert VlessCdnLifecycleOperations(operations).uninstall_plugin(AppState(), PROTOCOL_NAME) is True
    remove_timer.assert_called_once_with()
    operations.uninstall_plugin.assert_called_once_with(AppState(), PROTOCOL_NAME)


def test_generic_enable_starts_the_cdn_timer_and_page(monkeypatch) -> None:
    operations = MagicMock()
    operations.enable.return_value = True
    timer = MagicMock(return_value=True)
    page = MagicMock()
    state = AppState(protocols={PROTOCOL_NAME: PluginState(enabled=True)})

    monkeypatch.setattr("hydra.services.vless_cdn_install.install_site_timer", timer)
    monkeypatch.setattr("hydra.services.vless_cdn_install.refresh_site", page)

    assert VlessCdnLifecycleOperations(operations).enable(state, PROTOCOL_NAME) is True
    timer.assert_called_once_with()
    page.assert_called_once_with(state)


def test_enable_installs_timer_and_refreshes_page(monkeypatch) -> None:
    app, protocols, _apply_config, _admin = _app()
    state = AppState(protocols={PROTOCOL_NAME: PluginState(enabled=False, config={"cert_file": "cert.pem"})})
    timer = MagicMock(return_value=True)
    page = MagicMock()

    def enable(target: AppState, _name: str) -> bool:
        target.protocols[PROTOCOL_NAME].enabled = True
        return True

    protocols.enable.side_effect = enable
    monkeypatch.setattr(application, "install_site_timer", timer)
    monkeypatch.setattr(application, "refresh_site", page)

    assert app.enable_vless_cdn(state) is True
    timer.assert_called_once_with()
    page.assert_called_once_with(state)


def test_enable_rolls_back_when_the_page_fails(monkeypatch) -> None:
    app, protocols, apply_config, admin = _app()
    state = AppState(protocols={PROTOCOL_NAME: PluginState(enabled=False, config={"cert_file": "cert.pem"})})
    cleanup = MagicMock(return_value=True)

    def enable(target: AppState, _name: str) -> bool:
        target.protocols[PROTOCOL_NAME].enabled = True
        return True

    protocols.enable.side_effect = enable
    monkeypatch.setattr(application, "install_site_timer", lambda: True)
    monkeypatch.setattr(application, "refresh_site", MagicMock(side_effect=RuntimeError("page failed")))
    monkeypatch.setattr(application, "remove_site_timer", cleanup)

    assert app.enable_vless_cdn(state) is False
    assert state.protocols[PROTOCOL_NAME].enabled is False
    cleanup.assert_called_once_with()
    assert apply_config.called
    assert admin.save_state.called


def test_disable_restores_timer_when_protocol_disable_fails(monkeypatch) -> None:
    app, protocols, apply_config, admin = _app()
    state = AppState(protocols={PROTOCOL_NAME: PluginState(enabled=True, config={"cert_file": "cert.pem"})})
    restore_timer = MagicMock(return_value=True)

    protocols.disable.return_value = False
    monkeypatch.setattr(application, "remove_site_timer", lambda: True)
    monkeypatch.setattr(application, "install_site_timer", restore_timer)

    assert app.disable_vless_cdn(state) is False
    assert state.protocols[PROTOCOL_NAME].enabled is True
    restore_timer.assert_called_once_with()
    assert apply_config.called
    assert admin.save_state.called


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
