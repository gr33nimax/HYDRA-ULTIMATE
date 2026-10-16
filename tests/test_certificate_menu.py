"""Certificate TUI delegates to the application port and confirms destructive actions."""
from unittest.mock import MagicMock, patch

import pytest

from hydra.core.state_models import AppState
from hydra.services.admin import AdminCommandResult
from hydra.services.certificate_management import IssuedCertificate
from hydra.ui import menus
from hydra.ui._menus import monitoring, monitoring_certificates as controller


@pytest.fixture
def screen(monkeypatch):
    # Restore child function bindings propagated by the preceding facade monkeypatch test.
    monitoring._sync_controller_dependencies()
    for name in ("clear", "panel", "info", "warn", "error", "success", "confirm", "menu", "prompt"):
        monkeypatch.setattr(controller, name, MagicMock())
    return controller


def _certificate(*, managed=True):
    return IssuedCertificate("vpn.example.org", ("vpn.example.org",), "/etc/letsencrypt/live/vpn.example.org/fullchain.pem",
                             "ok", "2026-12-01T00:00:00+00:00", 60, ("anytls", "subscriptions"), managed)


def test_certificate_submenu_is_next_to_sync_agent():
    state = AppState()
    app = MagicMock()
    app.admin.load_state.return_value = state
    app.admin.unit_active.return_value = False
    with (
        patch.object(menus, "clear"), patch.object(menus, "panel"),
        patch.object(menus, "menu", side_effect=["4", "0"]) as choose,
        patch.object(monitoring, "_menu_certificates") as submenu,
    ):
        getattr(menus, "_menu_service_settings")(state, app)
    submenu.assert_called_once_with(state, app)
    assert any(item[0] == "4" and "сертификаты" in item[1] for item in choose.call_args_list[0].args[0])


def test_inventory_refresh_does_not_issue_or_delete_certificates(screen):
    app = MagicMock()
    app.certificates.inventory.return_value = [_certificate()]
    screen.menu.side_effect = ["r", "0"]
    screen._menu_certificates(AppState(), app)
    assert app.certificates.inventory.call_count == 2
    app.certificates.reissue.assert_not_called()
    app.certificates.delete.assert_not_called()


def test_reissue_requires_confirmation(screen):
    app = MagicMock()
    app.certificates.reissue.return_value = AdminCommandResult(True, message="renewed")
    screen.menu.return_value = "1"
    screen.confirm.return_value = False
    screen._certificate_detail(_certificate(), app)
    app.certificates.reissue.assert_not_called()
    screen.confirm.return_value = True
    screen._certificate_detail(_certificate(), app)
    app.certificates.reissue.assert_called_once_with("vpn.example.org")
    screen.success.assert_called_once_with("renewed")


def test_used_certificate_delete_requires_exact_typed_name(screen):
    app = MagicMock()
    screen.menu.return_value = "2"
    screen.prompt.side_effect = ["wrong", ""]
    screen._certificate_detail(_certificate(), app)
    app.certificates.delete.assert_not_called()
    app.certificates.delete.return_value = AdminCommandResult(True, message="deleted")
    screen.prompt.side_effect = ["vpn.example.org", ""]
    screen._certificate_detail(_certificate(), app)
    app.certificates.delete.assert_called_once_with("vpn.example.org", confirmation="vpn.example.org")
    warnings = [call.args[0] for call in screen.warn.call_args_list]
    assert any("anytls" in text for text in warnings)
    assert any("Автопроверка" in text for text in warnings)


def test_external_tls_file_has_no_destructive_actions(screen):
    app = MagicMock()
    screen._certificate_detail(_certificate(managed=False), app)
    screen.menu.assert_not_called()
    app.certificates.delete.assert_not_called()
    app.certificates.reissue.assert_not_called()


def test_inventory_failure_returns_to_caller_without_mutation(screen):
    app = MagicMock()
    app.certificates.inventory.side_effect = OSError("denied")
    screen._menu_certificates(AppState(), app)
    screen.error.assert_called_once()
    screen.menu.assert_not_called()
    app.certificates.delete.assert_not_called()
