from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hydra.core.state import AppState
from hydra.ui import menus


def _state() -> AppState:
    state = AppState()
    state.network.sub_domain = "sub.example.com"
    return state


def _application(result):
    obtain = MagicMock(return_value=result)
    return (
        SimpleNamespace(
            admin=SimpleNamespace(obtain_subscription_certificate=obtain),
        ),
        obtain,
    )


def test_subscription_certificate_uses_injected_admin_boundary():
    result = SimpleNamespace(ok=True, code="issued", message="", detail="")
    app, obtain = _application(result)
    with patch.object(menus, "success") as success_message:
        assert menus._obtain_cert_for_sub(_state(), app) is True

    obtain.assert_called_once_with("sub.example.com")
    success_message.assert_called_once_with("Сертификат успешно получен!")


def test_subscription_certificate_reports_normalized_admin_failure():
    result = SimpleNamespace(
        ok=False,
        code="certbot_failed",
        message="certbot failed",
        detail="challenge rejected",
    )
    app, obtain = _application(result)
    with patch.object(menus, "error") as error_message:
        assert menus._obtain_cert_for_sub(_state(), app) is False

    obtain.assert_called_once_with("sub.example.com")
    error_message.assert_called_once_with("Ошибка работы certbot!")
