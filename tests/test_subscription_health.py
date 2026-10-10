from subprocess import CompletedProcess
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from hydra.core.state_models import AppState
from hydra.services.admin import AdminCommandResult
from hydra.services.subscription_health import subscription_health
from hydra.ui._menus import users_subscription


@pytest.mark.parametrize("route_ok", [True, False])
def test_health_checks_backend_then_actual_local_sni_route(monkeypatch, route_ok):
    monkeypatch.setattr("hydra.services.subscription_health.find_any_cert", lambda state: ("/cert.pem", "/key.pem"))
    state = AppState()
    state.network.sub_domain = "sub.example.test"
    commands = []

    def run(args, **kwargs):
        assert kwargs == {"timeout": 4, "text": True}
        commands.append(args)
        if len(commands) == 2 and not route_ok:
            return CompletedProcess(args, 7, "", "Connection refused")
        return CompletedProcess(args, 0, '{"status":"ok"}', "")

    result = subscription_health(state, host=SimpleNamespace(run=run))
    assert result.ok == route_ok
    assert result.code == ("ready" if route_ok else "routing_unavailable")
    assert len(commands) == 2
    assert commands[0][-1] == "https://sub.example.test:9443/healthz"
    assert commands[1][-1] == "https://sub.example.test:443/healthz"
    assert "sub.example.test:443:127.0.0.1:443" in commands[1]
    assert "--insecure" not in commands[0] and "--cacert" in commands[0]
    assert "--noproxy" in commands[0]


@pytest.mark.parametrize("stdout", ["not JSON", '{"status":"other"}'])
def test_an_unrelated_listener_cannot_produce_a_green_status(monkeypatch, stdout):
    monkeypatch.setattr("hydra.services.subscription_health.find_any_cert", lambda state: ("/cert.pem", "/key.pem"))
    state = AppState()
    state.network.domain = "sub.example.test"
    host = SimpleNamespace(run=lambda args, **kwargs: CompletedProcess(args, 0, stdout, ""))
    result = subscription_health(state, host=host)
    assert not result.ok and result.code == "backend_unavailable"


def test_active_systemd_unit_with_dead_https_is_not_green():
    app = MagicMock()
    app.admin.unit_active.return_value = True
    app.admin.subscription_health.return_value = AdminCommandResult(False, "backend_unavailable")
    app.admin.subscription_certificate.return_value = ("/cert.pem", "/key.pem")
    app.admin.subscription_public_host.return_value = "sub.example.test"
    status, *_ = users_subscription._subscription_status(AppState(), app)
    assert "9443 не отвечает" in status and "🟢" not in status


def test_restart_repairs_broken_route_and_reports_success_only_after_https(monkeypatch):
    app = MagicMock()
    app.admin.restart_unit.return_value = True
    app.admin.subscription_health.side_effect = [
        AdminCommandResult(False, "routing_unavailable"), AdminCommandResult(True, "ready"),
    ]
    app.admin.refresh_subscription_routing.return_value = True
    messages = []
    monkeypatch.setattr(users_subscription, "prompt", lambda *args: "")
    monkeypatch.setattr(users_subscription, "success", messages.append)
    state = AppState()
    users_subscription._restart_subscription_server(state, app, has_certificate=True)
    app.admin.refresh_subscription_routing.assert_called_once_with(state)
    assert messages == ["Сервер подписок отвечает по HTTPS"]


def test_restart_of_a_hung_process_does_not_report_false_success(monkeypatch):
    app = MagicMock()
    app.admin.restart_unit.return_value = True
    app.admin.subscription_health.return_value = AdminCommandResult(False, "backend_unavailable", detail="timeout")
    success = MagicMock()
    errors = []
    monkeypatch.setattr(users_subscription, "prompt", lambda *args: "")
    monkeypatch.setattr(users_subscription, "success", success)
    monkeypatch.setattr(users_subscription, "error", errors.append)
    users_subscription._restart_subscription_server(AppState(), app, has_certificate=True)
    success.assert_not_called()
    assert "timeout" in errors
