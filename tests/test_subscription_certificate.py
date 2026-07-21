from contextlib import nullcontext
from unittest.mock import MagicMock, patch

from hydra.core.state import AppState
from hydra.ui import menus


def _state() -> AppState:
    state = AppState()
    state.network.sub_domain = "sub.example.com"
    return state


def test_subscription_certbot_stops_and_restores_caddy_l4():
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        result = MagicMock(returncode=0, stdout="", stderr="")
        if command[:3] == ["systemctl", "is-active", "caddy-l4"]:
            result.stdout = "active\n"
        return result

    with (
        patch.object(menus.Path, "exists", return_value=False),
        patch("shutil.which", return_value="/usr/bin/certbot"),
        patch("hydra.utils.firewall.temporary_open_port", return_value=nullcontext()),
        patch.object(menus.HOST, "run", side_effect=fake_run),
    ):
        assert menus._obtain_cert_for_sub(_state()) is True

    stop_index = calls.index(["systemctl", "stop", "caddy-l4"])
    certbot_index = next(i for i, command in enumerate(calls) if command[0] == "certbot")
    start_index = calls.index(["systemctl", "start", "caddy-l4"])
    assert stop_index < certbot_index < start_index


def test_subscription_certbot_restores_services_after_exception():
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        result = MagicMock(returncode=0, stdout="", stderr="")
        if command[:3] == ["systemctl", "is-active", "caddy-l4"]:
            result.stdout = "active\n"
        if command and command[0] == "certbot":
            raise OSError("certbot crashed")
        return result

    with (
        patch.object(menus.Path, "exists", return_value=False),
        patch("shutil.which", return_value="/usr/bin/certbot"),
        patch("hydra.utils.firewall.temporary_open_port", return_value=nullcontext()),
        patch.object(menus.HOST, "run", side_effect=fake_run),
    ):
        assert menus._obtain_cert_for_sub(_state()) is False

    assert ["systemctl", "start", "caddy-l4"] in calls
