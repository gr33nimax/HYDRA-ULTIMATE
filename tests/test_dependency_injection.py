from argparse import Namespace
from types import SimpleNamespace

from hydra import cli
from hydra.core.state import AppState, User
from hydra.ui import menus


def test_cli_user_command_uses_injected_application_service(monkeypatch):
    calls = []
    app = SimpleNamespace(
        users=SimpleNamespace(list=lambda state: list(state.users)),
        add_user=lambda state, user: calls.append(("add", user.email)),
        block_user=lambda state, email: calls.append(("block", email)),
        unblock_user=lambda state, email: calls.append(("unblock", email)),
        remove_user=lambda state, email: calls.append(("remove", email)),
    )
    state = AppState(users=[User(email="alice", uuid="u1")])
    monkeypatch.setattr(cli, "_require_root", lambda: None)

    result = cli._user_command(Namespace(user_action="block", email="alice"), state, app)

    assert result == {"ok": True, "email": "alice", "action": "block"}
    assert calls == [("block", "alice")]


def test_menu_dependency_fallback_is_only_used_when_no_context_is_passed():
    injected = SimpleNamespace()
    assert menus._application(injected) is injected
