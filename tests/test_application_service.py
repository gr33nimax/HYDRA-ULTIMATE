from types import SimpleNamespace

from hydra.core.state import AppState, User
from hydra.services.application import ApplicationService


class _Users:
    def __init__(self):
        self.calls = []

    def list(self, state):
        return list(state.users)

    def add(self, state, user):
        self.calls.append(("add", user.email))
        return user

    def remove(self, state, email):
        self.calls.append(("remove", email))

    def block(self, state, email):
        self.calls.append(("block", email))

    def unblock(self, state, email):
        self.calls.append(("unblock", email))


def test_application_service_delegates_user_lifecycle_and_apply():
    users = _Users()
    applied = []
    app = ApplicationService(
        users=users,
        protocols=SimpleNamespace(),
        apply_config=lambda state: applied.append(state) or True,
        last_apply_error=lambda: "",
    )
    state = AppState()
    user = User(email="alice@example.com", uuid="u1")

    assert app.add_user(state, user) is user
    app.block_user(state, user.email)
    app.unblock_user(state, user.email)
    app.remove_user(state, user.email)
    assert app.apply(state) is True
    assert [kind for kind, _ in users.calls] == ["add", "block", "unblock", "remove"]
    assert applied == [state]


def test_application_service_exposes_last_apply_error_without_leaking_exceptions():
    app = ApplicationService(
        users=SimpleNamespace(), protocols=SimpleNamespace(),
        apply_config=lambda state: False,
        last_apply_error=lambda: "configuration failed",
    )
    assert app.apply(AppState()) is False
    assert app.apply_error() == "configuration failed"
