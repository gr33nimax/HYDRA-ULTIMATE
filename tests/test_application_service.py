from types import SimpleNamespace

from hydra.bootstrap import production_application
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
        plugin_statuses=lambda state: {},
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
        plugin_statuses=lambda state: {},
    )
    assert app.apply(AppState()) is False
    assert app.apply_error() == "configuration failed"


def test_application_check_combines_validation_host_and_change_preview():
    system = SimpleNamespace(
        validate=lambda state: {"valid": True, "schema_version": state.version},
        doctor=lambda state: {"ok": True, "required_failures": []},
    )
    planner = SimpleNamespace(
        build=lambda state: {
            "valid": True,
            "plugins": ["naive"],
            "reconciliation": [],
            "tls_mux": {"ok": True},
        },
    )
    app = ApplicationService(
        users=SimpleNamespace(),
        protocols=SimpleNamespace(),
        apply_config=lambda state: True,
        last_apply_error=lambda: "",
        plugin_statuses=lambda state: {},
        system=system,
        planner=planner,
    )

    assert app.check(AppState()) == {
        "ok": True,
        "configuration": {"valid": True, "schema_version": 4},
        "host": {"ok": True, "required_failures": []},
        "changes": {
            "valid": True,
            "plugins": ["naive"],
            "reconciliation": [],
            "tls_mux": {"ok": True},
        },
    }


def test_application_check_includes_tls_runtime_audit_in_result():
    app = ApplicationService(
        users=SimpleNamespace(),
        protocols=SimpleNamespace(),
        apply_config=lambda state: True,
        last_apply_error=lambda: "",
        plugin_statuses=lambda state: {},
        system=SimpleNamespace(
            validate=lambda state: {"valid": True},
            doctor=lambda state: {"ok": True},
        ),
        planner=SimpleNamespace(
            build=lambda state: {
                "valid": True,
                "tls_mux": {"ok": False, "required": True},
            },
        ),
    )

    assert app.check(AppState())["ok"] is False


def test_application_service_status_uses_injected_plugin_reader():
    calls = []
    app = ApplicationService(
        users=SimpleNamespace(),
        protocols=SimpleNamespace(),
        apply_config=lambda state: True,
        last_apply_error=lambda: "",
        plugin_statuses=lambda state: calls.append(state)
        or {"demo": {"running": True}},
    )
    state = AppState()

    payload = app.status(state)

    assert calls == [state]
    assert payload["runtime"]["demo"]["running"] is True


def test_production_applications_do_not_share_plugin_or_orchestrator_state():
    first = production_application()
    second = production_application()

    assert first.protocols.operations is not second.protocols.operations
    assert first.protocols.require("antidpi") is not second.protocols.require(
        "antidpi",
    )
