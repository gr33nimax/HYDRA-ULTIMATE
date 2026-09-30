from unittest.mock import Mock

from hydra.core.state import AppState, User
from hydra.services.users import UserService


def _fixture():
    operations = Mock()
    state = AppState(users=[User(email="alice", uuid="u1")])
    return UserService(operations), operations, state


def test_list_and_get_are_read_only():
    service, operations, state = _fixture()

    assert [user.email for user in service.list(state)] == ["alice"]
    user = service.get(state, "alice")
    assert user is not None
    assert user.uuid == "u1"
    operations.assert_not_called()


def test_add_delegates_and_returns_user():
    service, operations, state = _fixture()
    user = User(email="bob", uuid="u2")

    assert service.add(state, user) is user
    operations.add_user.assert_called_once_with(state, user)


def test_remove_delegates_by_email():
    service, operations, state = _fixture()

    service.remove(state, "alice")

    operations.remove_user.assert_called_once_with(state, "alice")


def test_user_projection_mutations_trigger_best_effort_node_reconciliation():
    events = []
    operations = Mock()
    operations.add_user.side_effect = lambda state, user: events.append("saved")
    service = UserService(operations, after_node_change=lambda: events.append("reconcile"))

    service.add(AppState(), User(email="bob", uuid="u2"))

    assert events == ["saved", "reconcile"]


def test_node_reconciliation_failure_does_not_fail_saved_user_change():
    operations = Mock()

    def offline():
        raise TimeoutError("node is offline")

    service = UserService(operations, after_node_change=offline)

    service.add(AppState(), User(email="bob", uuid="u2"))

    operations.add_user.assert_called_once()


def test_block_and_unblock_delegate_by_email():
    service, operations, state = _fixture()

    service.block(state, "alice")
    service.unblock(state, "alice")

    operations.block_user.assert_called_once_with(state, "alice")
    operations.unblock_user.assert_called_once_with(state, "alice")
