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
    assert service.get(state, "alice").uuid == "u1"
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


def test_block_and_unblock_delegate_by_email():
    service, operations, state = _fixture()

    service.block(state, "alice")
    service.unblock(state, "alice")

    operations.block_user.assert_called_once_with(state, "alice")
    operations.unblock_user.assert_called_once_with(state, "alice")
