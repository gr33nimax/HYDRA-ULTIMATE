from unittest.mock import patch

from hydra.core.state import AppState, User
from hydra.ui import menus


def test_add_user_normalizes_email_and_rejects_case_insensitive_duplicate():
    state = AppState(users=[User(email="alice@example.com", uuid="existing")])

    with patch.object(menus, "clear"), \
         patch.object(menus, "title"), \
         patch.object(menus, "prompt", side_effect=["  ALICE@EXAMPLE.COM  ", ""]), \
         patch.object(menus, "error") as show_error, \
         patch("hydra.plugins.registry.enabled", return_value=[]), \
         patch.object(menus.orchestrator, "add_user") as add_user:
        menus._add_user(state)

    add_user.assert_not_called()
    show_error.assert_called_once()


def test_reconcile_blocks_user_immediately_when_quota_is_exhausted():
    user = User(
        email="alice@example.com",
        uuid="token",
        traffic_limit_gb=1,
        traffic_used_bytes=1073741824,
    )
    state = AppState(users=[user])

    with patch.object(menus.orchestrator, "block_user") as block_user, \
         patch.object(menus, "warn"):
        menus._reconcile_user_access(state, user)

    block_user.assert_called_once_with(state, "alice@example.com")


def test_reconcile_offers_unblock_after_limits_are_extended():
    user = User(email="alice@example.com", uuid="token", blocked=True)
    state = AppState(users=[user])

    with patch.object(menus, "confirm", return_value=True), \
         patch.object(menus, "success"), \
         patch.object(menus.orchestrator, "unblock_user") as unblock_user:
        menus._reconcile_user_access(state, user)

    unblock_user.assert_called_once_with(state, "alice@example.com")


def test_manual_unblock_is_rejected_while_subscription_is_expired():
    user = User(
        email="alice@example.com",
        uuid="token",
        blocked=True,
        expiry_date="2000-01-01T00:00:00Z",
    )
    state = AppState(users=[user])

    with patch.object(menus, "error") as show_error, \
         patch.object(menus, "prompt", return_value=""), \
         patch.object(menus.orchestrator, "unblock_user") as unblock_user:
        menus._toggle_block(state, user)

    unblock_user.assert_not_called()
    assert "срок истёк" in show_error.call_args.args[0]
