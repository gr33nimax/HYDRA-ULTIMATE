"""Operator can revoke one transport without presenting WDTT as revocable."""

from unittest.mock import MagicMock, patch

from hydra.core.state_models import AppState, PluginState, User
from hydra.ui._menus import users_detail, users_management


def test_detail_menu_offers_personal_protocol_access():
    choices = users_detail.detail_menu_choices(blocked=False)
    assert any("протокол" in label.lower() for _, label, _ in choices)


def test_protocol_menu_uses_restored_user_after_apply_failure():
    user = User(email="alice", uuid="uuid")
    state = AppState(users=[user], protocols={"anytls": PluginState(enabled=True)})
    app = MagicMock()
    app.protocols.enabled_names.return_value = {"anytls"}
    app.protocols.display_name.return_value = "AnyTLS"
    offered = []

    def fail_and_restore(_state, _email, _name, _enabled):
        user.disabled_protocols.append("anytls")
        state.users = [User(email="alice", uuid="uuid")]
        raise RuntimeError("apply failed; rolled back")

    app.users.set_protocol_enabled.side_effect = fail_and_restore

    def choose(options, _header):
        offered.append(options)
        return "1" if len(offered) == 1 else "0"

    with (
        patch.object(users_management, "clear"),
        patch.object(users_management, "title"),
        patch.object(users_management, "menu", side_effect=choose),
        patch.object(users_management, "error"),
        patch.object(users_management, "prompt"),
    ):
        users_management._change_protocol_access(state, user, app)

    assert "Разрешено" in str(offered[1])


def test_protocol_menu_toggles_a_user_and_never_offers_wdtt():
    user = User(email="alice", uuid="uuid")
    state = AppState(
        users=[user],
        protocols={
            "anytls": PluginState(enabled=True),
            "wdtt": PluginState(enabled=True),
        },
    )
    app = MagicMock()
    app.protocols.enabled_names.return_value = {"anytls", "wdtt"}
    app.protocols.display_name.side_effect = lambda name: name
    app.users.set_protocol_enabled.side_effect = lambda state, email, name, enabled: user.disabled_protocols.append(
        name
    )
    offered = []

    def choose(options, _header):
        offered.append(options)
        return "1" if len(offered) == 1 else "0"

    with (
        patch.object(users_management, "clear"),
        patch.object(users_management, "title"),
        patch.object(users_management, "menu", side_effect=choose),
        patch.object(users_management, "success"),
    ):
        users_management._change_protocol_access(state, user, app)

    assert user.disabled_protocols == ["anytls"]
    assert all("wdtt" not in str(options).lower() for options in offered)
    assert app.users.set_protocol_enabled.call_args.args == (state, "alice", "anytls", False)
