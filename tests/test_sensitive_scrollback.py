"""Manual client artifacts should not remain in terminal scrollback."""

from unittest.mock import MagicMock, patch

from hydra.core.state_models import AppState, User
from hydra.ui._menus import users_links


def test_manual_screens_erase_history_on_exit(capsys):
    user = User(email="alice@example.com", uuid="token")
    artifact = users_links._ClientArtifact(
        plugin_name="anytls",
        display_name="AnyTLS",
        profile_name="",
        profile_label="",
        config="",
        links=("anytls://fake@example.com#alice",),
    )
    for screen in (users_links._user_configs, users_links._user_links):
        with (
            patch.object(users_links, "_client_artifacts", return_value=[artifact]),
            patch("builtins.input", return_value=""),
        ):
            screen(AppState(users=[user]), user, MagicMock())
        output = capsys.readouterr().out
        assert "anytls://fake@example.com#alice" in output
        assert output.endswith("\033[3J\033[2J\033[H")
