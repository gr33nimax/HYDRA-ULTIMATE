from unittest.mock import patch

from hydra.core.state import AppState, PluginState, User
from hydra.ui import menus


class _Plugin:
    def __init__(self, name: str):
        self.meta = type("Meta", (), {"name": name})()


def test_monitoring_user_detail_contains_stats_but_no_secrets_or_system_plugins(capsys):
    user = User(
        email="alice", uuid="secret-uuid", traffic_used_bytes=150,
        credentials={
            "anytls": {"traffic_used_bytes": 100, "password": "secret-password"},
            "mieru": {"traffic_used_bytes": 50, "password": "another-secret"},
        },
    )
    state = AppState(
        users=[user],
        protocols={
            "anytls": PluginState(enabled=True),
            "mieru": PluginState(enabled=True),
            "warp": PluginState(enabled=True),
        },
    )

    with patch.object(menus, "clear"), \
         patch.object(menus, "update_user_traffic"), \
         patch.object(menus, "enabled", return_value=[_Plugin("anytls"), _Plugin("mieru")]), \
         patch.object(menus, "prompt", return_value=""):
        menus._show_user_detail(state, user)

    output = capsys.readouterr().out
    assert "AnyTLS" in output
    assert "Mieru" in output
    assert "secret-uuid" not in output
    assert "secret-password" not in output
    assert "another-secret" not in output
    assert "warp" not in output.lower()
