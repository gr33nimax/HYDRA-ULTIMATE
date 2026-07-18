from unittest.mock import MagicMock, patch

from hydra.core.state import AppState, PluginState, User
from hydra.services.active_connections import tracked_active_connections
from hydra.services.traffic import refresh_user_traffic, check_traffic_limits


def test_resettable_snapshot_is_accumulated_monotonically():
    user = User(email="u@example.com", uuid="u1")
    state = AppState(
        users=[user],
        protocols={"amneziawg": PluginState(enabled=True)},
    )
    plugin = MagicMock()
    plugin.meta.name = "amneziawg"
    plugin.traffic.side_effect = [
        {user.email: 100}, {user.email: 150}, {user.email: 20},
    ]
    with patch("hydra.services.traffic.enabled", return_value=[plugin]), \
         patch("hydra.services.traffic.get", return_value=plugin):
        refresh_user_traffic(state)
        refresh_user_traffic(state)
        refresh_user_traffic(state)

    assert user.credentials["amneziawg"]["traffic_used_bytes"] == 170
    assert user.traffic_used_bytes == 170


def test_limit_is_reached_at_exact_boundary():
    limit = 1073741824
    user = User(
        email="u@example.com", uuid="u1", traffic_limit_gb=1,
        traffic_used_bytes=limit,
    )
    state = AppState(users=[user])
    with patch("hydra.services.traffic.enabled", return_value=[]):
        assert check_traffic_limits(state) == [user.email]


def test_active_connections_group_only_current_attributed_sessions():
    state = AppState()
    state.network.clash_api_enabled = True
    import time
    state.install["traffic_daemon_last_poll"] = time.time()
    state.install["traffic_connection_counters"] = {
        "a": {"user": "u@example.com", "protocol": "anytls", "download": 100,
              "upload": 20, "missed_polls": 0},
        "b": {"user": "u@example.com", "protocol": "anytls", "download": 50,
              "upload": 10, "missed_polls": 0},
        "stale": {"user": "old@example.com", "protocol": "anytls", "download": 999,
                  "upload": 999, "missed_polls": 1},
        "unknown": {"user": "", "protocol": "mieru", "download": 999,
                    "upload": 999, "missed_polls": 0},
    }
    rows = tracked_active_connections(state)
    assert len(rows) == 1
    assert rows[0]["email"] == "u@example.com"
    assert rows[0]["rx"] == 150
    assert rows[0]["tx"] == 30
    assert rows[0]["connections"] == 2


def test_active_connections_include_attributed_shadowtls_sessions():
    state = AppState()
    state.network.clash_api_enabled = True
    import time
    state.install["traffic_daemon_last_poll"] = time.time()
    state.install["traffic_connection_counters"] = {
        "shadow": {
            "user": "shadow@example.com",
            "protocol": "shadowtls",
            "download": 480,
            "upload": 120,
            "missed_polls": 0,
            "seen_at": time.time(),
        },
    }

    rows = tracked_active_connections(state)
    assert len(rows) == 1
    assert rows[0]["plugin"] == "shadowtls"
    assert rows[0]["email"] == "shadow@example.com"
    assert rows[0]["rx"] == 480
    assert rows[0]["tx"] == 120
