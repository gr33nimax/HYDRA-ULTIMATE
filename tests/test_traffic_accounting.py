from unittest.mock import MagicMock

from hydra.core.state import AppState, PluginState, User
from hydra.services.active_connections import tracked_active_connections
from hydra.services.traffic import (
    refresh_user_traffic, check_traffic_limits, protocol_totals,
)


class FakeTrafficProtocols:
    def __init__(self, plugins=()):
        self.plugins = {plugin.meta.name: plugin for plugin in plugins}

    def enabled_names(self, state: AppState) -> set[str]:
        return {
            name
            for name, protocol in state.protocols.items()
            if protocol.enabled and name in self.plugins
        }

    def traffic(self, state: AppState, name: str) -> dict[str, int]:
        return self.plugins[name].traffic(state)

    def traffic_snapshot(
        self,
        state: AppState,
        name: str,
    ) -> dict[str, int] | None:
        return self.plugins[name].traffic_snapshot(state)

    def aggregate_traffic_snapshot(
        self,
        state: AppState,
        name: str,
    ) -> int | None:
        return self.plugins[name].aggregate_traffic_snapshot(state)

    def ingest_traffic(
        self,
        state: AppState,
        name: str,
        cursors: dict,
    ) -> None:
        self.plugins[name].ingest_traffic(state, cursors)


def test_resettable_snapshot_is_accumulated_monotonically():
    user = User(email="u@example.com", uuid="u1")
    state = AppState(
        users=[user],
        protocols={"amneziawg": PluginState(enabled=True)},
    )
    plugin = MagicMock()
    plugin.meta.name = "amneziawg"
    plugin.traffic_snapshot.side_effect = [
        {user.email: 100}, {user.email: 150}, {user.email: 20},
    ]
    plugin.aggregate_traffic_snapshot.return_value = None
    protocols = FakeTrafficProtocols([plugin])
    refresh_user_traffic(state, protocols=protocols)
    refresh_user_traffic(state, protocols=protocols)
    refresh_user_traffic(state, protocols=protocols)

    assert user.credentials["amneziawg"]["traffic_used_bytes"] == 170
    assert user.traffic_used_bytes == 170


def test_qwdtt_aggregate_is_monotonic_without_per_user_attribution():
    state = AppState(protocols={"wdtt": PluginState(enabled=True)})
    plugin = MagicMock()
    plugin.meta.name = "wdtt"
    plugin.traffic_snapshot.return_value = None
    plugin.aggregate_traffic_snapshot.side_effect = [
        100,
        150,
        20,
        None,
        40,
    ]

    protocols = FakeTrafficProtocols([plugin])
    for _ in range(5):
        refresh_user_traffic(state, protocols=protocols)

    stats = state.install["protocol_traffic_totals"]["wdtt"]
    assert stats["traffic_used_bytes"] == 190
    assert stats["traffic_last_raw_bytes"] == 40
    assert protocol_totals(state)["wdtt"] == 190
    assert state.users == []


def test_custom_plugin_snapshot_needs_no_service_allowlist():
    user = User(email="custom@example.com", uuid="u1")
    state = AppState(
        users=[user],
        protocols={"custom": PluginState(enabled=True)},
    )
    plugin = MagicMock()
    plugin.meta.name = "custom"
    plugin.traffic_snapshot.return_value = {user.email: 125}
    plugin.aggregate_traffic_snapshot.return_value = None

    refresh_user_traffic(
        state,
        protocols=FakeTrafficProtocols([plugin]),
    )

    assert user.credentials["custom"]["traffic_used_bytes"] == 125


def test_limit_is_reached_at_exact_boundary():
    limit = 1073741824
    user = User(
        email="u@example.com", uuid="u1", traffic_limit_gb=1,
        traffic_used_bytes=limit,
    )
    state = AppState(users=[user])
    assert check_traffic_limits(
        state,
        protocols=FakeTrafficProtocols(),
    ) == [user.email]


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


def test_active_connections_include_attributed_hysteria2_sessions():
    state = AppState()
    state.network.clash_api_enabled = True
    import time
    state.install["traffic_daemon_last_poll"] = time.time()
    state.install["traffic_connection_counters"] = {
        "hysteria2": {
            "user": "hy2@example.com",
            "protocol": "hysteria2",
            "download": 500,
            "upload": 200,
            "missed_polls": 0,
            "seen_at": time.time(),
        },
    }

    rows = tracked_active_connections(state)
    assert len(rows) == 1
    assert rows[0]["plugin"] == "hysteria2"
    assert rows[0]["email"] == "hy2@example.com"
    assert rows[0]["rx"] == 500
    assert rows[0]["tx"] == 200


def test_active_connections_include_a_custom_attributed_protocol():
    state = AppState()
    state.network.clash_api_enabled = True
    import time

    state.install["traffic_daemon_last_poll"] = time.time()
    state.install["traffic_connection_counters"] = {
        "custom": {
            "user": "custom@example.com",
            "protocol": "custom",
            "download": 300,
            "upload": 100,
            "missed_polls": 0,
            "seen_at": time.time(),
        },
    }

    assert tracked_active_connections(state) == [
        {
            "plugin": "custom",
            "email": "custom@example.com",
            "online": True,
            "rx": 300,
            "tx": 100,
            "connections": 1,
            "last_handshake": int(
                state.install["traffic_connection_counters"][
                    "custom"
                ]["seen_at"],
            ),
            "traffic_scope": "active",
        },
    ]
