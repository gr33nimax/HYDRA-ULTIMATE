"""Simultaneous device limits derived from live connections."""
from __future__ import annotations

from unittest.mock import patch

from hydra.core.state import AppState, User
from hydra.services.device_sessions import (
    COUNTERS_KEY,
    SESSIONS_KEY,
    connections_to_close,
    observed_devices,
    update_sessions,
    user_sessions,
)
from hydra.services import traffic_daemon


def _state(*, limit: int = 0, **connections: dict) -> AppState:
    state = AppState()
    state.users = [User("alice@example.com", "uuid-a", device_limit=limit)]
    state.install[COUNTERS_KEY] = {
        connection_id: {
            "user": "alice@example.com",
            "protocol": "vless",
            "total": 100,
            "missed_polls": 0,
            **record,
        }
        for connection_id, record in connections.items()
    }
    return state


def test_connections_group_into_one_session_per_address():
    state = _state(
        c1={"address": "198.51.100.7"},
        c2={"address": "198.51.100.7", "total": 40},
        c3={"address": "203.0.113.9"},
    )

    devices = observed_devices(state, now=1000.0)["alice@example.com"]

    assert set(devices) == {"198.51.100.7", "203.0.113.9"}
    assert devices["198.51.100.7"]["connections"] == 2
    assert devices["198.51.100.7"]["bytes_total"] == 140


def test_unattributed_or_stale_connections_are_ignored():
    state = _state(
        c1={"address": "198.51.100.7", "user": ""},
        c2={"address": "", "user": "alice@example.com"},
        c3={"address": "203.0.113.9", "missed_polls": 2},
    )

    assert observed_devices(state, now=1000.0) == {}


def test_no_limit_means_every_device_is_allowed():
    state = _state(
        limit=0,
        c1={"address": "198.51.100.1"},
        c2={"address": "198.51.100.2"},
        c3={"address": "198.51.100.3"},
    )

    assert update_sessions(state, now=1000.0) == {}
    assert connections_to_close(state, {}) == []
    assert all(session.allowed for session in user_sessions(state, "alice@example.com"))


def test_devices_beyond_the_limit_are_refused_oldest_first():
    state = _state(limit=2, c1={"address": "198.51.100.1"})
    update_sessions(state, now=1000.0)
    state.install[COUNTERS_KEY]["c2"] = {
        "user": "alice@example.com",
        "address": "198.51.100.2",
        "total": 10,
        "missed_polls": 0,
    }
    update_sessions(state, now=1100.0)
    state.install[COUNTERS_KEY]["c3"] = {
        "user": "alice@example.com",
        "address": "198.51.100.3",
        "total": 10,
        "missed_polls": 0,
    }

    refused = update_sessions(state, now=1200.0)

    assert refused == {"alice@example.com": ["198.51.100.3"]}
    assert connections_to_close(state, refused) == ["c3"]
    sessions = {
        session.address: session.allowed
        for session in user_sessions(state, "alice@example.com")
    }
    assert sessions == {
        "198.51.100.1": True,
        "198.51.100.2": True,
        "198.51.100.3": False,
    }


def test_an_established_device_keeps_working_after_a_reconnect():
    state = _state(limit=1, c1={"address": "198.51.100.1"})
    update_sessions(state, now=1000.0)

    # The device drops off for a moment, then a second device appears.
    state.install[COUNTERS_KEY] = {
        "c2": {
            "user": "alice@example.com",
            "address": "198.51.100.2",
            "total": 10,
            "missed_polls": 0,
        },
    }
    update_sessions(state, now=1010.0)
    state.install[COUNTERS_KEY]["c1"] = {
        "user": "alice@example.com",
        "address": "198.51.100.1",
        "total": 10,
        "missed_polls": 0,
    }

    refused = update_sessions(state, now=1020.0)

    assert refused == {"alice@example.com": ["198.51.100.2"]}


def test_sessions_expire_and_stay_bounded():
    state = _state(limit=0, c1={"address": "198.51.100.1"})
    update_sessions(state, now=1000.0)
    state.install[COUNTERS_KEY] = {}

    update_sessions(state, now=1000.0 + 599)
    assert user_sessions(state, "alice@example.com")

    update_sessions(state, now=1000.0 + 601)
    assert user_sessions(state, "alice@example.com") == []
    assert state.install[SESSIONS_KEY] == {}


def test_daemon_closes_refused_connections_through_the_clash_api():
    state = _state(limit=1, c1={"address": "198.51.100.1"})
    update_sessions(state, now=1000.0)
    state.install[COUNTERS_KEY]["c2"] = {
        "user": "alice@example.com",
        "address": "198.51.100.2",
        "total": 10,
        "missed_polls": 0,
    }
    closed: list[str] = []

    with patch.object(
        traffic_daemon,
        "_close_connection",
        side_effect=lambda *args: closed.append(args[2]) or True,
    ), patch.object(traffic_daemon, "_write_log") as log:
        count = traffic_daemon._enforce_device_limits(
            state,
            port=9090,
            secret="secret",
        )

    assert count == 1
    assert closed == ["c2"]
    assert any("198.51.100.2" in call.args[0] for call in log.call_args_list)


def test_daemon_reports_when_the_api_refuses_to_close():
    state = _state(limit=1, c1={"address": "198.51.100.1"})
    update_sessions(state, now=1000.0)
    state.install[COUNTERS_KEY]["c2"] = {
        "user": "alice@example.com",
        "address": "198.51.100.2",
        "total": 10,
        "missed_polls": 0,
    }

    with patch.object(traffic_daemon, "_close_connection", return_value=False), \
         patch.object(traffic_daemon, "_write_log") as log:
        count = traffic_daemon._enforce_device_limits(
            state,
            port=9090,
            secret="",
        )

    assert count == 0
    assert any(
        "could not close connections" in call.args[0]
        for call in log.call_args_list
    )


def test_nothing_is_closed_while_every_user_is_within_the_limit():
    state = _state(limit=2, c1={"address": "198.51.100.1"})

    with patch.object(traffic_daemon, "_close_connection") as close:
        assert traffic_daemon._enforce_device_limits(
            state,
            port=9090,
            secret="",
        ) == 0

    close.assert_not_called()


def test_tracked_traffic_is_reported_without_a_per_plugin_override():
    from hydra.core.state import AppState, User
    from hydra.plugins.vless_xhttp.plugin import VlessXhttpPlugin

    state = AppState()
    state.users = [
        User(
            "alice@example.com",
            "uuid-a",
            credentials={"vless": {"traffic_used_bytes": 4096}},
        ),
        User(
            "bob@example.com",
            "uuid-b",
            credentials={"vless": {"traffic_used_bytes": 0}},
        ),
        User("carol@example.com", "uuid-c"),
    ]

    assert VlessXhttpPlugin().traffic(state) == {"alice@example.com": 4096}
