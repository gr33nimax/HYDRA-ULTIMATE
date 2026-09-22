"""Telemt per-user traffic comes from the loopback control API (ADR 0016)."""

from __future__ import annotations

import inspect
import json
import urllib.error
from email.message import Message
from unittest.mock import MagicMock, patch

from hydra.core.state import AppState, PluginState, User
from hydra.plugins.telemt import observation
from hydra.plugins.telemt.credentials import derive_username
from hydra.plugins.telemt.plugin import TelemtPlugin
from hydra.services.traffic import refresh_user_traffic


class _Protocols:
    """Minimal traffic port around one real Telemt plugin."""

    def __init__(self, plugin: TelemtPlugin) -> None:
        self.plugin = plugin

    def enabled_names(self, state: AppState) -> set[str]:
        return {"telemt"}

    def traffic(self, state: AppState, name: str) -> dict[str, int]:
        return self.plugin.traffic(state)

    def traffic_snapshot(self, state: AppState, name: str) -> dict[str, int] | None:
        return self.plugin.traffic_snapshot(state)

    def traffic_source_reason(self, state: AppState, name: str) -> str:
        return self.plugin.traffic_source_reason(state)

    def aggregate_traffic_snapshot(self, state: AppState, name: str) -> int | None:
        return None

    def ingest_traffic(self, state: AppState, name: str, cursors: dict) -> None:
        return None


def _state(*, blocked: bool = False) -> AppState:
    user = User(email="a@example.com", uuid="user-a", blocked=blocked)
    return AppState(users=[user], protocols={"telemt": PluginState(enabled=True)})


def _entry(uuid: str, total: int) -> dict:
    return {"username": derive_username(uuid), "total_octets": total}


def _payload(*entries: dict) -> str:
    return json.dumps(list(entries))


def _read(state: AppState, payload: str):
    return observation.traffic(
        state,
        derive_username=derive_username,
        fetch=lambda: payload,
    )


def _failing_read(state: AppState, error: Exception):
    def fetch() -> str:
        raise error

    return observation.traffic(
        state,
        derive_username=derive_username,
        fetch=fetch,
    )


def test_control_api_fixture_maps_username_to_the_state_user():
    state = _state()

    totals, reason = _read(state, _payload(_entry("user-a", 4096)))

    assert totals == {"a@example.com": 4096}
    assert reason == ""


def test_control_api_accumulates_monotonically_through_the_snapshot_path():
    state = _state()
    plugin = TelemtPlugin()
    protocols = _Protocols(plugin)
    samples = [
        _read(state, _payload(_entry("user-a", 100))),
        _read(state, _payload(_entry("user-a", 150))),
        # A process restart resets the cumulative counter below its previous value;
        # the restarted counter's value is added to the accumulated total.
        _read(state, _payload(_entry("user-a", 20))),
    ]

    with patch.object(observation, "traffic", side_effect=samples):
        refresh_user_traffic(state, protocols=protocols)
        refresh_user_traffic(state, protocols=protocols)
        refresh_user_traffic(state, protocols=protocols)

    assert state.users[0].credentials["telemt"]["traffic_used_bytes"] == 170
    assert state.users[0].traffic_used_bytes == 170


def test_every_failure_is_unavailable_rather_than_a_measured_zero():
    state = _state()
    http_error = urllib.error.HTTPError(
        observation.STATS_URL,
        503,
        "Service Unavailable",
        Message(),
        None,
    )
    cases = {
        "disabled or unreachable": _failing_read(
            state,
            urllib.error.URLError("connection refused"),
        ),
        "non-200": _failing_read(state, http_error),
        "malformed body": _read(state, "not json"),
        "missing total_octets": _read(
            state,
            json.dumps([{"username": derive_username("user-a")}]),
        ),
        "absent user": _read(state, _payload(_entry("someone-else", 5))),
    }

    for label, (totals, reason) in cases.items():
        assert totals is None, label
        assert reason, label


def test_failed_read_preserves_last_good_totals_and_keeps_the_reason():
    state = _state()
    plugin = TelemtPlugin()
    protocols = _Protocols(plugin)
    samples = [
        _read(state, _payload(_entry("user-a", 100))),
        _failing_read(state, urllib.error.URLError("connection refused")),
    ]

    with patch.object(observation, "traffic", side_effect=samples):
        refresh_user_traffic(state, protocols=protocols)
        refresh_user_traffic(state, protocols=protocols)

    assert state.users[0].credentials["telemt"]["traffic_used_bytes"] == 100
    assert state.users[0].traffic_used_bytes == 100
    assert "control API" in plugin.traffic_source_reason(state)


def test_blocked_users_are_not_required_from_the_control_api():
    state = _state(blocked=True)

    totals, reason = _read(state, _payload())

    assert totals == {}
    assert reason == ""


def test_plugin_status_and_health_expose_the_counter_failure():
    state = _state()
    plugin = TelemtPlugin()
    failure = (None, "control API недоступен (URLError)")

    with (
        patch.object(TelemtPlugin, "_installed", return_value=True),
        patch("hydra.plugins.telemt.plugin.CONFIG_FILE") as config_file,
        patch("subprocess.run") as run,
        patch.object(observation, "traffic", return_value=failure),
    ):
        config_file.exists.return_value = True
        run.return_value = MagicMock(stdout="active\n", returncode=0)
        assert plugin.traffic_snapshot(state) is None
        assert plugin.traffic_source_reason(state) == failure[1]
        status = plugin.status(state)
        health = plugin.healthcheck_for_state(state)

    assert status.info["traffic_source"] == failure[1]
    assert health.healthy is True
    assert "источник трафика недоступен" in health.detail


def test_legacy_stats_file_reader_is_not_a_source():
    """The iptables/stats.json scheme must not be revived (ADR 0016)."""
    assert "stats_file" not in inspect.signature(observation.traffic).parameters
