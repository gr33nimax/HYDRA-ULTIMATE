"""Operator views of user devices and the fingerprints behind them."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from hydra.core.state import AppState, User
from hydra.core.status import public_user
from hydra.services.device_sessions import COUNTERS_KEY, update_sessions
from hydra.services.subscriptions.devices import (
    NETWORK_SOURCE,
    register_subscription_device,
    subscription_fingerprint,
)
from hydra.ui._menus import monitoring_devices, users_devices


def _user(**devices: dict) -> User:
    return User("alice@example.com", "uuid-a", device_limit=2, devices=devices)


def _state(user: User, **connections: dict) -> AppState:
    state = AppState()
    state.users = [user]
    state.install[COUNTERS_KEY] = {
        connection_id: {
            "user": user.email,
            "protocol": "vless",
            "total": 2048,
            "missed_polls": 0,
            **record,
        }
        for connection_id, record in connections.items()
    }
    update_sessions(state, now=1000.0)
    return state


def test_reported_hwid_is_preferred_over_the_network_guess():
    reported = subscription_fingerprint(
        {"X-HWID": "device-42", "User-Agent": "v2rayNG/1.9"},
        "198.51.100.7",
        {},
    )
    guessed = subscription_fingerprint(
        {"User-Agent": "v2rayNG/1.9"},
        "198.51.100.7",
        {},
    )

    assert reported.source == "x-hwid"
    assert reported.reported_hwid is True
    assert reported.user_agent == "v2rayNG/1.9"
    assert reported.address == "198.51.100.7"
    assert guessed.source == NETWORK_SOURCE
    assert guessed.reported_hwid is False
    assert reported.device_id != guessed.device_id


def test_registration_keeps_the_first_sighting_and_updates_the_rest():
    first = subscription_fingerprint(
        {"X-HWID": "device-42", "User-Agent": "old-client"},
        "198.51.100.7",
        {},
    )
    record = first.record("2026-07-01T10:00:00+00:00")
    later = subscription_fingerprint(
        {"X-HWID": "device-42", "User-Agent": "new-client"},
        "203.0.113.9",
        {},
    )

    updated = later.record("2026-07-20T12:00:00+00:00", record)

    assert updated["first_seen"] == "2026-07-01T10:00:00+00:00"
    assert updated["last_seen"] == "2026-07-20T12:00:00+00:00"
    assert updated["user_agent"] == "new-client"
    assert updated["address"] == "203.0.113.9"


def test_public_user_publishes_devices_without_the_full_identifier():
    user = _user(
        **{
            "a" * 64: {
                "first_seen": "2026-07-01T10:00:00+00:00",
                "last_seen": "2026-07-20T12:00:00+00:00",
                "source": "x-hwid",
                "user_agent": "v2rayNG/1.9",
                "address": "198.51.100.7",
            },
        },
    )

    payload = public_user(user)

    assert payload["devices_registered"] == 1
    assert payload["devices"] == [
        {
            "id": "a" * 12,
            "source": "x-hwid",
            "client": "v2rayNG/1.9",
            "address": "198.51.100.7",
            "first_seen": "2026-07-01T10:00:00+00:00",
            "last_seen": "2026-07-20T12:00:00+00:00",
        },
    ]
    assert "credentials" not in payload


def test_device_screen_shows_registrations_and_live_sessions():
    user = _user(
        **{
            "b" * 64: {
                "first_seen": "2026-07-01T10:00:00+00:00",
                "last_seen": "2026-07-20T12:00:00+00:00",
                "source": "x-hwid",
                "user_agent": "v2rayNG/1.9",
                "address": "198.51.100.7",
            },
        },
    )
    state = _state(
        user,
        c1={"address": "198.51.100.7"},
        c2={"address": "203.0.113.9"},
        c3={"address": "192.0.2.5"},
    )

    text = "\n".join(users_devices.device_lines(state, user))

    assert "bbbbbbbbbbbb" in text
    assert "v2rayNG/1.9" in text
    assert "198.51.100.7" in text and "203.0.113.9" in text
    assert "сверх лимита" in text
    assert "2 одновременно подключённых устройств" in text


def test_device_screen_changes_the_limit_through_the_application():
    user = _user()
    state = _state(user)
    app = MagicMock()

    with patch.object(users_devices, "prompt", return_value="3"), \
         patch.object(users_devices, "success"), \
         patch.object(users_devices, "clear"), \
         patch.object(users_devices, "panel"), \
         patch.object(users_devices, "menu", side_effect=["1", "0"]):
        users_devices.open_menu(state, user, app)

    app.set_user_device_limit.assert_called_once_with(
        state,
        "alice@example.com",
        3,
        reset=False,
    )
    assert user.device_limit == 3


def test_device_screen_rejects_a_nonsense_limit():
    user = _user()
    state = _state(user)
    app = MagicMock()

    with patch.object(users_devices, "prompt", return_value="-1"), \
         patch.object(users_devices, "error") as report, \
         patch.object(users_devices, "clear"), \
         patch.object(users_devices, "panel"), \
         patch.object(users_devices, "menu", side_effect=["1", "0"]):
        users_devices.open_menu(state, user, app)

    app.set_user_device_limit.assert_not_called()
    report.assert_called_once()


def test_monitoring_summary_counts_online_devices_and_violations():
    user = _user()
    state = _state(
        user,
        c1={"address": "198.51.100.7"},
        c2={"address": "203.0.113.9"},
        c3={"address": "192.0.2.5"},
    )

    summary = monitoring_devices.summarize(state)

    assert summary.online_devices == 3
    assert summary.online_users == 1
    assert summary.over_limit_users == 1
    assert "сверх лимита" in summary.headline


def test_monitoring_summary_is_quiet_when_nobody_is_connected():
    summary = monitoring_devices.summarize(_state(_user()))

    assert summary.online_devices == 0
    assert "никто не подключён" in summary.headline


def test_subscription_registration_stores_the_full_record():
    from hydra.core.state import save_state

    # conftest already redirects state paths into a temporary directory.
    state = AppState()
    state.users = [User("alice@example.com", "token", device_limit=1)]
    save_state(state)

    fingerprint = subscription_fingerprint(
        {"X-Hydra-HWID": "phone-1", "User-Agent": "hydra-client/2"},
        "198.51.100.7",
        {},
    )
    _state_after, user, status = register_subscription_device(
        "token",
        fingerprint,
    )

    assert status == "allowed"
    record = user.devices[fingerprint.device_id]
    assert record["source"] == "x-hydra-hwid"
    assert record["user_agent"] == "hydra-client/2"
    assert record["address"] == "198.51.100.7"
    assert record["first_seen"] == record["last_seen"]
