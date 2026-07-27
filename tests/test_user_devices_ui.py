"""Operator views of user devices and the fingerprints behind them."""
from __future__ import annotations

import hashlib
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


def test_network_fingerprint_survives_an_address_change_for_the_same_client():
    first = subscription_fingerprint(
        {"User-Agent": "  NekoBox/Android/1.4.2a  "},
        "198.51.100.7",
        {},
    )
    later = subscription_fingerprint(
        {"User-Agent": "NekoBox/Android/1.4.2a"},
        "203.0.113.9",
        {},
    )

    assert first.device_id == later.device_id
    assert first.user_agent == "NekoBox/Android/1.4.2a"
    assert later.address == "203.0.113.9"


def test_network_fingerprint_uses_the_address_when_client_is_unknown():
    first = subscription_fingerprint({}, "198.51.100.7", {})
    later = subscription_fingerprint({}, "203.0.113.9", {})

    assert first.device_id != later.device_id


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


def test_registration_collapses_legacy_address_and_client_duplicates():
    from hydra.core.state import save_state

    agent = "Throne/1.2.0"
    first_id = hashlib.sha256(
        f"{NETWORK_SOURCE}:198.51.100.7|{agent}".encode(),
    ).hexdigest()
    second_id = hashlib.sha256(
        f"{NETWORK_SOURCE}:203.0.113.9|{agent}".encode(),
    ).hexdigest()
    user = User(
        "alice@example.com",
        "token",
        device_limit=1,
        devices={
            first_id: {
                "first_seen": "2026-07-01T10:00:00+00:00",
                "last_seen": "2026-07-20T10:00:00+00:00",
                "source": NETWORK_SOURCE,
                "user_agent": agent,
                "address": "198.51.100.7",
            },
            second_id: {
                "first_seen": "2026-07-10T10:00:00+00:00",
                "last_seen": "2026-07-21T10:00:00+00:00",
                "source": NETWORK_SOURCE,
                "user_agent": agent,
                "address": "203.0.113.9",
            },
        },
    )
    save_state(AppState(users=[user]))
    current = subscription_fingerprint(
        {"User-Agent": agent},
        "192.0.2.44",
        {},
    )

    _state_after, updated, status = register_subscription_device(
        "token",
        current,
    )

    assert status == "allowed"
    assert updated is not None
    assert list(updated.devices) == [current.device_id]
    record = updated.devices[current.device_id]
    assert record["first_seen"] == "2026-07-01T10:00:00+00:00"
    assert record["address"] == "192.0.2.44"


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


def test_device_lines_stay_inside_the_panel():
    from hydra.ui.tui import PANEL_W, visible_width

    user = _user(
        **{
            "c" * 64: {
                "first_seen": "2026-07-01T10:00:00+00:00",
                "last_seen": "2026-07-20T12:00:00+00:00",
                "source": "x-hydra-hwid",
                "user_agent": "v2rayNG/1.9.11 (Android 14; SM-G998B)",
                "address": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            },
        },
    )
    state = _state(
        user,
        c1={"address": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
        c2={"address": "198.51.100.4", "total": 900_000},
        c3={"address": "203.0.113.9"},
    )

    for line in users_devices.device_lines(state, user):
        assert visible_width(line) <= PANEL_W - 4, line


def test_loopback_address_is_explained_not_shown_as_the_device():
    user = _user(
        **{
            "d" * 64: {
                "first_seen": "2026-07-01T10:00:00+00:00",
                "last_seen": "2026-07-20T12:00:00+00:00",
                "source": "network-client",
                "user_agent": "Throne/1.2.0",
                "address": "127.0.0.1",
            },
        },
    )

    text = "\n".join(users_devices.device_lines(_state(user), user))

    assert "адрес скрыт мультиплексором" in text
    assert "127.0.0.1" not in text


def test_monitoring_overview_never_calls_loopback_a_device():
    user = _user()
    state = _state(user, c1={"address": "127.0.0.1"})

    text = "\n".join(monitoring_devices._user_lines(state, user))

    assert "адрес скрыт мультиплексором" in text
    assert "127.0.0.1" not in text


def test_guessed_device_label_explains_that_hwid_is_unavailable():
    user = _user(
        **{
            "d" * 64: {
                "first_seen": "2026-07-01T10:00:00+00:00",
                "last_seen": "2026-07-20T12:00:00+00:00",
                "source": NETWORK_SOURCE,
                "user_agent": "Throne/1.2.0",
                "address": "198.51.100.7",
            },
        },
    )

    text = "\n".join(users_devices.device_lines(_state(user), user))

    assert "по клиенту (без HWID)" in text
    assert "по адресу и клиенту" not in text


def test_subscription_handler_recovers_the_peer_behind_the_multiplexer():
    import socket
    import struct

    from hydra.services.subscriptions.proxy_protocol import (
        SIGNATURE,
        read_source_address,
    )

    payload = (
        socket.inet_aton("198.51.100.7")
        + socket.inet_aton("10.0.0.1")
        + struct.pack("!HH", 54321, 443)
    )
    header = SIGNATURE + bytes([0x21, 0x11]) + struct.pack("!H", len(payload))
    listener, client = socket.socketpair()
    try:
        client.sendall(header + payload + b"GET / HTTP/1.1\r\n\r\n")
        assert read_source_address(listener) == ("198.51.100.7", 54321)
        assert listener.recv(16).startswith(b"GET / HTTP/1.1")
    finally:
        listener.close()
        client.close()


def test_a_direct_request_is_left_alone():
    import socket

    from hydra.services.subscriptions.proxy_protocol import read_source_address

    listener, client = socket.socketpair()
    try:
        client.sendall(b"GET /sub/token HTTP/1.1\r\n\r\n")
        assert read_source_address(listener) is None
        assert listener.recv(5) == b"GET /"
    finally:
        listener.close()
        client.close()
