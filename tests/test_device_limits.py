from io import BytesIO

from hydra.core.state import AppState, User, load_state, save_state
from hydra.services.subscriptions.generator import (
    register_subscription_device,
    subscription_device_id,
)
from hydra.services.subscriptions.server import SubscriptionHandler


def test_device_identifier_prefers_hwid_and_never_contains_raw_value():
    fingerprint = subscription_device_id(
        {"X-HWID": "phone-serial-123", "User-Agent": "Karing"},
        "203.0.113.10",
        {},
    )
    assert len(fingerprint) == 64
    assert "phone-serial-123" not in fingerprint


def test_subscription_device_limit_is_atomic_and_allows_known_device():
    state = AppState(users=[
        User(email="alice", uuid="token", device_limit=1),
    ])
    save_state(state)

    _, user, status = register_subscription_device("token", "device-a")
    assert status == "allowed"
    assert user is not None
    assert list(user.devices) == ["device-a"]

    _, _, status = register_subscription_device("token", "device-b")
    assert status == "limit"
    assert list(load_state().users[0].devices) == ["device-a"]

    _, _, status = register_subscription_device("token", "device-a")
    assert status == "allowed"


def test_zero_device_limit_is_unlimited():
    save_state(AppState(users=[User(email="default", uuid="token")]))
    for device in ("a", "b", "c"):
        _, _, status = register_subscription_device("token", device)
        assert status == "allowed"


def test_device_updates_merge_into_stale_settings_without_revision_conflict():
    save_state(AppState(users=[
        User(email="alice", uuid="token", device_limit=2),
    ]))
    stale = load_state()
    initial_revision = stale.revision

    registered, _, status = register_subscription_device("token", "device-a")
    assert status == "allowed"
    assert registered.revision == initial_revision

    stale.network.domain = "settings.example"
    save_state(stale)
    persisted = load_state()

    assert persisted.network.domain == "settings.example"
    assert list(persisted.users[0].devices) == ["device-a"]
    assert persisted.revision == initial_revision + 1


def _request_handler(
    *,
    hwid: str,
) -> tuple[SubscriptionHandler, list[int], list[tuple[int, str]]]:
    handler = object.__new__(SubscriptionHandler)
    handler.plugins = object()
    handler.path = "/sub/token"
    handler.headers = {"X-HWID": hwid, "User-Agent": "Karing"}
    handler.client_address = ("203.0.113.10", 12345)
    handler.wfile = BytesIO()
    responses: list[int] = []
    errors: list[tuple[int, str]] = []
    handler.send_response = responses.append
    handler.send_header = lambda *_args: None
    handler.end_headers = lambda: None
    handler._send_error = lambda code, message: errors.append((code, message))
    handler._subscription = lambda *_args: (
        "subscription",
        "text/plain; charset=utf-8",
        "sub.txt",
    )
    return handler, responses, errors


def test_subscription_handler_registers_fingerprint_and_enforces_limit():
    save_state(AppState(users=[
        User(email="alice", uuid="token", device_limit=1),
    ]))

    first, responses, errors = _request_handler(hwid="phone")
    first.do_GET()

    expected = subscription_device_id(
        first.headers,
        "203.0.113.10",
        {},
    )
    assert responses == [200]
    assert errors == []
    assert list(load_state().users[0].devices) == [expected]

    second, responses, errors = _request_handler(hwid="tablet")
    second.do_GET()

    assert responses == []
    assert errors == [(403, "Device limit reached")]
    assert list(load_state().users[0].devices) == [expected]


def test_subscription_handler_honors_explicit_singbox_query_format():
    save_state(AppState(users=[User(email="alice", uuid="token")]))
    handler, responses, errors = _request_handler(hwid="desktop")
    handler.path = "/sub/token?format=singbox"
    selected_formats: list[str] = []

    def subscription(response_format, *_args):
        selected_formats.append(response_format)
        return (
            '{"outbounds":[]}',
            "application/json; charset=utf-8",
            "singbox.json",
        )

    handler._subscription = subscription
    handler.do_GET()

    assert responses == [200]
    assert errors == []
    assert selected_formats == ["singbox"]
    assert handler.wfile.getvalue() == b'{"outbounds":[]}'


def test_admin_can_reset_devices_without_stale_save_restoring_them():
    from hydra.core.orchestrator import set_user_device_limit

    state = AppState(users=[
        User(
            email="alice",
            uuid="token",
            device_limit=2,
            devices={
                "old-device": {
                    "first_seen": "2026-07-24T00:00:00+00:00",
                    "last_seen": "2026-07-24T00:00:00+00:00",
                },
            },
        ),
    ])
    save_state(state)
    set_user_device_limit(state, "alice", 1, reset=True)

    loaded = load_state()
    assert loaded.users[0].device_limit == 1
    assert loaded.users[0].devices == {}
    assert "_device_binding_resets" not in loaded.install
