from hydra.core.state import AppState, User, load_state, save_state
from hydra.services.subscriptions.generator import (
    register_subscription_device,
    subscription_device_id,
)


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


def test_admin_can_reset_devices_without_stale_save_restoring_them():
    from hydra.core.orchestrator import set_user_device_limit

    state = AppState(users=[
        User(
            email="alice",
            uuid="token",
            device_limit=2,
            devices={"old-device": "2026-07-24T00:00:00+00:00"},
        ),
    ])
    save_state(state)
    set_user_device_limit(state, "alice", 1, reset=True)

    loaded = load_state()
    assert loaded.users[0].device_limit == 1
    assert loaded.users[0].devices == {}
    assert "_device_binding_resets" not in loaded.install
