from __future__ import annotations

import pytest

from hydra.core.state import AppState, User, validate_state
from hydra.core.state_creator_models import HeadlessCreatorConfig
from hydra.core.state_models import validate_raw_state


def test_validate_state_accepts_defaults_and_users():
    validate_state(AppState(users=[User(email="u@example.com", uuid="u1")]))
    validate_state(AppState(users=[User(email="gr33nimax", uuid="u2")]))


def test_validate_state_rejects_invalid_port():
    state = AppState()
    state.network.tproxy_port = 70000
    with pytest.raises(ValueError, match="tproxy_port"):
        validate_state(state)


def test_validate_state_rejects_blank_or_spaced_identifier():
    with pytest.raises(ValueError, match="identifier"):
        validate_state(AppState(users=[User(email="bad name", uuid="u1")]))


def test_validate_state_rejects_invalid_device_fields():
    with pytest.raises(ValueError, match="device limit"):
        validate_state(AppState(users=[
            User(email="u@example.com", uuid="u1", device_limit=-1),
        ]))

    with pytest.raises(ValueError, match="device bindings"):
        validate_state(AppState(users=[
            User(
                email="u@example.com",
                uuid="u1",
                devices={"device": 123},  # type: ignore[dict-item]
            ),
        ]))


@pytest.mark.parametrize(
    "device_fields",
    [
        {"device_limit": -1, "devices": {}},
        {"device_limit": 1, "devices": {"device": 123}},
    ],
)
def test_validate_raw_state_rejects_invalid_device_fields(device_fields):
    user = {"email": "u@example.com", "uuid": "u1", **device_fields}
    with pytest.raises(ValueError, match="device"):
        validate_raw_state({"version": 3, "users": [user]})


@pytest.mark.parametrize("room_count", [True, 0, 17, "4"])
def test_qwdtt_room_count_is_strictly_validated(room_count) -> None:
    state = AppState(headless_creator=HeadlessCreatorConfig(consumers={
        "qwdtt": {"provider": "vk", "room_count": room_count},
    }))
    with pytest.raises(ValueError, match="room count"):
        validate_state(state)

    with pytest.raises(ValueError, match="room count"):
        validate_raw_state({
            "version": 9,
            "headless_creator": {
                "consumers": {"qwdtt": {"provider": "vk", "room_count": room_count}},
            },
        })


def test_qwdtt_boolean_flags_do_not_accept_truthy_strings() -> None:
    state = AppState(headless_creator=HeadlessCreatorConfig(consumers={
        "qwdtt": {"pool_enabled": "false"},
    }))
    with pytest.raises(ValueError, match="pool_enabled"):
        validate_state(state)
