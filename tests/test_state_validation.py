from __future__ import annotations

import pytest

from hydra.core.state import AppState, User, validate_state
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
