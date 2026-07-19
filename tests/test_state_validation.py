from __future__ import annotations

import pytest

from hydra.core.state import AppState, User, validate_state


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
