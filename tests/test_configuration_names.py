from __future__ import annotations

import pytest

from hydra.core.state_models import AppState, User, validate_state
from hydra.services.configuration_names import ConfigurationNameService


def test_user_name_overrides_global_then_builtin_default() -> None:
    state = AppState(users=[User(email="u@example.com", uuid="u")])
    names = ConfigurationNameService()
    user = state.users[0]

    assert names.resolve(state, user, "trusttunnel:quic", "TrustTunnel QUIC") == "TrustTunnel QUIC"
    names.set_global(state, "trusttunnel:quic", "Основной VPN")
    assert names.resolve(state, user, "trusttunnel:quic", "TrustTunnel QUIC") == "Основной VPN"
    names.set_user(state, user.email, "trusttunnel:quic", "Домашний")
    assert names.resolve(state, user, "trusttunnel:quic", "TrustTunnel QUIC") == "Домашний"


def test_empty_name_deletes_override_and_names_are_validated() -> None:
    state = AppState(users=[User(email="u@example.com", uuid="u")])
    names = ConfigurationNameService()
    names.set_global(state, "naive:https", "  Naive \u2713  ")
    names.set_user(state, "u@example.com", "naive:https", "Персональный")
    names.set_user(state, "u@example.com", "naive:https", "  ")

    assert state.configuration_names == {"naive:https": "Naive \u2713"}
    assert state.users[0].configuration_name_overrides == {}
    validate_state(state)
    with pytest.raises(ValueError, match="control"):
        names.set_global(state, "naive:https", "bad\nname")
    with pytest.raises(ValueError, match="128"):
        names.set_global(state, "naive:https", "x" * 129)


def test_old_state_without_name_fields_loads_with_empty_defaults(tmp_path, monkeypatch) -> None:
    from hydra.core import state as storage

    monkeypatch.setattr(storage, "STATE_DIR", tmp_path)
    monkeypatch.setattr(storage, "STATE_FILE", tmp_path / "state.json")
    storage.STATE_FILE.write_text(
        '{"format_version": 1, "revision": 0, "core": {"users": [{"email": "u", "uuid": "u"}]}, "features": {}}',
        encoding="utf-8",
    )

    loaded = storage.load_state()
    assert loaded.configuration_names == {}
    assert loaded.users[0].configuration_name_overrides == {}

    ConfigurationNameService().set_global(loaded, "naive:https", "Общий")
    ConfigurationNameService().set_user(loaded, "u", "naive:https", "Личный")
    storage.save_state(loaded)
    reloaded = storage.load_state()
    assert reloaded.configuration_names == {"naive:https": "Общий"}
    assert reloaded.users[0].configuration_name_overrides == {"naive:https": "Личный"}
