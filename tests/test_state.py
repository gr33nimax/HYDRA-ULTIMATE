"""
tests/test_state.py — Тесты для модуля state.
"""
import json
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.core.state import (
    AppState, ProtocolState, User, TelegramConfig, NetworkConfig, SecurityConfig,
    load_state, save_state, find_user, add_user, get_protocol,
    STATE_FILE,
)


def test_app_state_defaults():
    """Пустое состояние имеет корректные значения по умолчанию."""
    state = AppState()
    assert state.version == 1
    assert state.protocols == {}
    assert state.users == []
    assert isinstance(state.telegram, TelegramConfig)
    assert isinstance(state.network, NetworkConfig)
    assert isinstance(state.security, SecurityConfig)


def test_add_and_find_user():
    """Добавление и поиск пользователя."""
    state = AppState()
    user = User(email="test@example.com", uuid="abc-123", traffic_limit_gb=10)
    add_user(state, user)

    found = find_user(state, "test@example.com")
    assert found is not None
    assert found.email == "test@example.com"
    assert found.uuid == "abc-123"
    assert found.traffic_limit_gb == 10


def test_add_user_replace():
    """Повторное добавление заменяет существующего."""
    state = AppState()
    u1 = User(email="test@example.com", uuid="aaa", traffic_limit_gb=5)
    u2 = User(email="test@example.com", uuid="bbb", traffic_limit_gb=10)
    add_user(state, u1)
    add_user(state, u2)

    assert len(state.users) == 1
    assert state.users[0].uuid == "bbb"
    assert state.users[0].traffic_limit_gb == 10


def test_find_user_not_found():
    """Поиск несуществующего пользователя."""
    state = AppState()
    assert find_user(state, "nobody@example.com") is None


def test_get_protocol_creates():
    """get_protocol создаёт протокол, если его нет."""
    state = AppState()
    proto = get_protocol(state, "naiveproxy")
    assert isinstance(proto, ProtocolState)
    assert not proto.enabled
    assert "naiveproxy" in state.protocols


def test_save_and_load():
    """Сохранение и загрузка состояния."""
    import os

    state = AppState()
    user = User(email="test@example.com", uuid="test-uuid", traffic_limit_gb=25)
    add_user(state, user)
    state.network.domain = "example.com"

    with tempfile.TemporaryDirectory() as tmp:
        # Переопределяем STATE_FILE для теста
        original = str(STATE_FILE)
        try:
            import hydra.core.state as state_mod
            state_mod.STATE_FILE = Path(tmp) / "state.json"
            state_mod.STATE_DIR = Path(tmp)

            save_state(state)
            loaded = load_state()

            assert loaded.version == 1
            assert loaded.network.domain == "example.com"
            assert len(loaded.users) == 1
            assert loaded.users[0].email == "test@example.com"
            assert loaded.users[0].traffic_limit_gb == 25
        finally:
            state_mod.STATE_FILE = Path(original)


def test_user_blocking():
    """Блокировка пользователя."""
    state = AppState()
    user = User(email="test@example.com", uuid="test-uuid", blocked=False)
    add_user(state, user)

    user.blocked = True
    assert state.users[0].blocked is True


def test_protocol_state():
    """Состояние протокола."""
    proto = ProtocolState()
    assert not proto.enabled
    assert proto.port == 0
    assert not proto.installed

    proto.enabled = True
    proto.port = 8443
    proto.installed = True
    assert proto.enabled
    assert proto.port == 8443
