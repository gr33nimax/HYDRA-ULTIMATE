"""
tests/test_state.py — Тесты для модуля state.
"""
import json
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from hydra.core.state import (
    AppState, PluginState, User, TelegramConfig, NetworkConfig, SecurityConfig,
    load_state, save_state, find_user, add_user, get_protocol,
    STATE_FILE,
)


def test_app_state_defaults():
    """Пустое состояние имеет корректные значения по умолчанию."""
    state = AppState()
    assert state.version == 2
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
    assert isinstance(proto, PluginState)
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

            assert loaded.version == 2
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


def test_plugin_state():
    """Состояние плагина (переименован из ProtocolState → PluginState)."""
    proto = PluginState()
    assert not proto.enabled
    assert proto.port == 0
    assert not proto.installed

    proto.enabled = True
    proto.port = 8443
    proto.installed = True
    assert proto.enabled
    assert proto.port == 8443


def test_roundtrip_with_credentials():
    """Сохранение и загрузка User с credentials → поля совпадают."""
    state = AppState()
    user = User(
        email="cred@example.com",
        uuid="cred-uuid-111",
        credentials={"mieru": {"username": "u_abc", "password": "p_xyz"}},
    )
    add_user(state, user)

    with tempfile.TemporaryDirectory() as tmp:
        import hydra.core.state as state_mod
        orig_file = state_mod.STATE_FILE
        orig_dir = state_mod.STATE_DIR
        try:
            state_mod.STATE_DIR = Path(tmp)
            state_mod.STATE_FILE = Path(tmp) / "state.json"

            save_state(state)
            loaded = load_state()
        finally:
            state_mod.STATE_FILE = orig_file
            state_mod.STATE_DIR = orig_dir

    assert len(loaded.users) == 1
    u = loaded.users[0]
    assert u.email == "cred@example.com"
    assert u.credentials == {"mieru": {"username": "u_abc", "password": "p_xyz"}}


def test_migrate_v1_to_v2():
    """Подать v1-словарь без credentials/tproxy → после load_state версия 2, поля есть."""
    v1_data = {
        "version": 1,
        "install": {},
        "protocols": {},
        "users": [
            {"email": "old@example.com", "uuid": "old-uuid",
             "traffic_limit_gb": 5, "traffic_used_bytes": 0,
             "expiry_date": "", "blocked": False,
             "created_at": "", "telegram_id": None}
        ],
        "telegram": {},
        "network": {"domain": "", "server_ip": ""},
        "security": {},
    }

    with tempfile.TemporaryDirectory() as tmp:
        import hydra.core.state as state_mod
        orig_file = state_mod.STATE_FILE
        orig_dir = state_mod.STATE_DIR
        try:
            state_mod.STATE_DIR = Path(tmp)
            state_mod.STATE_FILE = Path(tmp) / "state.json"

            import json as _json
            (Path(tmp) / "state.json").write_text(
                _json.dumps(v1_data), encoding="utf-8"
            )
            loaded = load_state()
        finally:
            state_mod.STATE_FILE = orig_file
            state_mod.STATE_DIR = orig_dir

    # Версия должна мигрировать до 2
    assert loaded.version == 2
    # credentials добавлены каждому пользователю
    assert loaded.users[0].credentials == {}
    # tproxy-поля появились в NetworkConfig
    assert loaded.network.tproxy_enabled is False
    assert loaded.network.tproxy_port == 1081


def test_singbox_generate_config_tproxy_reject_rule():
    """Тест генерации конфига sing-box с правилом защиты от петель TPROXY."""
    from hydra.core.singbox import generate_config
    state = AppState()
    state.network.tproxy_enabled = True
    state.network.tproxy_port = 1081
    
    config = generate_config(state, {})
    
    rules = config.get("route", {}).get("rules", [])
    reject_rule = None
    for rule in rules:
        if rule.get("action") == "reject":
            reject_rule = rule
            break
            
    assert reject_rule is not None
    assert reject_rule["inbound"] == ["tproxy-in"]
    assert reject_rule["port"] == [1081]
