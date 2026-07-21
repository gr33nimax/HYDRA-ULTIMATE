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
    load_state, save_state, update_state, find_user, add_user, get_protocol,
    STATE_FILE,
)


def test_app_state_defaults():
    """Пустое состояние имеет корректные значения по умолчанию."""
    state = AppState()
    assert state.version == 2
    assert state.protocols == {}
    assert state.users == []
    assert isinstance(state.telegram, TelegramConfig)
    assert state.telegram.notifications_enabled is True
    assert state.telegram.notify_antidpi is True
    assert state.telegram.notify_honeypot is True
    assert state.telegram.notify_fail2ban is True
    assert state.telegram.notify_unbans is False
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


def test_add_user_rejects_duplicate_uuid_for_different_email():
    import pytest
    from hydra.core.state import add_user

    state = AppState(users=[User(email="first@example.com", uuid="same")])
    with pytest.raises(ValueError, match="UUID"):
        add_user(state, User(email="second@example.com", uuid="same"))


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
            state_mod.STATE_DIR = Path(original).parent


def test_stale_settings_save_preserves_newer_traffic_counters(tmp_path):
    import hydra.core.state as state_mod

    original_file, original_dir = state_mod.STATE_FILE, state_mod.STATE_DIR
    try:
        state_mod.STATE_FILE = tmp_path / "state.json"
        state_mod.STATE_DIR = tmp_path
        initial = AppState(users=[User(email="u@example.com", uuid="u1")])
        save_state(initial)

        stale = load_state()
        latest = load_state()
        latest.users[0].traffic_used_bytes = 500
        latest.users[0].credentials["anytls"] = {"traffic_used_bytes": 500}
        latest.install["traffic_connection_counters"] = {"c1": {"total": 500}}
        save_state(latest)
        update_state(lambda current: current.install.__setitem__("sync_config_pending", True))

        stale.network.domain = "changed.example"
        save_state(stale)
        merged = load_state()
        assert merged.network.domain == "changed.example"
        assert merged.users[0].traffic_used_bytes == 500
        assert merged.users[0].credentials["anytls"]["traffic_used_bytes"] == 500
        assert "c1" in merged.install["traffic_connection_counters"]
        assert merged.install["sync_config_pending"] is True

        stale_pending = load_state()
        update_state(lambda current: current.install.pop("sync_config_pending", None))
        stale_pending.network.domain = "stale.example"
        save_state(stale_pending)
        assert "sync_config_pending" not in load_state().install
    finally:
        state_mod.STATE_FILE, state_mod.STATE_DIR = original_file, original_dir


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


def test_protocol_state_roundtrip_preserves_lifecycle_and_config(tmp_path):
    """Loading state must not replace a populated PluginState with defaults."""
    import hydra.core.state as state_mod

    original_file, original_dir = state_mod.STATE_FILE, state_mod.STATE_DIR
    try:
        state_mod.STATE_FILE = tmp_path / "state.json"
        state_mod.STATE_DIR = tmp_path
        state = AppState(protocols={
            "anytls": PluginState(
                enabled=True,
                installed=True,
                port=20444,
                config={"domain": "anytls.example", "padding": ["1=1-2"]},
            ),
        })

        save_state(state)
        loaded = load_state()

        assert loaded.protocols["anytls"] == state.protocols["anytls"]
    finally:
        state_mod.STATE_FILE, state_mod.STATE_DIR = original_file, original_dir


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


def test_load_recovers_from_backup(tmp_path):
    import hydra.core.state as state_mod
    original_file, original_dir = state_mod.STATE_FILE, state_mod.STATE_DIR
    try:
        state_mod.STATE_DIR = tmp_path
        state_mod.STATE_FILE = tmp_path / "state.json"
        first = AppState()
        first.network.domain = "backup.example"
        save_state(first)
        second = AppState()
        second.network.domain = "current.example"
        save_state(second)
        state_mod.STATE_FILE.write_text("{broken", encoding="utf-8")

        assert load_state().network.domain == "backup.example"
    finally:
        state_mod.STATE_FILE, state_mod.STATE_DIR = original_file, original_dir


def test_load_recovers_from_structurally_invalid_state(tmp_path):
    import hydra.core.state as state_mod

    original_file, original_dir = state_mod.STATE_FILE, state_mod.STATE_DIR
    try:
        state_mod.STATE_FILE = tmp_path / "state.json"
        state_mod.STATE_DIR = tmp_path
        state_mod.STATE_FILE.write_text(json.dumps({"version": 2, "users": "invalid"}), encoding="utf-8")
        state_mod.STATE_FILE.with_suffix(".json.bak").write_text(
            json.dumps({"version": 2, "users": [], "protocols": {}}), encoding="utf-8"
        )
        assert load_state().users == []
    finally:
        state_mod.STATE_FILE, state_mod.STATE_DIR = original_file, original_dir


def test_update_state_is_atomic_mutation(tmp_path):
    import hydra.core.state as state_mod
    original_file, original_dir = state_mod.STATE_FILE, state_mod.STATE_DIR
    try:
        state_mod.STATE_DIR = tmp_path
        state_mod.STATE_FILE = tmp_path / "state.json"
        save_state(AppState())

        state, result = state_mod.update_state(
            lambda current: current.install.setdefault("updates", 1)
        )
        assert result == 1
        assert state.install["updates"] == 1
        assert load_state().install["updates"] == 1
    finally:
        state_mod.STATE_FILE, state_mod.STATE_DIR = original_file, original_dir
