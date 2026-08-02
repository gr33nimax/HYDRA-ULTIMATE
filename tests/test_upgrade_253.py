from __future__ import annotations

import json
import shutil
from pathlib import Path

from hydra.core import state as state_module
from hydra.core.state_migrations import migrate_v2_to_v3


def test_v2_to_v3_only_adds_released_device_fields():
    source = {
        "version": 2,
        "users": [{"email": "legacy", "uuid": "token"}],
        "protocols": {},
        "network": {"warp_enabled": True},
        "security": {"fail2ban_enabled": True},
    }

    migrated = migrate_v2_to_v3(source)

    assert migrated == {
        "version": 3,
        "users": [{
            "email": "legacy",
            "uuid": "token",
            "device_limit": 0,
            "devices": {},
        }],
        "protocols": {},
        "network": {"warp_enabled": True},
        "security": {"fail2ban_enabled": True},
    }
    assert "revision" not in migrated


def test_253_schema_fixture_survives_v4_migration_and_round_trip(
    tmp_path,
    monkeypatch,
):
    fixture = Path(__file__).parent / "fixtures" / "state-2.5.3.json"
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    state_file = state_dir / "state.json"
    shutil.copy2(fixture, state_file)
    monkeypatch.setattr(state_module, "STATE_DIR", state_dir)
    monkeypatch.setattr(state_module, "STATE_FILE", state_file)

    first_migration = state_module.migrate_persisted_state()
    migrated_bytes = state_file.read_bytes()
    second_migration = state_module.migrate_persisted_state()

    assert first_migration == {"from": 3, "to": 6, "changed": True}
    assert second_migration == {"from": 6, "to": 6, "changed": False}
    assert state_file.read_bytes() == migrated_bytes

    loaded = state_module.load_state()

    assert loaded.version == state_module.SCHEMA_VERSION
    assert loaded.revision == 0
    assert loaded.users[0].device_limit == 2
    assert len(loaded.users[0].hydrabox_jwe_key) == 43
    assert loaded.users[0].devices == {
        "cd1fe8030198a45df90f44a04cda869fbbf799d4e78294337cdee955e1203658": {
            "first_seen": "2026-07-24T12:00:00+00:00",
            "last_seen": "2026-07-24T12:00:00+00:00",
            "source": "",
            "user_agent": "",
            "address": "",
        },
    }
    assert loaded.users[0].credentials["naive"]["password"] == "preserve-me"
    assert (
        loaded.users[0].credentials["custom-transport"]["token"]
        == "preserve-user-token"
    )
    assert loaded.install["private_runtime_value"] == "preserve-install-data"
    assert (
        loaded.protocols["warp"].config["private_key"]
        == "preserve-warp-private-key"
    )
    assert loaded.protocols["custom-transport"].enabled is True
    assert (
        loaded.protocols["custom-transport"].config["password"]
        == "preserve-custom-secret"
    )
    assert loaded.telegram.admin_token == "preserve-admin-token"
    assert loaded.telegram.bot_token == "preserve-user-bot-token"
    assert loaded.telegram.allowed_users == [123456, 654321]
    assert loaded.network.clash_api_secret == "preserve-clash-secret"
    assert loaded.protocols["warp"].enabled is True
    assert loaded.protocols["dnscrypt"].enabled is True
    assert loaded.protocols["fail2ban"].enabled is True
    assert loaded.protocols["ipban"].enabled is True
    assert loaded.protocols["antidpi"].enabled is True
    assert "honeypot" not in loaded.protocols
    assert not hasattr(loaded.network, "warp_enabled")
    assert not hasattr(loaded.network, "dnscrypt_enabled")
    assert not hasattr(loaded, "security")

    state_module.save_state(loaded)
    reloaded = state_module.load_state()
    persisted = json.loads(state_file.read_text(encoding="utf-8"))

    assert reloaded.users[0].device_limit == 2
    assert reloaded.users[0].devices == loaded.users[0].devices
    assert persisted["users"][0]["devices"] == loaded.users[0].devices
    assert persisted["telegram"]["admin_token"] == "preserve-admin-token"
    assert (
        persisted["protocols"]["custom-transport"]["config"]["password"]
        == "preserve-custom-secret"
    )
    assert persisted["network"]["clash_api_secret"] == "preserve-clash-secret"
    assert "security" not in persisted
    assert "warp_enabled" not in persisted["network"]
    assert "dnscrypt_enabled" not in persisted["network"]
