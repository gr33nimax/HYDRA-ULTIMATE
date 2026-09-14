from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from hydra.core.host import HostBackend
from hydra.core.state_creator_models import HeadlessCreatorConfig
from hydra.core.state_models import AppState, PluginState, User
from hydra.services.calls import CallsService
from hydra.services.calls_health import CallsProbeStore, ProbeDecision
from hydra.services.creator_sessions import (
    CreatorEndpoint,
    CreatorProviderAvailability,
    CreatorSessionGroup,
)


class Runtime:
    def __init__(self) -> None:
        self.multi = True
        self.links: list[str] = []
        self.tokens: list[str] = []
        self.running = True
        self.remove_error: Exception | None = None
        self.cookie_import_error: Exception | None = None
        self.imported_cookie_path: Path | None = None
        self.legacy_join_removed = False
        self.metadata: dict[str, object] = {}
        self.slot_snapshot: list[str] | None = None
        self.replaced_slot: int | None = None
        self.slot_finalized = False

    def stage_native_slot(self, slot: int):
        self.slot_snapshot = list(self.links)
        self.replaced_slot = slot
        self.links[slot - 1] = f"https://vk.com/call/join/replacement-{slot}"
        return list(self.links)

    def finalize_native_slot(self):
        self.slot_finalized = True

    def rollback_native_slot(self):
        if self.slot_snapshot is not None:
            self.links = self.slot_snapshot

    def vk_parasite_supported(self):
        return self.multi

    def ensure_creator_installed(self):
        return True, "installed"

    def import_vk_cookies(self, source_path: Path):
        if self.cookie_import_error:
            raise self.cookie_import_error
        self.imported_cookie_path = source_path

    def load_native_join_links(self):
        return list(self.links)

    def load_native_join_tokens(self):
        return list(self.tokens)

    def pool_metadata(self):
        return dict(self.metadata)

    def snapshot_native_pool(self):
        return (list(self.links), list(self.tokens))

    def restore_native_pool(self, snapshot):
        self.links, self.tokens = snapshot

    def uninstall_native_pool(self):
        self.links = []
        self.tokens = []
        return True, "removed"

    def remove_native_join_link(self):
        if self.remove_error:
            raise self.remove_error
        self.legacy_join_removed = True

    def singbox_running(self):
        return self.running


class Creator:
    def __init__(self, runtime: Runtime) -> None:
        self.runtime = runtime
        self.created = False
        self.committed = False
        self.finalized = False
        self.rolled_back = False
        self._previous_pool: tuple[list[str], list[str]] | None = None

    def availability(self, provider):
        assert provider == "vk"
        return CreatorProviderAvailability(True, True)

    def create(self, request):
        assert request.lifetime == "managed"
        assert request.consumer == "calls"
        self.created = True
        self._previous_pool = self.runtime.snapshot_native_pool()
        endpoints = tuple(
            CreatorEndpoint(
                f"https://vk.com/call/join/room-{index}",
                f"room-{index}",
            )
            for index in range(1, request.count + 1)
        )
        self.runtime.links = [endpoint.uri for endpoint in endpoints]
        self.runtime.tokens = [endpoint.token for endpoint in endpoints]
        return CreatorSessionGroup(request, endpoints)

    def commit(self, group):
        self.committed = True

    def finalize(self, group):
        self.finalized = True

    def rollback(self, group):
        self.rolled_back = True
        if self._previous_pool is not None:
            self.runtime.restore_native_pool(self._previous_pool)

    def close(self, group):
        return None

    def stop_managed(self, provider, consumer):
        assert (provider, consumer) == ("vk", "calls")
        self.runtime.links = []
        self.runtime.tokens = []
        return True, "stopped"


class Protocols:
    def __init__(self, *, outcome: bool = True, uninstall_outcome: bool = True) -> None:
        self.outcome = outcome
        self.uninstall_outcome = uninstall_outcome
        self.operations: list[str] = []

    def activate(self, state, name):
        self.operations.append("activate")
        desired = state.protocols.setdefault(name, PluginState())
        desired.installed = True
        desired.enabled = True
        return self.outcome

    def enable(self, state, name):
        self.operations.append("enable")
        state.protocols[name].enabled = True
        return self.outcome

    def disable(self, state, name):
        self.operations.append("disable")
        if not self.outcome:
            return False
        state.protocols[name].enabled = False
        return True

    def uninstall(self, state, name):
        self.operations.append("uninstall")
        if not self.uninstall_outcome:
            return False
        desired = state.protocols[name]
        desired.installed = False
        desired.enabled = False
        desired.config = {}
        desired.port = 0
        return True


def _state(*, installed: bool = False, enabled: bool = False) -> AppState:
    state = AppState(users=[User(email="alice@example.com", uuid="alice")])
    state.kernel.provider = "hydracore"
    state.network.server_ip = "203.0.113.10"
    if installed or enabled:
        state.protocols["calls"] = PluginState(
            installed=installed,
            enabled=enabled,
            config={"mode": "vk_parasite", "obfs_password": "o" * 43},
        )
    return state


def _service(runtime, protocols=None, *, apply=None, saves=None):
    creator = Creator(runtime)
    service = CallsService(
        runtime=runtime,
        creator=creator,
        protocols=protocols or Protocols(),
        save_state=lambda state: (saves if saves is not None else []).append(state),
        apply_config=apply or (lambda state: True),
        last_apply_error=lambda: "apply failed",
    )
    return service, creator


def test_native_enable_is_hydracore_vk_parasite_only() -> None:
    runtime = Runtime()
    protocols = Protocols()
    state = _state()
    service, creator = _service(runtime, protocols)

    result = service.enable_native_vk(state)

    assert result
    assert protocols.operations == ["activate"]
    assert result.value == {
        "operation": "enable",
        "profile": "admin",
        "mode": "vk_parasite",
        "rooms": 4,
    }
    assert state.protocols["calls"].enabled is True
    assert state.protocols["calls"].config["mode"] == "vk_parasite"
    assert state.protocols["calls"].config["workers"] == 4
    assert state.protocols["calls"].config["listen_port"] == 56002
    assert state.protocols["calls"].config["public_endpoint"] == "203.0.113.10"
    password = state.protocols["calls"].config["obfs_password"]
    assert isinstance(password, str)
    assert len(password) >= 32
    assert creator.committed and creator.finalized


def test_confirmed_room_replacement_keeps_other_rooms_and_applies_config() -> None:
    runtime = Runtime()
    runtime.links = [f"https://vk.com/call/join/room-{index}" for index in range(1, 5)]
    state = _state(installed=True, enabled=True)
    service, _creator = _service(runtime)

    result = service.replace_native_vk_slot(state, 2)

    assert result
    assert runtime.links == [
        "https://vk.com/call/join/room-1",
        "https://vk.com/call/join/replacement-2",
        "https://vk.com/call/join/room-3",
        "https://vk.com/call/join/room-4",
    ]
    assert runtime.slot_finalized is True


def test_failed_room_replacement_restores_the_prior_pool() -> None:
    runtime = Runtime()
    runtime.links = [f"https://vk.com/call/join/room-{index}" for index in range(1, 5)]
    state = _state(installed=True, enabled=True)
    service, _creator = _service(runtime, apply=lambda _state: False)

    result = service.replace_native_vk_slot(state, 3)

    assert not result
    assert runtime.links == [f"https://vk.com/call/join/room-{index}" for index in range(1, 5)]
    assert runtime.slot_finalized is False


def test_calls_status_exposes_redacted_probe_state(tmp_path) -> None:
    runtime = Runtime()
    runtime.links = [f"https://vk.com/call/join/room-{index}" for index in range(1, 5)]
    state = _state(installed=True, enabled=True)
    store = CallsProbeStore(HostBackend(), tmp_path / "probe-state.json")
    now = datetime.now(timezone.utc)
    decision = store.claim_due(runtime.links, now=now)
    assert decision is not None
    store.record(runtime.links, decision, "dead", now=now)
    service, _creator = _service(runtime)
    service.probe_store = store

    status = service.status(state)

    assert status.external_probe_outcome == "dead"
    assert status.external_probe_confirmation_pending is True
    assert "room-1" not in str(status.as_dict())


def test_full_rotation_resets_runtime_probe_history(tmp_path) -> None:
    runtime = Runtime()
    runtime.links = [f"https://vk.com/call/join/room-{index}" for index in range(1, 5)]
    runtime.tokens = [f"room-{index}" for index in range(1, 5)]
    state = _state(installed=True, enabled=True)
    store = CallsProbeStore(HostBackend(), tmp_path / "probe-state.json")
    decision = store.claim_due(runtime.links, now=datetime.now(timezone.utc))
    assert decision is not None
    store.record(runtime.links, decision, "healthy", now=datetime.now(timezone.utc))
    service, _creator = _service(runtime)
    service.probe_store = store

    assert service.rotate_native_vk(state)
    assert not store.path.exists()


def test_confirmed_dead_probe_replaces_only_the_failed_room(tmp_path) -> None:
    class DeadProbe:
        def verify(self, _link):
            return type("Result", (), {"outcome": "dead"})()

    runtime = Runtime()
    runtime.links = [f"https://vk.com/call/join/room-{index}" for index in range(1, 5)]
    state = _state(installed=True, enabled=True)
    store = CallsProbeStore(HostBackend(), tmp_path / "probe-state.json")
    started = datetime.now(timezone.utc) - timedelta(minutes=16)
    decision = store.claim_due(runtime.links, now=started)
    assert decision == ProbeDecision(1, False)
    assert decision is not None
    store.record(runtime.links, decision, "dead", now=started)
    service, _creator = _service(runtime)
    service.probe_store = store
    service.turn_probe = DeadProbe()

    result = service.run_health(state)

    assert result.value == {"operation": "replace", "slot": 1}
    assert runtime.replaced_slot == 1
    assert runtime.links[1:] == [f"https://vk.com/call/join/room-{index}" for index in range(2, 5)]


def test_set_workers_updates_the_single_calls_configuration_value() -> None:
    runtime = Runtime()
    state = _state(installed=True, enabled=True)
    applied: list[int] = []
    service, _ = _service(
        runtime,
        apply=lambda current: applied.append(current.protocols["calls"].config["workers"]) or True,
    )

    result = service.set_workers(state, 12)

    assert result.value == {"workers": 12}
    assert state.protocols["calls"].config["workers"] == 12
    assert "max_workers_per_session" not in state.protocols["calls"].config
    assert applied == [12]


def test_pool_rotation_schedule_is_persisted_and_uses_runtime_timestamp() -> None:
    runtime = Runtime()
    runtime.links = [f"https://vk.com/call/join/{index}" for index in range(4)]
    runtime.metadata["refreshed_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    state = _state(installed=True, enabled=True)
    service, _ = _service(runtime)

    assert service.set_pool_refresh_interval(state, 3600)
    assert service.set_pool_auto_refresh(state, True)
    assert service.pool_rotation_due(state) is True
    assert service.status(state).pool_auto_refresh is True
    assert service.status(state).pool_refresh_interval_seconds == 3600


def test_pool_refresh_interval_rejects_values_outside_one_to_24_hours() -> None:
    runtime = Runtime()
    state = _state(installed=True, enabled=True)
    service, _ = _service(runtime)

    assert not service.set_pool_refresh_interval(state, 3599)
    assert not service.set_pool_refresh_interval(state, 86_401)
    assert "pool_refresh_interval_seconds" not in state.protocols["calls"].config


def test_cookie_import_is_available_before_calls_installation() -> None:
    runtime = Runtime()
    state = _state()
    service, _ = _service(runtime)
    source_path = "/tmp/vk-cookies.json"

    result = service.import_vk_cookies(state, source_path)

    assert result.value == {"imported": True}
    assert runtime.imported_cookie_path == Path(source_path)
    assert "calls" not in state.protocols


def test_stock_core_is_rejected_without_starting_creator() -> None:
    runtime = Runtime()
    state = _state()
    state.kernel.provider = "sing-box-extended"
    service, creator = _service(runtime)

    result = service.enable_native_vk(state)

    assert not result
    assert result.error is not None
    assert "require the Hydracore kernel" in result.error.message
    assert creator.created is False
    assert "calls" not in state.protocols


def test_hydracore_without_exact_vk_parasite_contract_fails_closed() -> None:
    runtime = Runtime()
    runtime.multi = False
    state = _state()
    service, creator = _service(runtime)

    result = service.enable_native_vk(state)

    assert not result
    assert result.error is not None
    assert "exact call_vk_parasite" in result.error.message
    assert creator.created is False
    assert "calls" not in state.protocols


def test_explicit_legacy_p2p_state_is_rejected_before_creator() -> None:
    runtime = Runtime()
    state = _state(installed=True)
    state.protocols["calls"].config["mode"] = "p2p"
    service, creator = _service(runtime)

    result = service.reinstall_native_vk(state)

    assert not result
    assert result.error is not None
    assert "must be vk_parasite" in result.error.message
    assert creator.created is False


def test_native_apply_failure_rolls_back_pool_and_state() -> None:
    runtime = Runtime()
    runtime.links = ["https://vk.com/call/join/old-room"]
    runtime.tokens = ["old-room"]
    protocols = Protocols(outcome=False)
    state = _state(installed=True)
    saves: list[AppState] = []
    service, creator = _service(runtime, protocols, saves=saves)

    result = service.enable_native_vk(state)

    assert not result
    assert state.protocols["calls"].enabled is False
    assert runtime.links == ["https://vk.com/call/join/old-room"]
    assert creator.rolled_back is True
    assert saves


def test_enable_rejects_duplicate_managed_rooms_and_rolls_back() -> None:
    runtime = Runtime()
    state = _state()
    service, creator = _service(runtime)

    def duplicate_pool(request):
        creator.created = True
        endpoint = CreatorEndpoint(
            "https://vk.com/call/join/duplicate",
            "duplicate",
        )
        endpoints = tuple(endpoint for _ in range(request.count))
        runtime.links = [item.uri for item in endpoints]
        return CreatorSessionGroup(request, endpoints)

    creator.create = duplicate_pool

    result = service.enable_native_vk(state)

    assert not result
    assert result.error is not None
    assert "incomplete Calls room pool" in result.error.message
    assert creator.committed is False
    assert creator.rolled_back is True
    assert "calls" not in state.protocols


def test_reinstall_of_migrated_disabled_calls_creates_managed_pool() -> None:
    runtime = Runtime()
    protocols = Protocols()
    state = _state(installed=True)
    service, creator = _service(runtime, protocols)

    result = service.reinstall_native_vk(state)

    assert result
    assert protocols.operations == ["enable"]
    assert state.protocols["calls"].enabled is True
    assert len(runtime.links) == 4
    assert creator.created and creator.finalized


def test_admin_client_profile_uses_vk_parasite_and_keeps_metadata_alias() -> None:
    runtime = Runtime()
    runtime.links = [
        "https://vk.com/call/join/one",
        "https://vk.com/call/join/two",
        "https://vk.com/call/join/three",
        "https://vk.com/call/join/four",
    ]
    state = _state(installed=True, enabled=True)
    service, _ = _service(runtime)

    profile = service.native_client_profile(state)
    payload = profile.as_dict()
    config = json.loads(profile.config)
    outbound = config["outbounds"][0]

    assert profile.name == "Hydra VK Tunnel"
    assert outbound["mode"] == "vk_parasite"
    assert outbound["join_links"] == runtime.links
    assert "join_link" not in outbound
    assert profile.join_link == runtime.links[0]
    assert payload["join_link"] == runtime.links[0]
    assert payload["join_links"] == tuple(runtime.links)


def test_admin_client_profile_uses_public_ip_instead_of_transport_sni() -> None:
    runtime = Runtime()
    runtime.links = [f"https://vk.com/call/join/{index}" for index in range(4)]
    state = _state(installed=True, enabled=True)
    state.network.server_ip = ""
    state.network.domain = "transport-sni.example"
    service, _ = _service(runtime)

    with patch("hydra.services.calls.public_ip", return_value="203.0.113.42"):
        profile = service.native_client_profile(state)

    outbound = json.loads(profile.config)["outbounds"][0]
    assert outbound["server"] == "203.0.113.42"
    assert outbound["server"] != state.network.domain


def test_admin_client_profile_prefers_persisted_calls_endpoint() -> None:
    runtime = Runtime()
    runtime.links = [f"https://vk.com/call/join/{index}" for index in range(4)]
    state = _state(installed=True, enabled=True)
    state.protocols["calls"].config["public_endpoint"] = "198.51.100.77"
    state.network.server_ip = "203.0.113.10"
    service, _ = _service(runtime)

    with patch("hydra.services.calls.public_ip") as probe:
        profile = service.native_client_profile(state)

    outbound = json.loads(profile.config)["outbounds"][0]
    assert outbound["server"] == "198.51.100.77"
    probe.assert_not_called()


def test_status_keeps_native_link_ready_wire_key_with_pool_alias() -> None:
    runtime = Runtime()
    runtime.links = [f"https://vk.com/call/join/{index}" for index in range(4)]
    state = _state(installed=True, enabled=True)
    service, _ = _service(runtime)

    status = service.status(state)

    assert status.native_link_ready is True
    assert status.native_pool_ready is True
    assert status.as_dict()["native_link_ready"] is True
    assert status.as_dict()["native_mode"] == "vk_parasite"
    assert "native_pool_ready" not in status.as_dict()


def test_disable_failure_restores_managed_pool_and_state() -> None:
    runtime = Runtime()
    runtime.links = ["https://vk.com/call/join/working"]
    runtime.tokens = ["working"]
    state = _state(installed=True, enabled=True)
    service, _ = _service(runtime, Protocols(outcome=False))

    result = service.disable_native_vk(state)

    assert not result
    assert state.protocols["calls"].enabled is True
    assert runtime.links == ["https://vk.com/call/join/working"]


def test_uninstall_removes_pool_and_preserves_qwdtt_creator_state() -> None:
    runtime = Runtime()
    runtime.links = ["https://vk.com/call/join/working"]
    state = _state(installed=True, enabled=True)
    state.headless_creator = HeadlessCreatorConfig(
        consumers={"qwdtt": {"provider": "vk", "pool_enabled": True}},
    )
    protocols = Protocols()
    service, _ = _service(runtime, protocols)

    result = service.uninstall_native_vk(state)

    assert result
    assert protocols.operations == ["uninstall"]
    assert state.protocols["calls"].installed is False
    assert runtime.links == []
    assert runtime.legacy_join_removed is True
    assert state.headless_creator.consumers["qwdtt"]["pool_enabled"] is True


def test_uninstall_apply_failure_restores_state_and_pool() -> None:
    runtime = Runtime()
    runtime.links = ["https://vk.com/call/join/working"]
    runtime.tokens = ["working"]
    state = _state(installed=True, enabled=True)
    service, _ = _service(runtime, Protocols(uninstall_outcome=False))

    result = service.uninstall_native_vk(state)

    assert not result
    assert state.protocols["calls"].installed is True
    assert state.protocols["calls"].enabled is True
    assert runtime.links == ["https://vk.com/call/join/working"]


def test_legacy_artifact_cleanup_failure_rolls_back_state_and_pool() -> None:
    runtime = Runtime()
    runtime.links = ["https://vk.com/call/join/working"]
    runtime.tokens = ["working"]
    runtime.remove_error = OSError("legacy cleanup failed")
    state = _state(installed=True, enabled=True)
    service, _ = _service(runtime, Protocols())

    result = service.uninstall_native_vk(state)

    assert not result
    assert state.protocols["calls"].installed is True
    assert state.protocols["calls"].enabled is True
    assert runtime.links == ["https://vk.com/call/join/working"]
