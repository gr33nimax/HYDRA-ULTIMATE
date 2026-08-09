from __future__ import annotations

import json

from hydra.core.state_creator_models import HeadlessCreatorConfig
from hydra.core.state_models import AppState, PluginState, User
from hydra.services.calls import CallsService
from hydra.services.creator_sessions import (
    CreatorEndpoint,
    CreatorProviderAvailability,
    CreatorSessionGroup,
)


class Runtime:
    def __init__(self) -> None:
        self.supported = True
        self.link = "https://vk.com/call/join/old-room"
        self.new_link = "https://vk.com/call/join/new-room"
        self.handoff = True
        self.remove_error: Exception | None = None
        self.multi = False
        self.links: list[str] = []
        self.tokens: list[str] = []

    def feature_supported(self):
        return self.supported

    def multi_user_supported(self):
        return self.multi

    def ensure_creator_installed(self):
        return True, "installed"

    def load_native_join_link(self):
        return self.link

    def load_native_join_links(self):
        return list(self.links)

    def load_native_join_tokens(self):
        return list(self.tokens)

    def snapshot_native_pool(self):
        return (list(self.links), list(self.tokens))

    def restore_native_pool(self, snapshot):
        self.links, self.tokens = snapshot

    def uninstall_native_pool(self):
        self.links = []
        self.tokens = []
        return True, "removed"

    def write_native_join_link(self, link):
        self.link = link

    def remove_native_join_link(self):
        self.link = ""
        if self.remove_error:
            raise self.remove_error

    def singbox_running(self):
        return True

    def wait_main_join(self, link):
        assert link == self.new_link
        return self.handoff


class Creator:
    def __init__(self, runtime: Runtime) -> None:
        self.runtime = runtime
        self.closed = False
        self.committed = False
        self.finalized = False
        self.rolled_back = False

    def availability(self, provider):
        assert provider == "vk"
        return CreatorProviderAvailability(True, True)

    def create(self, request):
        if request.lifetime == "managed":
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
        return CreatorSessionGroup(
            request,
            (CreatorEndpoint(self.runtime.new_link, "new-room"),),
        )

    def close(self, group):
        self.closed = True

    def commit(self, group):
        self.committed = True

    def finalize(self, group):
        self.finalized = True

    def rollback(self, group):
        self.rolled_back = True

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
        state.protocols[name].enabled = False
        return self.outcome

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


def test_native_enable_uses_shared_creator_then_hands_off() -> None:
    runtime = Runtime()
    runtime.link = ""
    protocols = Protocols()
    state = AppState()
    service, creator = _service(runtime, protocols)

    result = service.enable_native_vk(state)

    assert result
    assert protocols.operations == ["activate"]
    assert state.protocols["calls"].enabled is True
    assert runtime.link == runtime.new_link
    assert creator.closed is True


def test_native_enable_is_blocked_by_feature_probe_without_creator_start() -> None:
    runtime = Runtime()
    runtime.supported = False
    state = AppState(protocols={"calls": PluginState()})
    service, creator = _service(runtime)

    result = service.enable_native_vk(state)

    assert not result
    assert "Extended" in result.error.message
    assert creator.closed is False
    assert state.protocols["calls"].enabled is False


def test_native_apply_failure_restores_previous_link_and_state() -> None:
    runtime = Runtime()
    protocols = Protocols(outcome=False)
    state = AppState(protocols={"calls": PluginState(installed=True)})
    saves: list[AppState] = []
    service, creator = _service(runtime, protocols, saves=saves)

    result = service.enable_native_vk(state)

    assert not result
    assert runtime.link == "https://vk.com/call/join/old-room"
    assert state.protocols["calls"].enabled is False
    assert creator.closed is True
    assert saves


def test_rotation_timeout_restores_old_working_link_and_runtime() -> None:
    runtime = Runtime()
    runtime.handoff = False
    state = AppState(protocols={"calls": PluginState(installed=True, enabled=True)})
    applies: list[str] = []
    service, _ = _service(runtime, apply=lambda state: applies.append(runtime.link) or True)

    result = service.rotate_native_vk(state)

    assert not result
    assert runtime.link == "https://vk.com/call/join/old-room"
    assert applies == [runtime.new_link, "https://vk.com/call/join/old-room"]


def test_reinstall_recreates_room_and_enables_legacy_disabled_state() -> None:
    runtime = Runtime()
    protocols = Protocols()
    state = AppState(
        protocols={"calls": PluginState(installed=True, enabled=False)},
    )
    service, creator = _service(runtime, protocols)

    result = service.reinstall_native_vk(state)

    assert result
    assert protocols.operations == ["enable"]
    assert state.protocols["calls"].enabled is True
    assert runtime.link == runtime.new_link
    assert creator.closed is True


def test_admin_client_profile_is_fixed_joiner_json() -> None:
    runtime = Runtime()
    state = AppState(protocols={
        "calls": PluginState(
            installed=True,
            enabled=True,
            config={"read_buffer": 65536},
        ),
    })
    service, _ = _service(runtime)

    profile = service.native_client_profile(state)
    config = json.loads(profile.config)

    assert config["inbounds"][0]["type"] == "socks"
    assert config["inbounds"][0]["listen"] == "127.0.0.1"
    assert config["outbounds"] == [{
        "type": "call",
        "tag": "call-vk-out",
        "platform": "vk",
        "read_buffer": 65536,
        "join_link": runtime.link,
    }]
    assert config["route"]["final"] == "call-vk-out"


def test_hydracore_enable_creates_managed_pool_and_multi_user_state() -> None:
    runtime = Runtime()
    runtime.multi = True
    state = AppState(
        users=[User(email="alice@example.com", uuid="alice")],
    )
    state.network.server_ip = "203.0.113.10"
    state.kernel.provider = "hydracore"
    protocols = Protocols()
    service, creator = _service(runtime, protocols)

    result = service.enable_native_vk(state)

    assert result
    assert result.value["mode"] == "multi_user"
    assert result.value["rooms"] == 4
    assert state.protocols["calls"].config["mode"] == "multi_user"
    assert state.protocols["calls"].config["listen_port"] == 56002
    assert len(state.protocols["calls"].config["obfs_password"]) >= 32
    assert creator.committed is True
    assert creator.finalized is True
    assert creator.closed is False


def test_hydracore_enable_rejects_duplicate_managed_rooms() -> None:
    runtime = Runtime()
    runtime.multi = True
    state = AppState(users=[User(email="alice@example.com", uuid="alice")])
    state.kernel.provider = "hydracore"
    service, creator = _service(runtime)

    def duplicate_pool(request):
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
    assert "incomplete Calls room pool" in result.error.message
    assert creator.committed is False
    assert creator.rolled_back is True
    assert "calls" not in state.protocols


def test_selected_hydracore_fails_closed_without_exact_multi_user_contract() -> None:
    runtime = Runtime()
    state = AppState()
    state.kernel.provider = "hydracore"
    saves: list[AppState] = []
    applies: list[AppState] = []
    service, creator = _service(
        runtime,
        saves=saves,
        apply=lambda current: applies.append(current) or True,
    )

    result = service.enable_native_vk(state)

    assert not result
    assert "exact call_vk_multi_user" in result.error.message
    assert creator.committed is False
    assert "calls" not in state.protocols
    assert saves == []
    assert applies == []


def test_uninstall_removes_calls_and_link_but_preserves_shared_creator_state() -> None:
    runtime = Runtime()
    protocols = Protocols()
    state = AppState(
        protocols={"calls": PluginState(installed=True, enabled=True)},
        headless_creator=HeadlessCreatorConfig(
            consumers={"qwdtt": {"provider": "vk", "pool_enabled": True}},
        ),
    )
    service, _ = _service(runtime, protocols)

    result = service.uninstall_native_vk(state)

    assert result
    assert protocols.operations == ["uninstall"]
    assert state.protocols["calls"].installed is False
    assert runtime.link == ""
    assert state.headless_creator.consumers["qwdtt"]["pool_enabled"] is True


def test_uninstall_apply_failure_preserves_state_and_link() -> None:
    runtime = Runtime()
    protocols = Protocols(uninstall_outcome=False)
    state = AppState(
        protocols={"calls": PluginState(installed=True, enabled=True)},
    )
    service, _ = _service(runtime, protocols)

    result = service.uninstall_native_vk(state)

    assert not result
    assert state.protocols["calls"].installed is True
    assert state.protocols["calls"].enabled is True
    assert runtime.link == "https://vk.com/call/join/old-room"


def test_uninstall_link_cleanup_failure_rolls_back_state_link_and_runtime() -> None:
    runtime = Runtime()
    runtime.remove_error = OSError("link cleanup failed")
    protocols = Protocols()
    applies: list[str] = []
    state = AppState(
        protocols={"calls": PluginState(installed=True, enabled=True)},
    )
    service, _ = _service(
        runtime,
        protocols,
        apply=lambda current: applies.append(runtime.link) or True,
    )

    result = service.uninstall_native_vk(state)

    assert not result
    assert state.protocols["calls"].installed is True
    assert state.protocols["calls"].enabled is True
    assert runtime.link == "https://vk.com/call/join/old-room"
    assert applies == ["https://vk.com/call/join/old-room"]
