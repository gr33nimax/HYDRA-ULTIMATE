from __future__ import annotations

import json
from types import SimpleNamespace

from hydra.core.state_models import AppState, PluginState
from hydra.services.calls import CallsService


class Runtime:
    def __init__(self) -> None:
        self.supported = True
        self.link = "https://vk.com/call/join/old-room"
        self.new_link = "https://vk.com/call/join/new-room"
        self.handoff = True

    def feature_supported(self):
        return self.supported

    def load_native_join_link(self):
        return self.link

    def write_native_join_link(self, link):
        self.link = link

    def remove_native_join_link(self):
        self.link = ""

    def singbox_running(self):
        return True

    def wait_main_join(self, link):
        assert link == self.new_link
        return self.handoff


class Creator:
    def __init__(self, runtime: Runtime) -> None:
        self.runtime = runtime
        self.closed = False

    def status(self, state):
        return SimpleNamespace(installed=True, cookies_ready=True)

    def start_vk_room(self):
        return SimpleNamespace(join_link=self.runtime.new_link)

    def close_vk_room(self, bootstrap):
        self.closed = True


class Protocols:
    def __init__(self, *, outcome: bool = True) -> None:
        self.outcome = outcome
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
