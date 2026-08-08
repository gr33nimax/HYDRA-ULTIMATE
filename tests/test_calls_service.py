from __future__ import annotations

import json
from types import SimpleNamespace

from hydra.core.state_models import AppState, PluginState
from hydra.services.calls import CallsService


class Runtime:
    def __init__(self) -> None:
        self.supported = True
        self.cookies = [{"name": "remixsid", "value": "secret"}]
        self.link = "https://vk.com/call/join/old-room"
        self.new_link = "https://vk.com/call/join/new-room"
        self.handoff = True
        self.closed = False
        self.hashes = ["one", "two", "three", "four"]
        self.metadata: dict[str, object] = {}
        self.commit_error: Exception | None = None
        self.forgotten = False
        self.legacy_restored = False
        self.legacy_cleanup_ok = True
        self.pool_rolled_back = False

    def feature_supported(self):
        return self.supported

    def load_vk_cookies(self):
        return list(self.cookies)

    def validate_credentials(self):
        if not self.cookies:
            raise ValueError("VK cookies are missing")
        return list(self.cookies)

    def load_native_join_link(self):
        return self.link

    def write_native_join_link(self, link):
        self.link = link

    def remove_native_join_link(self):
        self.link = ""

    def singbox_running(self):
        return True

    def start_native_bootstrap(self, cookies):
        assert cookies == self.cookies
        return SimpleNamespace(join_link=self.new_link)

    def close_native_bootstrap(self, bootstrap):
        self.closed = True

    def wait_main_join(self, link):
        assert link == self.new_link
        return self.handoff

    def install_creator(self):
        return True, "installed"

    def refresh_creator_pool(self, *, previous=None):
        return list(self.hashes)

    def read_creator_hashes(self):
        return list(self.hashes)

    def pool_metadata(self):
        return dict(self.metadata)

    def commit_pool(self, hashes):
        if self.commit_error:
            raise self.commit_error
        self.metadata = {"hashes": list(hashes), "refreshed_at": "now"}

    def finalize_creator_pool(self):
        return None

    def rollback_creator_pool(self):
        self.pool_rolled_back = True

    def cleanup_legacy_creator(self):
        return self.legacy_cleanup_ok, "removed" if self.legacy_cleanup_ok else "cleanup failed"

    def snapshot_legacy_creator(self):
        return {"legacy": "snapshot"}

    def restore_legacy_creator(self, snapshot):
        assert snapshot == {"legacy": "snapshot"}
        self.legacy_restored = True

    def stop_creator_pool(self):
        return True, "stopped"

    def uninstall_creator_pool(self):
        return True, "uninstalled"

    def forget_credentials(self):
        self.forgotten = True
        self.cookies = []


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


class Actions:
    def __init__(self) -> None:
        self.link = "qwdtt://config?old=1"
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(self, plugin_name, action, **parameters):
        assert plugin_name == "wdtt"
        self.calls.append((action, parameters))
        if action == "update_call_pool_artifact":
            previous = self.link
            if "restore_link" in parameters:
                self.link = str(parameters["restore_link"])
            else:
                self.link = "qwdtt://config?new=1"
            return {"ok": True, "previous_link": previous}
        if action == "clear_call_pool_artifact":
            self.link = ""
            return True
        raise AssertionError(action)


def _service(
    runtime: Runtime,
    protocols: Protocols | None = None,
    actions: Actions | None = None,
    *,
    apply=None,
    saves: list[AppState] | None = None,
) -> CallsService:
    snapshots = saves if saves is not None else []
    return CallsService(
        runtime=runtime,
        protocols=protocols or Protocols(),
        plugin_actions=actions or Actions(),
        save_state=lambda state: snapshots.append(state),
        apply_config=apply or (lambda state: True),
        last_apply_error=lambda: "apply failed",
    )


def test_native_enable_bootstraps_applies_and_hands_off_before_close() -> None:
    runtime = Runtime()
    runtime.link = ""
    protocols = Protocols()
    state = AppState()

    result = _service(runtime, protocols).enable_native_vk(state)

    assert result
    assert protocols.operations == ["activate"]
    assert state.protocols["calls"].enabled is True
    assert runtime.link == runtime.new_link
    assert runtime.closed is True


def test_native_enable_is_blocked_by_feature_probe_without_state_change() -> None:
    runtime = Runtime()
    runtime.supported = False
    state = AppState(protocols={"calls": PluginState()})

    result = _service(runtime).enable_native_vk(state)

    assert not result
    assert "Extended" in result.error.message
    assert state.protocols["calls"].enabled is False


def test_native_apply_failure_restores_previous_link_and_desired_state() -> None:
    runtime = Runtime()
    protocols = Protocols(outcome=False)
    state = AppState(protocols={"calls": PluginState(installed=True, enabled=False)})
    saves: list[AppState] = []

    result = _service(runtime, protocols, saves=saves).enable_native_vk(state)

    assert not result
    assert runtime.link == "https://vk.com/call/join/old-room"
    assert state.protocols["calls"].enabled is False
    assert runtime.closed is True
    assert saves


def test_rotation_handoff_timeout_restores_old_working_link_and_runtime() -> None:
    runtime = Runtime()
    runtime.handoff = False
    state = AppState(protocols={"calls": PluginState(installed=True, enabled=True)})
    applies: list[str] = []

    result = _service(
        runtime,
        apply=lambda state: applies.append(runtime.link) or True,
    ).rotate_native_vk(state)

    assert not result
    assert runtime.link == "https://vk.com/call/join/old-room"
    assert applies == [
        "https://vk.com/call/join/new-room",
        "https://vk.com/call/join/old-room",
    ]


def test_admin_client_profile_is_fixed_joiner_json() -> None:
    runtime = Runtime()
    state = AppState(
        protocols={
            "calls": PluginState(
                installed=True,
                enabled=True,
                config={"read_buffer": 65536},
            ),
        },
    )

    profile = _service(runtime).native_client_profile(state)
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


def test_qwdtt_setup_publishes_four_hashes_and_persists_calls_owner() -> None:
    runtime = Runtime()
    actions = Actions()
    state = AppState(protocols={"wdtt": PluginState(enabled=True)})

    result = _service(runtime, actions=actions).setup_qwdtt_pool(state)

    assert result
    assert state.protocols["calls"].config["qwdtt_pool_enabled"] is True
    assert actions.calls[0][1]["hashes"] == ["one", "two", "three", "four"]
    assert runtime.metadata["hashes"] == runtime.hashes


def test_qwdtt_commit_failure_restores_previous_master_link() -> None:
    runtime = Runtime()
    runtime.commit_error = RuntimeError("metadata write failed")
    actions = Actions()
    state = AppState(protocols={"wdtt": PluginState(enabled=True)})

    result = _service(runtime, actions=actions).setup_qwdtt_pool(state)

    assert not result
    assert actions.link == "qwdtt://config?old=1"
    assert state.protocols.get("calls") is None
    assert runtime.pool_rolled_back is True


def test_fresh_setup_restores_legacy_creator_when_cleanup_partially_fails() -> None:
    runtime = Runtime()
    runtime.legacy_cleanup_ok = False
    actions = Actions()
    state = AppState(
        protocols={
            "wdtt": PluginState(enabled=True),
            "calls": PluginState(
                config={"legacy_creator_reinstall_required": True},
            ),
        },
    )

    result = _service(runtime, actions=actions).setup_qwdtt_pool(state)

    assert not result
    assert runtime.legacy_restored is True
    assert actions.link == "qwdtt://config?old=1"
    assert state.protocols["calls"].config == {
        "legacy_creator_reinstall_required": True,
    }


def test_credentials_cannot_be_removed_while_either_consumer_is_enabled() -> None:
    runtime = Runtime()
    state = AppState(protocols={"calls": PluginState(enabled=True)})
    assert not _service(runtime).forget_vk_credentials(state)
    assert runtime.forgotten is False

    state.protocols["calls"].enabled = False
    state.protocols["calls"].config["qwdtt_pool_enabled"] = True
    assert not _service(runtime).forget_vk_credentials(state)
    assert runtime.forgotten is False
