from __future__ import annotations

from hydra.core.state_creator_models import HeadlessCreatorConfig
from hydra.core.state_models import AppState, PluginState
from hydra.services.headless_creator import HeadlessCreatorService


class Runtime:
    def __init__(self) -> None:
        self.cookies_file = "/etc/hydra/cookiesvk/cookies-vk.json"
        self.cookies = [{"name": "remixsid", "value": "secret"}]
        self.hashes = ["one", "two", "three", "four"]
        self.metadata: dict[str, object] = {}
        self.commit_error: Exception | None = None
        self.forgotten = False
        self.legacy_restored = False
        self.legacy_cleanup_ok = True
        self.pool_rolled_back = False

    def creator_installed(self): return True
    def load_vk_cookies(self): return list(self.cookies)
    def validate_credentials(self): return list(self.cookies)
    def install_creator(self): return True, "installed"
    def refresh_creator_pool(self, *, previous=None): return list(self.hashes)
    def read_creator_hashes(self): return list(self.hashes)
    def pool_metadata(self): return dict(self.metadata)
    def finalize_creator_pool(self): return None
    def snapshot_legacy_creator(self): return {"legacy": "snapshot"}
    def stop_creator_pool(self): return True, "stopped"
    def uninstall_creator_pool(self): return True, "pool removed"
    def uninstall_creator(self): return True, "creator removed"

    def commit_pool(self, hashes):
        if self.commit_error:
            raise self.commit_error
        self.metadata = {"hashes": list(hashes), "refreshed_at": "now"}

    def rollback_creator_pool(self):
        self.pool_rolled_back = True

    def cleanup_legacy_creator(self):
        return self.legacy_cleanup_ok, "removed" if self.legacy_cleanup_ok else "failed"

    def restore_legacy_creator(self, snapshot):
        self.legacy_restored = snapshot == {"legacy": "snapshot"}

    def forget_credentials(self):
        self.forgotten = True
        self.cookies = []


class Actions:
    def __init__(self) -> None:
        self.link = "qwdtt://config?old=1"
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(self, plugin_name, action, **parameters):
        assert plugin_name == "wdtt"
        self.calls.append((action, parameters))
        if action == "update_call_pool_artifact":
            previous = self.link
            self.link = str(parameters.get("restore_link", "qwdtt://config?new=1"))
            return {"ok": True, "previous_link": previous}
        if action == "clear_call_pool_artifact":
            self.link = ""
            return True
        raise AssertionError(action)


def _service(runtime, actions=None, saves=None):
    return HeadlessCreatorService(
        runtime=runtime,
        plugin_actions=actions or Actions(),
        save_state=lambda state: (saves if saves is not None else []).append(state),
    )


def test_qwdtt_setup_publishes_hashes_under_creator_owner() -> None:
    runtime = Runtime()
    actions = Actions()
    state = AppState(protocols={"wdtt": PluginState(enabled=True)})

    result = _service(runtime, actions).setup_qwdtt_pool(state)

    assert result
    assert state.headless_creator.providers["vk"]["qwdtt_pool_enabled"] is True
    assert actions.calls[0][1]["hashes"] == runtime.hashes


def test_qwdtt_commit_failure_restores_previous_master_link() -> None:
    runtime = Runtime()
    runtime.commit_error = RuntimeError("metadata write failed")
    actions = Actions()
    state = AppState(protocols={"wdtt": PluginState(enabled=True)})

    result = _service(runtime, actions).setup_qwdtt_pool(state)

    assert not result
    assert actions.link == "qwdtt://config?old=1"
    assert state.headless_creator.providers == {}
    assert runtime.pool_rolled_back is True


def test_fresh_setup_restores_legacy_runtime_on_cleanup_failure() -> None:
    runtime = Runtime()
    runtime.legacy_cleanup_ok = False
    state = AppState(
        protocols={"wdtt": PluginState(enabled=True)},
        headless_creator=HeadlessCreatorConfig(providers={
            "vk": {"legacy_creator_reinstall_required": True},
        }),
    )

    result = _service(runtime).setup_qwdtt_pool(state)

    assert not result
    assert runtime.legacy_restored is True
    assert state.headless_creator.providers["vk"] == {
        "legacy_creator_reinstall_required": True,
    }


def test_credentials_are_shared_and_blocked_by_either_consumer() -> None:
    runtime = Runtime()
    service = _service(runtime)
    state = AppState(protocols={"calls": PluginState(enabled=True)})
    assert not service.forget_vk_credentials(state)

    state.protocols["calls"].enabled = False
    state.headless_creator.providers["vk"] = {"qwdtt_pool_enabled": True}
    assert not service.forget_vk_credentials(state)
    assert runtime.forgotten is False


def test_creator_core_cannot_be_removed_while_calls_is_enabled() -> None:
    state = AppState(protocols={"calls": PluginState(enabled=True)})
    result = _service(Runtime()).uninstall(state)
    assert not result
    assert "Calls" in result.error.message


def test_status_is_read_only_for_empty_creator_state() -> None:
    state = AppState()
    _service(Runtime()).status(state)
    assert state.headless_creator.providers == {}
