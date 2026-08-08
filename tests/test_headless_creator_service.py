from __future__ import annotations

from hydra.core.state_creator_models import HeadlessCreatorConfig
from hydra.core.state_models import AppState, PluginState
from hydra.services.creator_sessions import CreatorEndpoint, CreatorSessionGroup
from hydra.services.headless_creator import HeadlessCreatorService
from hydra.services.qwdtt_creator import NoopOperationLock, QwdttCreatorService


class Runtime:
    def __init__(self) -> None:
        self.cookies_file = "/etc/hydra/cookiesvk/cookies-vk.json"
        self.cookies = [{"name": "remixsid", "value": "secret"}]
        self.hashes = ["one", "two", "three", "four"]
        self.metadata: dict[str, object] = {}
        self.installed = True
        self.commit_error: Exception | None = None
        self.finalize_error: Exception | None = None
        self.forgotten = False
        self.legacy_restored = False
        self.legacy_cleanup_ok = True
        self.pool_rolled_back = False
        self.pool_restored = False
        self.last_count = 0

    def creator_installed(self): return self.installed
    def creator_credentials_path(self): return str(self.cookies_file)
    def creator_credentials_ready(self): return bool(self.load_vk_cookies())
    def load_vk_cookies(self): return list(self.cookies)
    def count_valid_creator_rooms(self): return len(set(self.hashes))
    def validate_credentials(self): return list(self.cookies)
    def install_creator(self): return True, "installed"
    def read_creator_hashes(self): return list(self.hashes)
    def pool_metadata(self): return dict(self.metadata)
    def finalize_creator_pool(self):
        if self.finalize_error:
            raise self.finalize_error
    def snapshot_legacy_creator(self): return {"legacy": "snapshot"}
    def snapshot_creator_pool(self): return {"pool": "snapshot"}
    def stop_creator_pool(self): return True, "stopped"
    def uninstall_creator_pool(self): return True, "pool removed"
    def uninstall_creator(self): return True, "creator removed"

    def refresh_creator_pool(self, *, previous=None, count=4):
        self.last_count = count
        return list(self.hashes[:count])

    def commit_pool(self, hashes, *, count=None):
        if self.commit_error:
            raise self.commit_error
        self.metadata = {
            "hashes": list(hashes),
            "refreshed_at": "now",
            "room_count": count,
        }

    def rollback_creator_pool(self):
        self.pool_rolled_back = True

    def restore_creator_pool(self, snapshot):
        self.pool_restored = snapshot == {"pool": "snapshot"}

    def cleanup_legacy_creator(self):
        return self.legacy_cleanup_ok, "removed" if self.legacy_cleanup_ok else "failed"

    def restore_legacy_creator(self, snapshot):
        self.legacy_restored = snapshot == {"legacy": "snapshot"}

    def forget_credentials(self):
        self.forgotten = True
        self.cookies = []


class Sessions:
    def __init__(self, runtime: Runtime) -> None:
        self.runtime = runtime

    def create(self, request):
        hashes = self.runtime.refresh_creator_pool(
            previous=list(request.previous_tokens),
            count=request.count,
        )
        return CreatorSessionGroup(
            request,
            tuple(CreatorEndpoint("", token) for token in hashes),
        )

    def commit(self, group):
        self.runtime.commit_pool(
            [endpoint.token for endpoint in group.endpoints],
            count=group.request.count,
        )

    def finalize(self, group):
        self.runtime.finalize_creator_pool()

    def rollback(self, group):
        self.runtime.rollback_creator_pool()

    def stop_managed(self, provider, consumer):
        assert (provider, consumer) == ("vk", "qwdtt")
        return self.runtime.stop_creator_pool()


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
            previous = self.link
            self.link = ""
            return {"ok": True, "previous_link": previous}
        raise AssertionError(action)


def _service(runtime, actions=None, saves=None, save_state=None, operation_lock=None):
    actions = actions or Actions()
    save = save_state or (
        lambda state: (saves if saves is not None else []).append(state)
    )
    qwdtt = QwdttCreatorService(
        sessions=Sessions(runtime),
        runtime=runtime,
        plugin_actions=actions,
        save_state=save,
        operation_lock=operation_lock or NoopOperationLock(),
    )
    return HeadlessCreatorService(providers={"vk": runtime}, qwdtt=qwdtt)


def _qwdtt_state(*, enabled: bool = False, count: int = 4) -> HeadlessCreatorConfig:
    return HeadlessCreatorConfig(consumers={"qwdtt": {
        "provider": "vk",
        "pool_enabled": enabled,
        "room_count": count,
    }})


def test_qwdtt_setup_publishes_requested_number_of_hashes() -> None:
    runtime = Runtime()
    actions = Actions()
    state = AppState(
        protocols={"wdtt": PluginState(enabled=True)},
        headless_creator=_qwdtt_state(count=2),
    )

    result = _service(runtime, actions).setup_qwdtt_pool(state)

    assert result
    assert state.headless_creator.consumers["qwdtt"]["pool_enabled"] is True
    assert actions.calls[0][1]["hashes"] == ["one", "two"]
    assert runtime.last_count == 2


def test_qwdtt_operation_is_rejected_when_another_process_holds_the_lock() -> None:
    class BusyLock:
        def try_acquire(self): return None

    runtime = Runtime()
    actions = Actions()
    state = AppState(
        protocols={"wdtt": PluginState(enabled=True)},
        headless_creator=_qwdtt_state(count=2),
    )

    result = _service(runtime, actions, operation_lock=BusyLock()).setup_qwdtt_pool(state)

    assert not result
    assert "another qWDTT creator operation" in result.error.message
    assert runtime.last_count == 0
    assert actions.calls == []


def test_qwdtt_commit_failure_restores_previous_master_link() -> None:
    runtime = Runtime()
    runtime.commit_error = RuntimeError("metadata write failed")
    actions = Actions()
    state = AppState(protocols={"wdtt": PluginState(enabled=True)})

    result = _service(runtime, actions).setup_qwdtt_pool(state)

    assert not result
    assert actions.link == "qwdtt://config?old=1"
    assert state.headless_creator.consumers == {}
    assert runtime.pool_rolled_back is True


def test_fresh_setup_restores_legacy_runtime_on_cleanup_failure() -> None:
    runtime = Runtime()
    runtime.legacy_cleanup_ok = False
    state = AppState(
        protocols={"wdtt": PluginState(enabled=True)},
        headless_creator=HeadlessCreatorConfig(consumers={"qwdtt": {
            "provider": "vk",
            "legacy_creator_reinstall_required": True,
            "room_count": 4,
        }}),
    )

    result = _service(runtime).setup_qwdtt_pool(state)

    assert not result
    assert runtime.legacy_restored is True
    assert state.headless_creator.consumers["qwdtt"] == {
        "provider": "vk",
        "legacy_creator_reinstall_required": True,
        "room_count": 4,
    }


def test_credentials_are_shared_and_blocked_by_either_consumer() -> None:
    runtime = Runtime()
    service = _service(runtime)
    state = AppState(protocols={"calls": PluginState(enabled=True)})
    assert not service.forget_vk_credentials(state)

    state.protocols["calls"].enabled = False
    state.headless_creator = _qwdtt_state(enabled=True)
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
    assert state.headless_creator.consumers == {}


def test_status_reports_cookie_path_partial_and_desired_room_count() -> None:
    runtime = Runtime()
    runtime.hashes = ["one", "two", "two"]
    state = AppState(headless_creator=_qwdtt_state(count=6))

    status = _service(runtime).status(state)

    assert status.installed is True
    assert status.cookies_ready is True
    assert status.cookies_path == "/etc/hydra/cookiesvk/cookies-vk.json"
    assert status.vk_qwdtt_call_count == 2
    assert status.vk_qwdtt_room_count == 6


def test_status_marks_vk_cookies_not_ready_when_file_is_invalid_or_missing() -> None:
    runtime = Runtime()
    runtime.cookies = []
    assert _service(runtime).status(AppState()).cookies_ready is False


def test_status_reports_uninstalled_creator_from_runtime() -> None:
    runtime = Runtime()
    runtime.installed = False
    assert _service(runtime).status(AppState()).installed is False


def test_qwdtt_refresh_replaces_the_existing_pool() -> None:
    runtime = Runtime()
    actions = Actions()
    state = AppState(
        protocols={"wdtt": PluginState(enabled=True)},
        headless_creator=_qwdtt_state(enabled=True, count=3),
    )

    result = _service(runtime, actions).refresh_qwdtt_pool(state, forced=True)

    assert result
    assert actions.calls[0][0] == "update_call_pool_artifact"
    assert runtime.metadata["hashes"] == ["one", "two", "three"]
    assert runtime.metadata["room_count"] == 3


def test_post_commit_cleanup_failure_keeps_the_new_working_pool() -> None:
    runtime = Runtime()
    runtime.finalize_error = RuntimeError("old generation did not stop")
    state = AppState(
        protocols={"wdtt": PluginState(enabled=True)},
        headless_creator=_qwdtt_state(enabled=True, count=2),
    )

    result = _service(runtime).refresh_qwdtt_pool(state, forced=True)

    assert result
    assert result.value["cleanup_warning"] == "old generation did not stop"
    assert runtime.metadata["hashes"] == ["one", "two"]
    assert runtime.pool_rolled_back is False


def test_qwdtt_stop_clears_artifact_and_persisted_pool_flag() -> None:
    runtime = Runtime()
    actions = Actions()
    saves: list[AppState] = []
    state = AppState(headless_creator=_qwdtt_state(enabled=True))

    result = _service(runtime, actions, saves).stop_qwdtt_pool(state)

    assert result
    assert actions.link == ""
    assert state.headless_creator.consumers["qwdtt"]["pool_enabled"] is False
    assert saves


def test_qwdtt_stop_save_failure_restores_state_artifact_and_runtime() -> None:
    runtime = Runtime()
    actions = Actions()
    state = AppState(headless_creator=_qwdtt_state(enabled=True))

    def fail_save(_state):
        raise OSError("state write failed")

    result = _service(runtime, actions, save_state=fail_save).stop_qwdtt_pool(state)

    assert not result
    assert state.headless_creator.consumers["qwdtt"]["pool_enabled"] is True
    assert actions.link == "qwdtt://config?old=1"
    assert runtime.pool_restored is True


def test_qwdtt_interval_and_room_count_validation() -> None:
    state = AppState()
    service = _service(Runtime())

    assert service.set_qwdtt_refresh_interval(state, 3600)
    assert state.headless_creator.consumers["qwdtt"]["refresh_interval_seconds"] == 3600
    assert not service.set_qwdtt_refresh_interval(state, 25 * 3600)
    assert service.set_qwdtt_room_count(state, 8)
    assert state.headless_creator.consumers["qwdtt"]["room_count"] == 8
    assert not service.set_qwdtt_room_count(state, 0)
    assert not service.set_qwdtt_room_count(state, 17)
