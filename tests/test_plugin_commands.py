from types import SimpleNamespace

import pytest

from hydra.core.state import AppState, PluginState
from hydra.services.plugin_commands import PluginCommandService


class _Plugin:
    meta = SimpleNamespace(
        name="naive",
        contract_version=1,
        capabilities=SimpleNamespace(
            commands=("set_transport",),
            central_apply=True,
        ),
    )

    def set_transport(self, *, state, network):
        state.protocols["naive"].config["network"] = network
        return network != "rejected"

    def explode(self, *, state):
        state.protocols["naive"].config["network"] = "broken"
        raise RuntimeError("command failed")


def _state(*, enabled: bool) -> AppState:
    return AppState(
        protocols={
            "naive": PluginState(
                installed=True,
                enabled=enabled,
                config={"network": "tcp"},
            ),
        },
    )


def _service(
    plugin,
    *,
    apply=lambda state: True,
    saves=None,
    prepare=None,
    last_apply_error=lambda: "",
    set_apply_error=lambda message: None,
):
    persisted = saves if saves is not None else []
    return PluginCommandService(
        get_plugin=lambda name: plugin if name == "naive" else None,
        apply_config=apply,
        save_state=lambda state: persisted.append(
            state.protocols["naive"].config["network"],
        ),
        prepare_apply=prepare or (lambda state, name: None),
        last_apply_error=last_apply_error,
        set_apply_error=set_apply_error,
    )


def test_disabled_plugin_command_persists_desired_state_without_runtime_apply():
    state = _state(enabled=False)
    applied = []
    saved = []
    service = _service(
        _Plugin(),
        apply=lambda current: applied.append(current) or True,
        saves=saved,
    )

    assert service.execute(
        state,
        "naive",
        "set_transport",
        network="quic",
    )
    assert state.protocols["naive"].config["network"] == "quic"
    assert saved == ["quic"]
    assert applied == []


def test_enabled_plugin_command_runs_preflight_then_atomic_apply():
    state = _state(enabled=True)
    events = []
    service = _service(
        _Plugin(),
        apply=lambda current: events.append("apply") or True,
        prepare=lambda current, name: events.append(f"prepare:{name}"),
    )

    assert service.execute(
        state,
        "naive",
        "set_transport",
        network="both",
    )
    assert events == ["prepare:naive", "apply"]


def test_persist_only_command_saves_enabled_state_without_runtime_apply():
    plugin = _Plugin()
    plugin.meta = SimpleNamespace(
        name="naive",
        contract_version=1,
        capabilities=SimpleNamespace(
            commands=("set_transport",),
            central_apply=True,
            persist_only_commands=("set_transport",),
        ),
    )
    state = _state(enabled=True)
    events = []
    saved = []
    service = _service(
        plugin,
        apply=lambda current: events.append("apply") or True,
        saves=saved,
        prepare=lambda current, name: events.append(f"prepare:{name}"),
    )

    assert service.execute(
        state,
        "naive",
        "set_transport",
        network="quic",
    )
    assert state.protocols["naive"].config["network"] == "quic"
    assert saved == ["quic"]
    assert events == []


def test_failed_apply_restores_and_persists_previous_desired_state():
    state = _state(enabled=True)
    saved = []
    service = _service(_Plugin(), apply=lambda current: False, saves=saved)

    assert not service.execute(
        state,
        "naive",
        "set_transport",
        network="quic",
    )
    assert state.protocols["naive"].config == {"network": "tcp"}
    assert saved == ["tcp"]


APPLY_REASON = "Не удалось применить конфигурацию плагина: route is not active"


class _FailingRollbackPlugin(_Plugin):
    """A plugin whose cleanup reports failure after a failed apply."""

    def rollback(self, state, snapshot):
        return False


def test_failed_apply_keeps_the_apply_reason_after_a_successful_rollback():
    state = _state(enabled=True)
    error = {"value": APPLY_REASON}
    service = _service(
        _Plugin(),
        apply=lambda current: False,
        last_apply_error=lambda: error["value"],
        set_apply_error=lambda message: error.update(value=message),
    )

    assert not service.execute(state, "naive", "set_transport", network="quic")
    assert error["value"] == APPLY_REASON
    assert "rollback" not in error["value"]
    assert state.protocols["naive"].config == {"network": "tcp"}


def test_failed_rollback_reports_it_next_to_the_apply_reason():
    state = _state(enabled=True)
    error = {"value": APPLY_REASON}
    service = _service(
        _FailingRollbackPlugin(),
        apply=lambda current: False,
        last_apply_error=lambda: error["value"],
        set_apply_error=lambda message: error.update(value=message),
    )

    with pytest.raises(RuntimeError) as raised:
        service.execute(state, "naive", "set_transport", network="quic")

    assert str(raised.value).splitlines() == [
        APPLY_REASON,
        "plugin command rollback failed: naive.set_transport",
    ]
    assert error["value"] == APPLY_REASON, "the restored reason must survive the raise"
    assert state.protocols["naive"].config == {"network": "tcp"}


def test_failed_rollback_without_an_apply_reason_keeps_the_existing_text():
    state = _state(enabled=True)
    service = _service(_FailingRollbackPlugin(), apply=lambda current: False)

    with pytest.raises(
        RuntimeError,
        match="plugin command rollback failed: naive.set_transport",
    ):
        service.execute(state, "naive", "set_transport", network="quic")
    assert state.protocols["naive"].config == {"network": "tcp"}


def test_successful_command_never_touches_the_apply_error():
    state = _state(enabled=True)
    written = []
    service = _service(
        _Plugin(),
        last_apply_error=lambda: APPLY_REASON,
        set_apply_error=written.append,
    )

    assert service.execute(state, "naive", "set_transport", network="quic")
    assert written == []


def test_unchanged_command_never_touches_the_apply_error():
    state = _state(enabled=False)
    written = []
    service = _service(
        _Plugin(),
        last_apply_error=lambda: APPLY_REASON,
        set_apply_error=written.append,
    )

    assert not service.execute(state, "naive", "set_transport", network="rejected")
    assert written == []


def test_persist_only_command_never_touches_the_apply_error():
    plugin = _Plugin()
    plugin.meta = SimpleNamespace(
        name="naive",
        contract_version=1,
        capabilities=SimpleNamespace(
            commands=("set_transport",),
            central_apply=True,
            persist_only_commands=("set_transport",),
        ),
    )
    state = _state(enabled=True)
    written = []
    service = _service(
        plugin,
        last_apply_error=lambda: APPLY_REASON,
        set_apply_error=written.append,
    )

    assert service.execute(state, "naive", "set_transport", network="quic")
    assert state.protocols["naive"].config["network"] == "quic"
    assert written == []


def test_rejected_and_raising_commands_leave_no_partial_state():
    state = _state(enabled=False)
    plugin = _Plugin()
    service = _service(plugin)

    assert not service.execute(
        state,
        "naive",
        "set_transport",
        network="rejected",
    )
    assert state.protocols["naive"].config == {"network": "tcp"}

    service = PluginCommandService(
        get_plugin=lambda name: plugin,
        apply_config=lambda current: True,
        save_state=lambda current: None,
        commands={"naive": frozenset({"explode"})},
    )
    with pytest.raises(RuntimeError, match="command failed"):
        service.execute(state, "naive", "explode")
    assert state.protocols["naive"].config == {"network": "tcp"}


class _RaisingCommand(_Plugin):
    """The base plugin with ``explode`` allowed through the command boundary."""

    meta = SimpleNamespace(
        name="naive",
        contract_version=1,
        capabilities=SimpleNamespace(
            commands=("explode",),
            central_apply=True,
        ),
    )


class _RaisingCommandWithFailedRollback(_RaisingCommand):
    """A command that raises while its cleanup also reports failure."""

    def rollback(self, state, snapshot):
        return False


def test_a_raising_command_keeps_its_own_exception_when_the_rollback_succeeds():
    state = _state(enabled=True)
    service = _service(_RaisingCommand())

    with pytest.raises(RuntimeError, match="command failed") as raised:
        service.execute(state, "naive", "explode")

    assert raised.value.__cause__ is None
    assert state.protocols["naive"].config == {"network": "tcp"}


def test_a_raising_command_keeps_its_cause_when_the_rollback_also_fails():
    state = _state(enabled=True)
    service = _service(_RaisingCommandWithFailedRollback())

    with pytest.raises(RuntimeError) as raised:
        service.execute(state, "naive", "explode")

    assert str(raised.value).splitlines() == [
        "command failed",
        "plugin command rollback failed: naive.explode",
    ]
    assert str(raised.value.__cause__) == "command failed"
    assert state.protocols["naive"].config == {"network": "tcp"}


def test_command_allowlist_rejects_arbitrary_plugin_methods():
    with pytest.raises(ValueError, match="unsupported plugin command"):
        _service(_Plugin()).execute(
            _state(enabled=False),
            "naive",
            "uninstall",
        )


class _ExternalPlugin:
    meta = SimpleNamespace(
        name="honeypot",
        contract_version=1,
        capabilities=SimpleNamespace(central_apply=False),
    )

    def __init__(self, *, apply_ok: bool):
        self.value = 9999
        self.apply_ok = apply_ok
        self.events = []

    def snapshot(self, state):
        self.events.append("snapshot")
        return self.value

    def set_port(self, *, state, port):
        self.events.append(f"command:{port}")
        self.value = port
        return True

    def apply(self, state):
        self.events.append("plugin-apply")
        return self.apply_ok

    def rollback(self, state, snapshot):
        self.events.append("rollback")
        self.value = snapshot
        return True


def test_noncentral_command_applies_once_through_plugin_contract():
    state = AppState(
        protocols={
            "honeypot": PluginState(installed=True, enabled=True),
        },
    )
    plugin = _ExternalPlugin(apply_ok=True)
    application_applies = []
    saves = []
    service = PluginCommandService(
        get_plugin=lambda name: plugin,
        apply_config=lambda current: application_applies.append(current) or True,
        save_state=lambda current: saves.append(current),
        commands={"honeypot": frozenset({"set_port"})},
    )

    assert service.execute(state, "honeypot", "set_port", port=8443)
    assert plugin.value == 8443
    assert plugin.events == ["snapshot", "command:8443", "plugin-apply"]
    assert application_applies == []
    assert saves == [state]


def test_failed_noncentral_apply_rolls_back_plugin_owned_state():
    state = AppState(
        protocols={
            "honeypot": PluginState(installed=True, enabled=True),
        },
    )
    plugin = _ExternalPlugin(apply_ok=False)
    service = PluginCommandService(
        get_plugin=lambda name: plugin,
        apply_config=lambda current: True,
        save_state=lambda current: None,
        commands={"honeypot": frozenset({"set_port"})},
    )

    assert not service.execute(state, "honeypot", "set_port", port=8443)
    assert plugin.value == 9999
    assert plugin.events == [
        "snapshot",
        "command:8443",
        "plugin-apply",
        "rollback",
    ]
