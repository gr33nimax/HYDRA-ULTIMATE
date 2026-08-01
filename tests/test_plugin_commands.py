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


def _service(plugin, *, apply=lambda state: True, saves=None, prepare=None):
    persisted = saves if saves is not None else []
    return PluginCommandService(
        get_plugin=lambda name: plugin if name == "naive" else None,
        apply_config=apply,
        save_state=lambda state: persisted.append(
            state.protocols["naive"].config["network"],
        ),
        prepare_apply=prepare or (lambda state, name: None),
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
