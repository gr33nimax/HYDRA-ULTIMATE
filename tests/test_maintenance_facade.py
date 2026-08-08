from __future__ import annotations

from hydra.core.errors import ServiceResult
from hydra.core.state_models import AppState, PluginState
from hydra.services.maintenance import MaintenanceService


class Protocols:
    def maintenance_jobs(self):
        return []


class Plugins:
    def execute(self, *args, **kwargs):
        raise AssertionError("plugin dispatch must not own Calls maintenance")


class Calls:
    def __init__(self) -> None:
        self.refreshes = 0

    def qwdtt_pool_due(self, state, *, forced=False):
        return True

    def refresh_qwdtt_pool(self, state, *, forced=False):
        assert forced is True
        self.refreshes += 1
        return ServiceResult(True, value={"changed": True})


def test_owner_neutral_facade_declares_and_runs_calls_job() -> None:
    calls = Calls()
    service = MaintenanceService(Protocols(), Plugins(), Plugins(), calls)
    state = AppState(
        protocols={
            "calls": PluginState(config={"qwdtt_pool_enabled": True}),
        },
    )

    jobs = service.jobs()
    assert jobs[-1].owner == "calls"
    assert jobs[-1].enabled_flag == "sync_calls_qwdtt_pool_enabled"
    outcomes = service.run(state, forced=False)

    assert outcomes[-1].status == "success"
    assert calls.refreshes == 1


def test_calls_maintenance_respects_owner_flag_and_consumer_state() -> None:
    calls = Calls()
    service = MaintenanceService(Protocols(), Plugins(), Plugins(), calls)
    state = AppState(
        protocols={
            "calls": PluginState(config={"qwdtt_pool_enabled": True}),
        },
        install={"sync_calls_qwdtt_pool_enabled": False},
    )

    assert service.run(state, forced=False)[-1].status == "disabled"
    state.protocols["calls"].config["qwdtt_pool_enabled"] = False
    assert service.run(state, forced=True)[-1].status == "consumer_disabled"
    assert calls.refreshes == 0
