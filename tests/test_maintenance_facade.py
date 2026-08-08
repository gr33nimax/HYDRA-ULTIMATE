from __future__ import annotations

from hydra.core.errors import ServiceResult
from hydra.core.state_creator_models import HeadlessCreatorConfig
from hydra.core.state_models import AppState
from hydra.services.maintenance import MaintenanceService


class Protocols:
    def maintenance_jobs(self):
        return []


class Plugins:
    def execute(self, *args, **kwargs):
        raise AssertionError("plugin dispatch must not own Calls maintenance")


class Creator:
    def __init__(self) -> None:
        self.refreshes = 0

    def qwdtt_pool_due(self, state, *, forced=False):
        return True

    def refresh_qwdtt_pool(self, state, *, forced=False):
        assert forced is True
        self.refreshes += 1
        return ServiceResult(True, value={"changed": True})


def test_owner_neutral_facade_declares_and_runs_creator_job() -> None:
    creator = Creator()
    service = MaintenanceService(Protocols(), Plugins(), Plugins(), creator)
    state = AppState(
        headless_creator=HeadlessCreatorConfig(
            consumers={"qwdtt": {"pool_enabled": True}},
        ),
    )

    jobs = service.jobs()
    assert jobs[-1].owner == "creator_consumer"
    assert jobs[-1].enabled_flag == "sync_headless_creator_vk_qwdtt_enabled"
    outcomes = service.run(state, forced=False)

    assert outcomes[-1].status == "success"
    assert creator.refreshes == 1


def test_creator_maintenance_respects_owner_flag_and_consumer_state() -> None:
    creator = Creator()
    service = MaintenanceService(Protocols(), Plugins(), Plugins(), creator)
    state = AppState(
        headless_creator=HeadlessCreatorConfig(
            consumers={"qwdtt": {"pool_enabled": True}},
        ),
        install={"sync_headless_creator_vk_qwdtt_enabled": False},
    )

    assert service.run(state, forced=False)[-1].status == "disabled"
    state.headless_creator.consumers["qwdtt"]["pool_enabled"] = False
    assert service.run(state, forced=True)[-1].status == "consumer_disabled"
    assert creator.refreshes == 0
