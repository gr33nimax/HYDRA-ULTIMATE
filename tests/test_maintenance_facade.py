from __future__ import annotations

from unittest.mock import Mock

from hydra.core.errors import ServiceResult
from hydra.core.state_models import AppState
from hydra.core.state_models import PluginState
from hydra.services.maintenance import MaintenanceJob, MaintenanceService


class Protocols:
    def maintenance_jobs(self):
        return [
            MaintenanceJob(
                plugin_name="example",
                action="refresh",
                title="Example",
                description="",
                due_query="",
                enabled_flag="sync_example_enabled",
                apply_on_success=False,
            ),
        ]


class Plugins:
    def execute(self, *args, **kwargs):
        return True, ""


class Queries:
    def execute(self, *args, **kwargs):
        raise AssertionError("maintenance job has no due query")


def test_maintenance_does_not_schedule_legacy_qwdtt_creator() -> None:
    service = MaintenanceService(Protocols(), Plugins(), Queries())

    jobs = service.jobs()
    outcomes = service.run(AppState(), forced=False)

    assert [job.plugin_name for job in jobs] == ["example"]
    assert [outcome.status for outcome in outcomes] == ["plugin_disabled"]


def test_calls_pool_rotation_is_opt_in_and_uses_calls_service() -> None:
    calls = Mock()
    calls.pool_rotation_due.return_value = True
    calls.rotate_native_vk.return_value = ServiceResult(True)
    service = MaintenanceService(Protocols(), Plugins(), Queries(), calls)
    state = AppState(
        protocols={
            "calls": PluginState(installed=True, enabled=True),
        },
    )

    assert service.run(state, forced=False)[-1].status == "disabled"
    state.install["sync_calls_vk_pool_enabled"] = True
    assert service.run(state, forced=False)[-1].status == "success"
    calls.pool_rotation_due.assert_called_once_with(state, forced=False)
    calls.rotate_native_vk.assert_called_once_with(state)
