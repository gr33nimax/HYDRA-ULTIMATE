from __future__ import annotations

from hydra.core.state_models import AppState
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
