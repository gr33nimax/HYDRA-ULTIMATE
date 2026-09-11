"""Owner-neutral maintenance projection and execution facade."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from hydra.core.state_models import AppState
from hydra.services.calls_contracts import CALLS_POOL_AUTO_FLAG, CallOperations


@dataclass(frozen=True)
class MaintenanceJob:
    """Adapter-neutral description of one scheduled maintenance task."""

    plugin_name: str
    action: str
    title: str
    description: str
    due_query: str
    enabled_flag: str
    apply_on_success: bool
    owner: str = "plugin"
    key: str = ""
    enabled_by_default: bool = True


@dataclass(frozen=True)
class MaintenanceOutcome:
    """Normalized result of one maintenance job."""

    job: MaintenanceJob
    status: str
    message: str = ""
    apply_required: bool = False


class MaintenanceOperations(Protocol):
    def jobs(self) -> list[MaintenanceJob]: ...
    def run(self, state: AppState, forced: bool) -> list[MaintenanceOutcome]: ...


class ProtocolMaintenanceAccess(Protocol):
    def maintenance_jobs(self) -> list[MaintenanceJob]: ...


class ActionAccess(Protocol):
    def execute(self, plugin_name: str, action: str, **parameters: object) -> Any: ...


class QueryAccess(Protocol):
    def execute(self, plugin_name: str, query: str, **parameters: object) -> Any: ...


@dataclass(frozen=True)
class UnavailableMaintenanceOperations:
    def jobs(self) -> list[MaintenanceJob]:
        return []

    def run(self, state: AppState, forced: bool) -> list[MaintenanceOutcome]:
        return []


def _action_result(value: Any) -> tuple[bool, str]:
    if isinstance(value, bool):
        return value, ""
    if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], bool):
        return value[0], str(value[1] or "")
    if isinstance(value, dict) and isinstance(value.get("ok"), bool):
        return value["ok"], str(value.get("message") or "")
    raise TypeError("plugin maintenance action returned an invalid result")


@dataclass(frozen=True)
class MaintenanceService:
    """Combine plugin tasks with owner-neutral application maintenance."""

    protocols: ProtocolMaintenanceAccess
    plugin_actions: ActionAccess
    plugin_queries: QueryAccess
    calls: CallOperations | None = None

    def jobs(self) -> list[MaintenanceJob]:
        jobs = self.protocols.maintenance_jobs()
        if self.calls is not None:
            jobs.append(MaintenanceJob(
                plugin_name="calls",
                action="rotate_native_vk",
                title="Hydra VK Tunnel: автопересоздание пула",
                description="Создавать новый blue/green VK-пул по интервалу",
                due_query="pool_rotation_due",
                enabled_flag=CALLS_POOL_AUTO_FLAG,
                apply_on_success=False,
                owner="application",
                key="calls.pool",
                enabled_by_default=False,
            ))
        return jobs

    def run(self, state: AppState, forced: bool) -> list[MaintenanceOutcome]:
        outcomes: list[MaintenanceOutcome] = []
        for job in self.jobs():
            outcomes.append(
                self._run_calls_job(state, job, forced)
                if job.owner == "application" and job.key == "calls.pool"
                else self._run_plugin_job(state, job, forced)
            )
        return outcomes

    def _run_calls_job(
        self,
        state: AppState,
        job: MaintenanceJob,
        forced: bool,
    ) -> MaintenanceOutcome:
        desired = state.protocols.get("calls")
        if not (desired and desired.enabled):
            return MaintenanceOutcome(job, "plugin_disabled")
        if not forced and not state.install.get(
            job.enabled_flag,
            job.enabled_by_default,
        ):
            return MaintenanceOutcome(job, "disabled")
        try:
            if not self.calls or not self.calls.pool_rotation_due(
                state,
                forced=forced,
            ):
                return MaintenanceOutcome(job, "fresh")
            result = self.calls.rotate_native_vk(state)
            return MaintenanceOutcome(
                job,
                "success" if result else "failed",
                "" if result or not result.error else result.error.message,
            )
        except Exception as exc:
            return MaintenanceOutcome(
                job,
                "failed",
                str(exc) or exc.__class__.__name__,
            )

    def _run_plugin_job(
        self,
        state: AppState,
        job: MaintenanceJob,
        forced: bool,
    ) -> MaintenanceOutcome:
        desired = state.protocols.get(job.plugin_name)
        if not (desired and desired.enabled):
            return MaintenanceOutcome(job, "plugin_disabled")
        if not forced and not state.install.get(
            job.enabled_flag,
            job.enabled_by_default,
        ):
            return MaintenanceOutcome(job, "disabled")
        try:
            if job.due_query and not self.plugin_queries.execute(
                job.plugin_name,
                job.due_query,
                state=state,
                forced=forced,
            ):
                return MaintenanceOutcome(job, "fresh")
            ok, message = _action_result(
                self.plugin_actions.execute(
                    job.plugin_name,
                    job.action,
                    state=state,
                ),
            )
            return MaintenanceOutcome(
                job,
                "success" if ok else "failed",
                message,
                apply_required=ok and job.apply_on_success,
            )
        except Exception as exc:
            return MaintenanceOutcome(job, "failed", str(exc) or exc.__class__.__name__)


__all__ = [
    "MaintenanceJob",
    "MaintenanceOperations",
    "MaintenanceOutcome",
    "MaintenanceService",
    "UnavailableMaintenanceOperations",
]
