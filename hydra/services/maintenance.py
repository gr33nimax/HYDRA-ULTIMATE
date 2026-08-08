"""Owner-neutral maintenance projection and execution facade."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from hydra.core.errors import ServiceResult
from hydra.core.state_models import AppState


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


class HeadlessCreatorMaintenanceAccess(Protocol):
    def qwdtt_pool_due(self, state: AppState, *, forced: bool = False) -> bool: ...
    def refresh_qwdtt_pool(
        self,
        state: AppState,
        *,
        forced: bool = False,
    ) -> ServiceResult: ...


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
    headless_creator: HeadlessCreatorMaintenanceAccess

    def jobs(self) -> list[MaintenanceJob]:
        return [
            *self.protocols.maintenance_jobs(),
            MaintenanceJob(
                plugin_name="",
                action="refresh_qwdtt_pool",
                title="Обновление VK-комнат qWDTT",
                description="Переоткрывает четыре VK-комнаты и публикует qwdtt:// ссылку",
                due_query="qwdtt_pool_due",
                enabled_flag="sync_headless_creator_vk_qwdtt_enabled",
                apply_on_success=False,
                owner="headless_creator",
                key="headless_creator.vk.qwdtt_pool",
            ),
        ]

    def run(self, state: AppState, forced: bool) -> list[MaintenanceOutcome]:
        outcomes: list[MaintenanceOutcome] = []
        for job in self.jobs():
            if job.owner == "headless_creator":
                outcomes.append(self._run_creator_job(state, job, forced))
            else:
                outcomes.append(self._run_plugin_job(state, job, forced))
        return outcomes

    def _run_creator_job(
        self,
        state: AppState,
        job: MaintenanceJob,
        forced: bool,
    ) -> MaintenanceOutcome:
        vk = state.headless_creator.providers.get("vk", {})
        if not vk.get("qwdtt_pool_enabled", False):
            return MaintenanceOutcome(job, "consumer_disabled")
        if not forced and not state.install.get(job.enabled_flag, True):
            return MaintenanceOutcome(job, "disabled")
        try:
            if not forced and not self.headless_creator.qwdtt_pool_due(state):
                return MaintenanceOutcome(job, "fresh")
            result = self.headless_creator.refresh_qwdtt_pool(state, forced=True)
            message = result.error.message if result.error else ""
            return MaintenanceOutcome(
                job,
                "success" if result else "failed",
                message,
            )
        except Exception as exc:
            return MaintenanceOutcome(job, "failed", str(exc) or exc.__class__.__name__)

    def _run_plugin_job(
        self,
        state: AppState,
        job: MaintenanceJob,
        forced: bool,
    ) -> MaintenanceOutcome:
        desired = state.protocols.get(job.plugin_name)
        if not (desired and desired.enabled):
            return MaintenanceOutcome(job, "plugin_disabled")
        if not forced and not state.install.get(job.enabled_flag, True):
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
