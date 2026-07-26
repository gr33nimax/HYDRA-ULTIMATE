"""Narrow application capabilities required by the background sync use-case."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from hydra.core.state_models import AppState
from hydra.services.certificate_audit import CertificateStatus
from hydra.services.protocols import MaintenanceJob


class SyncProtocolAccess(Protocol):
    def notify_user_block(self, state: AppState, user) -> list[str]: ...
    def maintenance_jobs(self) -> list[MaintenanceJob]: ...


class SyncPluginActions(Protocol):
    def execute(
        self,
        plugin_name: str,
        action: str,
        **parameters: object,
    ) -> Any: ...


class SyncPluginQueries(Protocol):
    def execute(
        self,
        plugin_name: str,
        query: str,
        **parameters: object,
    ) -> Any: ...


@dataclass(frozen=True)
class MaintenanceOutcome:
    """Normalized result of one declared plugin maintenance job."""

    job: MaintenanceJob
    status: str
    message: str = ""
    apply_required: bool = False


@dataclass(frozen=True)
class SyncOperations:
    """Explicit dependencies for one synchronization run."""

    protocols: SyncProtocolAccess
    apply_config: Callable[[AppState], bool]
    check_traffic_limits: Callable[[AppState], list[str]]
    run_maintenance: Callable[
        [AppState, bool],
        list[MaintenanceOutcome],
    ]
    # Facades assembled by hand audit nothing until they wire an inspector.
    inspect_certificates: Callable[
        [AppState],
        list[CertificateStatus],
    ] = lambda state: []
    renew_subscription_certificate: Callable[
        [str],
        tuple[bool, str],
    ] = lambda domain: (False, "обновление сертификата подписок не подключено")

    def apply(self, state: AppState) -> bool:
        return bool(self.apply_config(state))


class SubscriptionCertificateAdmin(Protocol):
    """Admin capabilities needed to refresh the subscription certificate."""

    def obtain_subscription_certificate(self, domain: str) -> Any: ...

    def unit_active(self, unit: str) -> bool: ...

    def restart_unit(self, unit: str) -> bool: ...


def subscription_certificate_renewal(
    admin: SubscriptionCertificateAdmin,
) -> Callable[[str], tuple[bool, str]]:
    """Renew the subscription certificate and reload the server that serves it.

    The subscription endpoint is not a plugin, so the shared apply preflight
    never reissues its certificate; this is the only automated path for it.
    """

    def renew(domain: str) -> tuple[bool, str]:
        result = admin.obtain_subscription_certificate(domain)
        ok = bool(getattr(result, "ok", False))
        message = str(getattr(result, "message", "") or "")
        if ok and admin.unit_active("hydra-sub"):
            admin.restart_unit("hydra-sub")
        return ok, message

    return renew


def _action_result(value: Any) -> tuple[bool, str]:
    if isinstance(value, bool):
        return value, ""
    if (
        isinstance(value, tuple)
        and len(value) == 2
        and isinstance(value[0], bool)
    ):
        return value[0], str(value[1] or "")
    if isinstance(value, dict) and isinstance(value.get("ok"), bool):
        return value["ok"], str(value.get("message") or "")
    raise TypeError("plugin maintenance action returned an invalid result")


def default_sync_operations(
    *,
    protocols: SyncProtocolAccess,
    plugin_actions: SyncPluginActions,
    plugin_queries: SyncPluginQueries,
    apply_config: Callable[[AppState], bool],
    check_traffic_limits: Callable[[AppState], list[str]],
    inspect_certificates: Callable[
        [AppState],
        list[CertificateStatus],
    ],
    renew_subscription_certificate: Callable[[str], tuple[bool, str]],
) -> SyncOperations:
    """Compose declared plugin maintenance without protocol-name branches."""

    def run_maintenance(
        state: AppState,
        forced: bool,
    ) -> list[MaintenanceOutcome]:
        outcomes: list[MaintenanceOutcome] = []
        for job in protocols.maintenance_jobs():
            desired = state.protocols.get(job.plugin_name)
            if not (desired and desired.enabled):
                outcomes.append(MaintenanceOutcome(job, "plugin_disabled"))
                continue
            if not forced and not state.install.get(job.enabled_flag, True):
                outcomes.append(MaintenanceOutcome(job, "disabled"))
                continue
            try:
                if job.due_query and not plugin_queries.execute(
                    job.plugin_name,
                    job.due_query,
                    state=state,
                    forced=forced,
                ):
                    outcomes.append(MaintenanceOutcome(job, "fresh"))
                    continue
                ok, message = _action_result(
                    plugin_actions.execute(
                        job.plugin_name,
                        job.action,
                        state=state,
                    ),
                )
                outcomes.append(
                    MaintenanceOutcome(
                        job,
                        "success" if ok else "failed",
                        message,
                        apply_required=ok and job.apply_on_success,
                    ),
                )
            except Exception as exc:
                outcomes.append(
                    MaintenanceOutcome(
                        job,
                        "failed",
                        str(exc) or exc.__class__.__name__,
                    ),
                )
        return outcomes

    return SyncOperations(
        protocols=protocols,
        apply_config=apply_config,
        check_traffic_limits=check_traffic_limits,
        run_maintenance=run_maintenance,
        inspect_certificates=inspect_certificates,
        renew_subscription_certificate=renew_subscription_certificate,
    )


__all__ = [
    "MaintenanceOutcome",
    "SubscriptionCertificateAdmin",
    "SyncOperations",
    "SyncPluginActions",
    "SyncPluginQueries",
    "SyncProtocolAccess",
    "default_sync_operations",
    "subscription_certificate_renewal",
]
