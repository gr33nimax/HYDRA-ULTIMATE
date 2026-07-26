"""Stable application facade for HYDRA use-cases.

Transport adapters (CLI, TUI, Telegram and future HTTP handlers) should depend
on this facade. Production assembly belongs to :mod:`hydra.bootstrap`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from hydra.core.runtime_state import PluginStatusReader
from hydra.core.state_models import AppState, User
from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.services.protocols import ProtocolService
from hydra.services.admin import AdminOperations, UnavailableAdminOperations
from hydra.services.backups import (
    BackupOperations,
    UnavailableBackupOperations,
)
from hydra.services.plugin_commands import (
    PluginCommands,
    UnavailablePluginCommands,
)
from hydra.services.plugin_actions import (
    PluginActions,
    UnavailablePluginActions,
)
from hydra.services.plugin_queries import (
    PluginQueries,
    UnavailablePluginQueries,
)
from hydra.services.configuration_plan import (
    ConfigurationPlanning,
    UnavailableConfigurationPlanning,
)
from hydra.services.logs import LogOperations, UnavailableLogOperations
from hydra.services.diagnostics import (
    DiagnosticOperations,
    UnavailableDiagnosticOperations,
)
from hydra.services.system_monitoring import (
    SystemMonitoring,
    UnavailableSystemMonitoring,
)
from hydra.services.system import (
    SystemOperations,
    UnavailableSystemOperations,
)
from hydra.services.traffic import (
    TrafficOperations,
    UnavailableTrafficOperations,
)
from hydra.services.uninstall import (
    UnavailableUninstallOperations,
    UninstallOperations,
)
from hydra.services.users import UserService


@dataclass(frozen=True)
class ApplicationService:
    """Stable application boundary shared by all management transports."""

    users: UserService
    protocols: ProtocolService
    apply_config: Callable[[AppState], bool]
    last_apply_error: Callable[[], str]
    plugin_statuses: PluginStatusReader
    reconcile_runtime: Callable[[AppState], None] = lambda state: None
    apply_journal: Callable[[], Path] = lambda: Path("/var/log/hydra/apply.jsonl")
    admin: AdminOperations = field(default_factory=UnavailableAdminOperations)
    backups: BackupOperations = field(
        default_factory=UnavailableBackupOperations,
    )
    logs: LogOperations = field(default_factory=UnavailableLogOperations)
    diagnostics: DiagnosticOperations = field(
        default_factory=UnavailableDiagnosticOperations,
    )
    monitoring: SystemMonitoring = field(
        default_factory=UnavailableSystemMonitoring,
    )
    system: SystemOperations = field(
        default_factory=UnavailableSystemOperations,
    )
    plugin_commands: PluginCommands = field(
        default_factory=UnavailablePluginCommands,
    )
    plugin_queries: PluginQueries = field(
        default_factory=UnavailablePluginQueries,
    )
    plugin_actions: PluginActions = field(
        default_factory=UnavailablePluginActions,
    )
    traffic: TrafficOperations = field(
        default_factory=UnavailableTrafficOperations,
    )
    planner: ConfigurationPlanning = field(
        default_factory=UnavailableConfigurationPlanning,
    )
    uninstaller: UninstallOperations = field(
        default_factory=UnavailableUninstallOperations,
    )

    def status(self, state: AppState) -> dict[str, Any]:
        from hydra.core.status import build_status

        return build_status(state, self.plugin_statuses)

    def apply(self, state: AppState) -> bool:
        return bool(self.apply_config(state))

    def apply_result(self, state: AppState) -> ServiceResult:
        try:
            if self.apply_config(state):
                return ServiceResult(True, value=True)
            message = self.apply_error() or "configuration apply failed"
            return ServiceResult(
                False,
                error=failed_result(RuntimeError(message), fallback=ErrorCode.OPERATION_FAILED).error,
            )
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.CONFIGURATION)

    def apply_error(self) -> str:
        return str(self.last_apply_error() or "")

    def reconcile_background_services(self, state: AppState) -> None:
        self.reconcile_runtime(state)

    def plugin_command(
        self,
        state: AppState,
        plugin_name: str,
        command: str,
        **parameters: object,
    ) -> bool:
        return self.plugin_commands.execute(
            state,
            plugin_name,
            command,
            **parameters,
        )

    def plugin_query(
        self,
        plugin_name: str,
        query: str,
        **parameters: object,
    ) -> Any:
        return self.plugin_queries.execute(
            plugin_name,
            query,
            **parameters,
        )

    def plugin_action(
        self,
        plugin_name: str,
        action: str,
        **parameters: object,
    ) -> Any:
        return self.plugin_actions.execute(
            plugin_name,
            action,
            **parameters,
        )

    def journal_path(self) -> Path:
        return Path(self.apply_journal())

    def plan(self, state: AppState) -> dict[str, Any]:
        return self.planner.build(state)

    def check(self, state: AppState) -> dict[str, Any]:
        """Run the complete read-only preflight exposed to operators."""
        configuration = self.system.validate(state)
        host = self.system.doctor(state)
        changes = self.planner.build(state)
        tls_mux = changes.get("tls_mux", {})
        tls_mux_ok = (
            bool(tls_mux.get("ok", tls_mux.get("valid", True)))
            if isinstance(tls_mux, dict)
            else True
        )
        return {
            "ok": bool(
                configuration.get("valid")
                and host.get("ok")
                and changes.get("valid")
                and tls_mux_ok
            ),
            "configuration": configuration,
            "host": host,
            "changes": changes,
        }

    def uninstall_plan(
        self,
        state: AppState,
        *,
        keep_data: bool = False,
    ) -> dict:
        return self.uninstaller.plan(state, keep_data=keep_data)

    def uninstall(
        self,
        state: AppState,
        *,
        confirmed: bool,
        dry_run: bool = False,
        keep_data: bool = False,
    ) -> dict:
        return self.uninstaller.uninstall(
            state,
            confirmed=confirmed,
            dry_run=dry_run,
            keep_data=keep_data,
        )

    def add_user(self, state: AppState, user: User) -> User:
        return self.users.add(state, user)

    def remove_user(self, state: AppState, email: str) -> None:
        self.users.remove(state, email)

    def block_user(self, state: AppState, email: str) -> None:
        self.users.block(state, email)

    def unblock_user(self, state: AppState, email: str) -> None:
        self.users.unblock(state, email)

    def rename_user(self, state: AppState, email: str, new_email: str) -> User:
        return self.users.rename(state, email, new_email)

    def set_user_device_limit(
        self, state: AppState, email: str, limit: int, *, reset: bool = False,
    ) -> User:
        return self.users.set_device_limit(state, email, limit, reset=reset)

    def user_result(self, operation: str, state: AppState, email: str, user: User | None = None) -> ServiceResult:
        """Run a user operation and normalize expected failures for adapters."""
        try:
            if operation == "add":
                if user is None:
                    raise ValueError("user is required")
                return ServiceResult(True, value=self.add_user(state, user))
            getattr(self, f"{operation}_user")(state, email)
            return ServiceResult(True, value=email)
        except Exception as exc:
            return failed_result(exc, fallback=ErrorCode.PLUGIN)
