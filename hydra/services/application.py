"""Stable application facade for HYDRA use-cases.

Transport adapters (CLI, TUI, Telegram and future HTTP handlers) should depend
on this facade. Production assembly belongs to :mod:`hydra.bootstrap`.
"""

from __future__ import annotations

import contextlib
import copy
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, cast

from hydra.core.runtime_state import PluginStatusReader
from hydra.core.state_models import AppState, User
from hydra.core.errors import ErrorCode, ServiceResult, failed_result
from hydra.services.protocols import ProtocolService
from hydra.services.configuration import restore_state_in_place
from hydra.services.vless_cdn_install import InstallOutcome, install_protocol
from hydra.services.vless_cdn_site import install_site_timer, refresh_site, remove_site_timer
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
from hydra.services.certificate_audit import (
    CertificateInspection,
    UnavailableCertificateInspection,
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
from hydra.services.configuration_names import ConfigurationNameService
from hydra.services.uninstall import (
    UnavailableUninstallOperations,
    UninstallOperations,
)
from hydra.services.users import UserService
from hydra.services.calls import CallOperations, UnavailableCallOperations
from hydra.services.maintenance import (
    MaintenanceOperations,
    UnavailableMaintenanceOperations,
)
from hydra.services.kernel import (
    KernelOperations,
    UnavailableKernelOperations,
)


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
    admin: AdminOperations = field(
        default_factory=lambda: cast(AdminOperations, UnavailableAdminOperations()),
    )
    backups: BackupOperations = field(
        default_factory=UnavailableBackupOperations,
    )
    logs: LogOperations = field(
        default_factory=lambda: cast(LogOperations, UnavailableLogOperations()),
    )
    diagnostics: DiagnosticOperations = field(
        default_factory=lambda: cast(DiagnosticOperations, UnavailableDiagnosticOperations()),
    )
    monitoring: SystemMonitoring = field(
        default_factory=lambda: cast(SystemMonitoring, UnavailableSystemMonitoring()),
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
    configuration_names: ConfigurationNameService = field(
        default_factory=ConfigurationNameService,
    )
    planner: ConfigurationPlanning = field(
        default_factory=UnavailableConfigurationPlanning,
    )
    uninstaller: UninstallOperations = field(
        default_factory=UnavailableUninstallOperations,
    )
    certificates: CertificateInspection = field(
        default_factory=UnavailableCertificateInspection,
    )
    calls: CallOperations = field(
        default_factory=lambda: cast(CallOperations, UnavailableCallOperations()),
    )
    maintenance: MaintenanceOperations = field(
        default_factory=UnavailableMaintenanceOperations,
    )
    kernel: KernelOperations = field(default_factory=UnavailableKernelOperations)

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

    def enable_vless_cdn(self, state: AppState) -> bool:
        """Enable CDN runtime and its page timer as one application operation."""
        snapshot = copy.deepcopy(state)
        if not self.protocols.enable(state, "vless_cdn"):
            return False
        try:
            if not install_site_timer():
                raise RuntimeError("site timer installation failed")
            refresh_site(state)
        except Exception:
            remove_site_timer()
            restore_state_in_place(state, snapshot)
            self.admin.save_state(state)
            self.apply(state)
            return False
        return True

    def set_vless_cdn_camera(self, state: AppState, url: str) -> bool:
        """Сменить HLS-источник и тут же пересобрать страницу прикрытия.

        `set_cam_source_url` (через plugin_command) уже пересобирает маршруты Caddy
        (central_apply). Но имя плейлиста в разметке плеера зависит от источника,
        поэтому страницу надо перегенерить сразу, а не ждать 10-минутный таймер.
        Пересборка страницы best-effort: её всё равно повторит таймер, если сейчас не выйдет.
        """
        if not self.plugin_command(state, "vless_cdn", "set_cam_source_url", url=url):
            return False
        with contextlib.suppress(Exception):
            refresh_site(state)
        return True

    def disable_vless_cdn(self, state: AppState) -> bool:
        """Stop CDN page refresh before disabling its runtime."""
        snapshot = copy.deepcopy(state)
        if not remove_site_timer():
            return False
        try:
            if self.protocols.disable(state, "vless_cdn"):
                return True
        except Exception:
            restore_state_in_place(state, snapshot)
            self.admin.save_state(state)
            self.apply(state)
            install_site_timer()
            return False
        restore_state_in_place(state, snapshot)
        self.admin.save_state(state)
        self.apply(state)
        install_site_timer()
        return False

    def provision_vless_cdn(
        self,
        state: AppState,
        *,
        cdn_domain: str,
        origin_host: str,
    ) -> InstallOutcome:
        """Provision CDN state, runtime config and site artifacts as one use-case."""
        snapshot = copy.deepcopy(state)
        outcome = install_protocol(
            state,
            cdn_domain=cdn_domain,
            origin_host=origin_host,
        )
        if not outcome.ok:
            return outcome

        timer_attempted = False
        try:
            self.admin.save_state(state)
            if not self.apply(state):
                raise RuntimeError(self.apply_error() or "configuration apply failed")
            timer_attempted = True
            if not install_site_timer():
                raise RuntimeError("site timer installation failed")
            refresh_site(state)
            self.admin.save_state(state)
        except Exception as exc:
            if timer_attempted:
                remove_site_timer()
            restore_state_in_place(state, snapshot)
            try:
                self.admin.save_state(state)
                self.apply(state)
            except Exception:
                pass
            detail = str(exc)
            if not detail:
                detail = exc.__class__.__name__
            return replace(outcome, ok=False, detail=detail)
        return outcome

    def uninstall_vless_cdn(self, state: AppState) -> bool:
        """Remove CDN protocol and its timer without leaving a half-removed site."""
        snapshot = copy.deepcopy(state)
        if not self.protocols.uninstall(state, "vless_cdn"):
            return False
        if remove_site_timer():
            return True

        restore_state_in_place(state, snapshot)
        try:
            self.admin.save_state(state)
            self.apply(state)
            install_site_timer()
        except Exception:
            pass
        return False

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
        tls_mux_ok = bool(tls_mux.get("ok", tls_mux.get("valid", True))) if isinstance(tls_mux, dict) else True
        return {
            "ok": bool(configuration.get("valid") and host.get("ok") and changes.get("valid") and tls_mux_ok),
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
        self,
        state: AppState,
        email: str,
        limit: int,
        *,
        reset: bool = False,
    ) -> User:
        return self.users.set_device_limit(state, email, limit, reset=reset)

    def rotate_user_hydrabox_key(
        self,
        state: AppState,
        email: str,
    ) -> User:
        return self.users.rotate_hydrabox_key(state, email)

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
