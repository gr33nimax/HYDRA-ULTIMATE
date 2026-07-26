"""Local-host implementation of the administration application port."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from hydra.core.host import HOST
from hydra.core.install_layout import project_root, python_executable
from hydra.core.state import load_state, save_state, update_state
from hydra.core.state_models import AppState
from hydra.core import systemd
from hydra.services.admin import (
    AdminCommandResult,
    SingboxDiagnostics,
    SystemOverview,
    UnitDiagnostics,
)
from hydra.services.sync_ports import SyncOperations
from hydra.utils.commands import CommandError


class AdminInfrastructure:
    """Own privileged host, persistence and service-manager interactions."""

    def __init__(
        self,
        *,
        sync_operations: SyncOperations | None = None,
        sync_runner: Callable[..., tuple[bool, str]] | None = None,
    ) -> None:
        self._sync_operations = sync_operations
        self._sync_runner = sync_runner

    def load_state(self) -> AppState:
        return load_state()

    def save_state(self, state: AppState) -> None:
        save_state(state)

    def set_install_flag(self, key: str, value: bool) -> AppState:
        state, _ = update_state(lambda latest: latest.install.__setitem__(key, value))
        return state

    def set_clash_api(self, enabled: bool) -> AppState:
        state, _ = update_state(
            lambda latest: setattr(latest.network, "clash_api_enabled", enabled)
        )
        return state

    def unit_active(self, unit: str) -> bool:
        return systemd.is_active(unit)

    def unit_known(self, unit: str) -> bool:
        try:
            result = HOST.run(
                ["systemctl", "show", "--property=LoadState", "--value", unit],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0 and result.stdout.strip() == "loaded"
        except (OSError, subprocess.SubprocessError, CommandError):
            return False

    def start_unit(self, unit: str) -> bool:
        return systemd.start(unit)

    def stop_unit(self, unit: str) -> bool:
        return systemd.stop(unit)

    def restart_unit(self, unit: str) -> bool:
        return systemd.restart(unit)

    def disable_unit(self, unit: str) -> bool:
        try:
            return HOST.run(
                ["systemctl", "disable", unit],
                capture_output=True,
            ).returncode == 0
        except (OSError, subprocess.SubprocessError, CommandError):
            return False

    @staticmethod
    def _project_root() -> Path:
        return project_root(Path(__file__).resolve().parents[2])

    def install_subscription_service(self, state: AppState) -> bool:
        install_dir = self._project_root()
        interpreter = python_executable(install_dir)
        host = "127.0.0.1" if getattr(state.network, "sub_domain", "") else "0.0.0.0"
        content = f"""[Unit]
Description=HYDRA Subscription Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory={install_dir}
Environment=PYTHONPATH={install_dir}
ExecStart={interpreter} -m hydra.entrypoints.subscription_server --host {host} --port 9443
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
        return systemd.install_service("hydra-sub", content)

    def subscription_certificate(self, state: AppState) -> tuple[str | None, str | None]:
        from hydra.services.subscriptions.certificates import find_any_cert

        return find_any_cert(state)

    def subscription_public_host(self, state: AppState) -> str:
        from hydra.utils.net import public_ip

        return (
            getattr(state.network, "sub_domain", "")
            or state.network.domain
            or state.network.server_ip
            or public_ip()
        )

    def obtain_subscription_certificate(self, domain: str) -> AdminCommandResult:
        if not domain:
            return AdminCommandResult(False, "missing_domain")

        cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        key_path = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
        if cert_path.exists() and key_path.exists():
            try:
                check = HOST.run(
                    [
                        "openssl", "x509", "-checkend", "2592000",
                        "-noout", "-in", str(cert_path),
                    ],
                    capture_output=True,
                )
                if check.returncode == 0:
                    return AdminCommandResult(True, "already_valid")
            except (OSError, subprocess.SubprocessError, CommandError):
                pass

        if not shutil.which("certbot"):
            try:
                updated = HOST.run(["apt-get", "update"], capture_output=True)
                installed = HOST.run(
                    ["apt-get", "install", "-y", "certbot"],
                    capture_output=True,
                )
                if updated.returncode != 0 or installed.returncode != 0:
                    return AdminCommandResult(False, "certbot_install_failed")
            except (OSError, subprocess.SubprocessError, CommandError) as exc:
                return AdminCommandResult(False, "certbot_install_failed", detail=str(exc))

        from hydra.utils.firewall import temporary_open_port

        services_to_stop = ("caddy-l4", "haproxy", "caddy-naive", "nginx", "apache2")
        was_running: list[str] = []
        try:
            for service in services_to_stop:
                status = HOST.run(
                    ["systemctl", "is-active", service],
                    capture_output=True,
                    text=True,
                )
                if status.stdout.strip() != "active":
                    continue
                stopped = HOST.run(
                    ["systemctl", "stop", service],
                    capture_output=True,
                    text=True,
                )
                if stopped.returncode != 0:
                    detail = stopped.stderr or stopped.stdout or "unknown error"
                    return AdminCommandResult(
                        False,
                        "port_busy",
                        message=service,
                        detail=str(detail).strip(),
                    )
                was_running.append(service)

            with temporary_open_port("tcp", 80, "temp-certbot"):
                result = HOST.run(
                    [
                        "certbot", "certonly", "--standalone",
                        "-d", domain,
                        "--non-interactive", "--agree-tos",
                        "--register-unsafely-without-email",
                        "--keep-until-expiring",
                    ],
                    capture_output=True,
                    text=True,
                )
            if result.returncode == 0:
                return AdminCommandResult(True, "obtained")
            return AdminCommandResult(
                False,
                "certbot_failed",
                detail=str(result.stderr or result.stdout or "").strip(),
            )
        except (OSError, subprocess.SubprocessError, CommandError) as exc:
            return AdminCommandResult(False, "certbot_failed", detail=str(exc))
        finally:
            for service in reversed(was_running):
                try:
                    HOST.run(
                        ["systemctl", "start", service],
                        capture_output=True,
                        text=True,
                    )
                except (OSError, subprocess.SubprocessError, CommandError):
                    pass

    def update_subscription_domain(
        self,
        state: AppState,
        domain: str,
    ) -> AdminCommandResult:
        state.network.sub_domain = domain.strip()
        save_state(state)
        rebuilt = self.refresh_subscription_routing(state)
        installed = self.install_subscription_service(state)
        return AdminCommandResult(
            rebuilt and installed,
            "updated" if rebuilt and installed else "partial_update",
        )

    def refresh_subscription_routing(self, state: AppState) -> bool:
        from hydra.core import sni_router

        try:
            return bool(sni_router.rebuild(state))
        except (OSError, subprocess.SubprocessError, CommandError):
            return False

    def install_admin_bot(self, state: AppState) -> AdminCommandResult:
        try:
            from telegram.ext import Application, CallbackQueryHandler  # noqa: F401
        except ImportError:
            installed = HOST.run(
                [
                    sys.executable, "-m", "pip", "install", "--upgrade", "-q",
                    "python-telegram-bot[job-queue]==22.8",
                ],
                timeout=180,
                text=True,
            )
            if installed.returncode != 0:
                return AdminCommandResult(False, "dependency_install_failed")

        project_root = self._project_root()
        interpreter = python_executable(project_root)
        unit_installed = systemd.install_service(
            "hydra-tg-admin",
            f"""[Unit]
Description=HYDRA Admin Bot (System Info + Security Alerts)
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=root
WorkingDirectory={project_root}
Environment=PYTHONPATH={project_root}
ExecStart={interpreter} -m hydra.services.telegram.admin_bot_entrypoint
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
""",
        )
        started = HOST.run(
            ["systemctl", "restart", "hydra-tg-admin.service"],
            timeout=30,
            text=True,
        )
        active = HOST.run(
            ["systemctl", "is-active", "--quiet", "hydra-tg-admin.service"],
            timeout=15,
        )
        state.telegram.admin_enabled = bool(
            unit_installed and started.returncode == 0 and active.returncode == 0
        )
        save_state(state)
        return AdminCommandResult(
            state.telegram.admin_enabled,
            "started" if state.telegram.admin_enabled else "start_failed",
        )

    def stop_admin_bot(self, state: AppState) -> AdminCommandResult:
        admin_removed = systemd.remove_unit("hydra-tg-admin")
        legacy_removed = systemd.remove_unit("hydra-tg-bot")
        state.telegram.admin_enabled = False
        state.telegram.bot_enabled = False
        save_state(state)
        return AdminCommandResult(
            admin_removed and legacy_removed,
            "stopped",
        )

    def configure_sync_agent(self, enabled: bool) -> bool:
        if not enabled:
            return systemd.remove_unit("hydra-sync-agent")
        project_root = self._project_root()
        interpreter = python_executable(project_root)
        return systemd.install_timer(
            "hydra-sync-agent",
            f"""[Unit]
Description=HYDRA Sync Agent
After=network.target
[Service]
Type=oneshot
User=root
WorkingDirectory={project_root}
Environment=PYTHONPATH={project_root}
ExecStart={interpreter} -m hydra.entrypoints.sync_agent
""",
            """[Unit]
Description=HYDRA Sync Agent Timer
[Timer]
OnCalendar=*:0/5
Persistent=true
[Install]
WantedBy=timers.target
""",
        )

    def run_sync_agent(self) -> tuple[bool, str]:
        if self._sync_operations is None or self._sync_runner is None:
            return False, "sync operations are not configured"
        return self._sync_runner(
            force_update_check=True,
            force_all_checks=True,
            operations=self._sync_operations,
        )

    def install_packages(self, packages: Sequence[str]) -> bool:
        try:
            update = HOST.run(["apt-get", "update"], timeout=300)
            install = HOST.run(
                ["apt-get", "install", "-y", *packages],
                timeout=300,
            )
            return update.returncode == 0 and install.returncode == 0
        except (OSError, subprocess.SubprocessError, CommandError):
            return False

    def run_command(
        self,
        args: Sequence[object],
        **kwargs: Any,
    ) -> subprocess.CompletedProcess:
        return HOST.run(args, **kwargs)

    def popen_command(self, args: Sequence[object], **kwargs: Any) -> subprocess.Popen:
        return HOST.popen(args, **kwargs)

    def singbox_diagnostics(self) -> SingboxDiagnostics:
        from hydra.core import singbox

        installed = singbox.is_installed()
        running = singbox.is_running()
        version = singbox.get_version() or ""
        config_exists = singbox.SINGBOX_CONFIG.exists()
        check_ok, detail = singbox.validate_current_config()
        return SingboxDiagnostics(
            installed=installed,
            running=running,
            version=version,
            config_exists=config_exists,
            config_check_ok=check_ok,
            config_check_detail=detail,
        )

    def install_singbox(self, *, force: bool = False) -> bool:
        from hydra.core.singbox import install

        return bool(install(force=force))

    def update_singbox(self) -> tuple[bool, str]:
        from hydra.core.singbox import update_kernel

        return update_kernel()

    def start_singbox(self) -> bool:
        from hydra.core.singbox import start

        return bool(start())

    def stop_singbox(self) -> bool:
        from hydra.core.singbox import stop

        return bool(stop())

    def apply_network_tuning(self) -> dict[str, Any]:
        from hydra.core.network_tuning import apply_network_tuning

        return apply_network_tuning()

    def rollback_network_tuning(self) -> dict[str, Any]:
        from hydra.core.network_tuning import rollback_network_tuning

        return rollback_network_tuning()

    def system_overview(self, state: AppState) -> SystemOverview:
        from hydra.services.system_overview import collect_system_overview

        return collect_system_overview(state, host=HOST)

    def unit_diagnostics(self, unit: str) -> UnitDiagnostics:
        loaded = HOST.run(
            ["systemctl", "show", unit, "--property=LoadState", "--value"],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if loaded.returncode != 0 or loaded.stdout.strip() != "loaded":
            return UnitDiagnostics(False)
        active = HOST.run(
            ["systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        enabled = HOST.run(
            ["systemctl", "is-enabled", unit],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        return UnitDiagnostics(
            True,
            active=str(active.stdout or "").strip(),
            enabled=str(enabled.stdout or "").strip(),
            active_ok=active.returncode == 0,
            enabled_ok=enabled.returncode == 0,
        )

    def read_text_lines(self, path: Path) -> list[str]:
        return path.read_text(encoding="utf-8").splitlines()

    def read_bytes(self, path: Path) -> bytes:
        return path.read_bytes()

    def atomic_write(self, path: Path, content: str | bytes) -> None:
        HOST.atomic_write(path, content)
