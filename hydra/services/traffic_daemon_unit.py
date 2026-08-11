"""Systemd unit reconciliation for the traffic accounting daemon."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from hydra.core.install_layout import project_root as runtime_project_root
from hydra.core.install_layout import python_executable
from hydra.core.state_models import AppState


class CommandHost(Protocol):
    def run(
        self,
        command: list[str],
        *,
        text: bool = False,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess: ...


@dataclass(frozen=True)
class TrafficDaemonUnitManager:
    """Own the traffic daemon's unit file and systemd state."""

    service_file: Path
    host: CommandHost
    project_root: Path | None = None

    def reconcile(self, state: AppState) -> None:
        enabled = bool(getattr(state.network, "clash_api_enabled", False))
        service_file = self.service_file

        if not enabled and not service_file.exists():
            return
        if os.name != "nt" and shutil.which("systemctl") is None:
            raise RuntimeError("systemctl is unavailable")

        def systemctl(
            *args: str,
            allow_inactive: bool = False,
        ) -> subprocess.CompletedProcess:
            try:
                result = self.host.run(["systemctl", *args], text=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RuntimeError(f"systemctl {' '.join(args)} failed: {exc}") from exc
            if result.returncode != 0 and not allow_inactive:
                detail = (result.stderr or result.stdout or "unknown error").strip()
                raise RuntimeError(f"systemctl {' '.join(args)} failed: {detail}")
            return result

        if enabled:
            project_root = runtime_project_root(
                self.project_root or Path(__file__).resolve().parents[2],
            )
            daemon_revision = self._daemon_revision(project_root)
            unit = self._render_unit(project_root, daemon_revision)
            unit_changed = (
                not service_file.exists()
                or service_file.read_text(encoding="utf-8") != unit
            )
            if unit_changed:
                service_file.parent.mkdir(parents=True, exist_ok=True)
                pending = service_file.with_suffix(".service.pending")
                pending.write_text(unit, encoding="utf-8")
                pending.chmod(0o644)
                pending.replace(service_file)
                systemctl("daemon-reload")
            systemctl("enable", "hydra-traffic-daemon")
            active = (
                systemctl(
                    "is-active",
                    "--quiet",
                    "hydra-traffic-daemon",
                    allow_inactive=True,
                ).returncode
                == 0
            )
            if unit_changed:
                systemctl("restart", "hydra-traffic-daemon")
            elif not active:
                systemctl("start", "hydra-traffic-daemon")
            return

        systemctl("stop", "hydra-traffic-daemon", allow_inactive=True)
        systemctl("disable", "hydra-traffic-daemon", allow_inactive=True)
        service_file.unlink(missing_ok=True)
        systemctl("daemon-reload")

    @staticmethod
    def _daemon_revision(project_root: Path) -> str:
        """Hash the whole traffic-daemon component, not only its facade."""
        service_root = project_root / "hydra" / "services"
        sources = sorted({
            *service_root.glob("traffic*.py"),
            *service_root.glob("calls_telemetry*.py"),
        })
        if not sources:
            return "unknown"
        digest = hashlib.sha256()
        try:
            for path in sources:
                digest.update(path.name.encode("utf-8"))
                digest.update(b"\0")
                digest.update(path.read_bytes())
                digest.update(b"\0")
        except OSError:
            return "unknown"
        return digest.hexdigest()[:12]

    @staticmethod
    def _render_unit(project_root: Path, daemon_revision: str) -> str:
        interpreter = python_executable(project_root)
        return f"""[Unit]
Description=HYDRA User Traffic Accounting Daemon
After=sing-box.service
Wants=sing-box.service

[Service]
Type=simple
User=root
WorkingDirectory={project_root}
Environment=PYTHONPATH={project_root}
Environment=HYDRA_TRAFFIC_DAEMON_REV={daemon_revision}
ExecStart={interpreter} -m hydra.services.traffic_daemon
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
