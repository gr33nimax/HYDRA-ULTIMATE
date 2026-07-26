"""Systemd unit management for the SNI router and source relays."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hydra.core.install_layout import python_executable


@dataclass(frozen=True)
class UnitSettings:
    """Filesystem paths and service names needed to render Hydra units."""

    caddy_binary: Path
    caddy_config: Path
    caddy_admin_address: str
    caddy_service_name: str
    caddy_service_file: Path
    source_service_name: str
    source_service_file: Path
    relay_service_name: str
    relay_service_file: Path
    project_root: Path


def install_source_service(
    tcp_ports: set[int],
    udp_ports: set[int],
    settings: UnitSettings,
    host: Any,
) -> None:
    """Install the oneshot policy-routing unit used by transparent sockets."""
    tcp = ",".join(str(port) for port in sorted(tcp_ports))
    udp = ",".join(str(port) for port in sorted(udp_ports))
    interpreter = python_executable(settings.project_root)
    unit = f"""[Unit]
Description=Hydra Caddy source-address reply routing
After=network-online.target
Before={settings.caddy_service_name}.service

[Service]
Type=oneshot
WorkingDirectory={settings.project_root}
Environment=PYTHONPATH={settings.project_root}
ExecStart={interpreter} -m hydra.core.source_transparency apply --tcp {tcp} --udp {udp}
ExecStop={interpreter} -m hydra.core.source_transparency clear
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    settings.source_service_file.parent.mkdir(parents=True, exist_ok=True)
    settings.source_service_file.write_text(unit, encoding="utf-8")
    host.run(["systemctl", "daemon-reload"], capture_output=True)
    result = host.run(
        ["systemctl", "enable", settings.source_service_name],
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError("cannot enable persistent Caddy source routing")


def remove_source_service(settings: UnitSettings, host: Any) -> None:
    """Disable and remove the transparent-source routing unit."""
    host.run(
        ["systemctl", "disable", "--now", settings.source_service_name],
        capture_output=True,
    )
    settings.source_service_file.unlink(missing_ok=True)
    host.run(["systemctl", "daemon-reload"], capture_output=True)


def install_relay_service(
    routes: list[tuple[str, int, int]],
    udp_routes: list[tuple[str, int, int]],
    settings: UnitSettings,
    host: Any,
) -> None:
    """Install the exact-source attribution relay with current route arguments."""
    tcp_arguments = " ".join(
        f"--route {protocol}:{listen}:{backend}"
        for protocol, listen, backend in routes
    )
    udp_arguments = " ".join(
        f"--udp-route {protocol}:{listen}:{backend}"
        for protocol, listen, backend in udp_routes
    )
    arguments = " ".join(
        value for value in (tcp_arguments, udp_arguments) if value
    )
    interpreter = python_executable(settings.project_root)
    unit = f"""[Unit]
Description=Hydra exact source attribution relay
After=network-online.target sing-box.service
Wants=network-online.target
Before={settings.caddy_service_name}.service

[Service]
Type=simple
WorkingDirectory={settings.project_root}
Environment=PYTHONPATH={settings.project_root}
ExecStart={interpreter} -m hydra.core.source_relay {arguments}
Restart=on-failure
RestartSec=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RuntimeDirectory=hydra-source-relay
RuntimeDirectoryMode=0750
ReadWritePaths=/run/hydra-source-relay

[Install]
WantedBy=multi-user.target
"""
    settings.relay_service_file.parent.mkdir(parents=True, exist_ok=True)
    settings.relay_service_file.write_text(unit, encoding="utf-8")
    host.run(["systemctl", "daemon-reload"], capture_output=True)
    result = host.run(
        ["systemctl", "enable", settings.relay_service_name],
        capture_output=True,
    )
    if result.returncode == 0:
        result = host.run(
            ["systemctl", "restart", settings.relay_service_name],
            capture_output=True,
        )
    if result.returncode != 0:
        raise RuntimeError("cannot start exact source attribution relay")


def remove_relay_service(settings: UnitSettings, host: Any) -> None:
    """Disable and remove the exact-source attribution relay."""
    host.run(
        ["systemctl", "disable", "--now", settings.relay_service_name],
        capture_output=True,
    )
    settings.relay_service_file.unlink(missing_ok=True)
    host.run(["systemctl", "daemon-reload"], capture_output=True)


def restore_unit_file(path: Path, content: bytes | None) -> None:
    """Atomically restore a captured systemd unit, or remove a new one."""
    if content is None:
        path.unlink(missing_ok=True)
        return
    rollback = path.with_suffix(path.suffix + ".rollback")
    rollback.write_bytes(content)
    rollback.replace(path)


def install_caddy_service(
    settings: UnitSettings,
    host: Any,
    *,
    source_required: bool = False,
    relay_required: bool = False,
) -> bool:
    """Render and install the Caddy L4 systemd unit."""
    source_after = (
        f" {settings.source_service_name}.service"
        if source_required
        else ""
    )
    source_requires = (
        f"Requires={settings.source_service_name}.service\n"
        if source_required
        else ""
    )
    relay_after = (
        f" {settings.relay_service_name}.service"
        if relay_required
        else ""
    )
    relay_requires = (
        f"Requires={settings.relay_service_name}.service\n"
        if relay_required
        else ""
    )
    unit = f"""[Unit]
Description=Caddy L4 (TLS multiplexer + decoy)
After=network-online.target sing-box.service{source_after}{relay_after}
Wants=network-online.target
{source_requires}{relay_requires}

[Service]
Type=notify
ExecStart={settings.caddy_binary} run --config {settings.caddy_config}
ExecReload={settings.caddy_binary} reload --config {settings.caddy_config} --address {settings.caddy_admin_address} --force
Restart=on-failure
RestartSec=1
TimeoutStopSec=5
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
"""
    try:
        settings.caddy_service_file.parent.mkdir(parents=True, exist_ok=True)
        settings.caddy_service_file.write_text(unit, encoding="utf-8")
        result = host.run(
            ["systemctl", "daemon-reload"],
            capture_output=True,
        )
        return result.returncode == 0
    except OSError:
        return False


__all__ = [
    "UnitSettings",
    "install_caddy_service",
    "install_relay_service",
    "install_source_service",
    "remove_relay_service",
    "remove_source_service",
    "restore_unit_file",
]
