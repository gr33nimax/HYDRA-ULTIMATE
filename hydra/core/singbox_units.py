"""Managed systemd unit for the Sing-Box runtime."""
from __future__ import annotations

from pathlib import Path

from hydra.core.host import HostBackend


def render_service_unit(binary_path: Path, config_path: Path) -> str:
    """Render the systemd unit expected by the current HYDRA release."""
    return f"""[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
WorkingDirectory=/var/lib/sing-box
Environment=LEGACY_DNS_SERVERS=true ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true
ExecStart={binary_path} run -c {config_path}
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=30
LimitNPROC=500
LimitNOFILE=1000000
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE

[Install]
WantedBy=multi-user.target
"""


def service_unit_needs_update(
    service_path: Path,
    binary_path: Path,
    config_path: Path,
) -> bool:
    """Return whether the installed unit differs from HYDRA's current unit."""
    try:
        installed_unit = service_path.read_text(encoding="utf-8")
    except OSError:
        return True
    return installed_unit != render_service_unit(binary_path, config_path)


def install_service_unit(
    service_path: Path,
    binary_path: Path,
    config_path: Path,
    host: HostBackend,
) -> bool:
    """Write the managed unit and reload the systemd manager."""
    Path("/var/lib/sing-box").mkdir(parents=True, exist_ok=True)
    service_path.parent.mkdir(parents=True, exist_ok=True)
    service_path.write_text(
        render_service_unit(binary_path, config_path),
        encoding="utf-8",
    )
    result = host.run(["systemctl", "daemon-reload"])
    return result.returncode == 0
