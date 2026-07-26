"""Runtime observation for ShadowTLS."""
from __future__ import annotations

from collections.abc import Callable

from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess


def status(
    state: PluginStateAccess | None,
    *,
    get_total_traffic: Callable[[], int],
) -> PluginStatus:
    """Observe runtime using only explicitly supplied desired state."""
    from hydra.core.singbox import is_installed, is_running

    installed = is_installed()
    protocol = (
        state.protocols.get("shadowtls")
        if state is not None
        else None
    )
    enabled = bool(protocol and protocol.enabled)
    info = {}
    if installed and enabled:
        try:
            info["Общий трафик"] = _format_bytes(
                get_total_traffic()
            )
        except Exception:
            pass

    effective_port = 443
    if state is not None:
        try:
            from hydra.core.sni_router import get_effective_port

            effective_port = get_effective_port("shadowtls", state)
        except Exception:
            pass
    return PluginStatus(
        installed=installed,
        enabled=enabled,
        running=installed and is_running() and enabled,
        port=effective_port,
        info=info,
    )


def traffic(state: PluginStateAccess) -> dict[str, int]:
    result = {}
    for user in state.users:
        used = user.credentials.get("shadowtls", {}).get(
            "traffic_used_bytes",
            0,
        )
        if used > 0:
            result[user.email] = used
    return result


def connected_clients(
    state: PluginStateAccess | None,
    *,
    which: Callable[[str], str | None],
    host,
    now: Callable[[], float],
) -> list[dict]:
    """Read socket and firewall counters without persistence access."""
    if not which("ss"):
        return []

    effective_port = 443
    if state is not None:
        try:
            from hydra.core.sni_router import get_effective_port

            effective_port = get_effective_port("shadowtls", state)
        except Exception:
            pass

    result = host.run(
        ["ss", "-t", "-H", "-n", "state", "established"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []

    ip_counts = _connected_ips(
        result.stdout,
        effective_port=effective_port,
    )
    rx_bytes = _iptables_counter(
        host,
        chain="INPUT",
        marker="shadowtls-rx",
    )
    tx_bytes = _iptables_counter(
        host,
        chain="OUTPUT",
        marker="shadowtls-tx",
    )
    client_count = len(ip_counts)
    timestamp = int(now())
    return [
        {
            "online": True,
            "email": f"{remote_ip} ({count} TCP)",
            "rx": (
                rx_bytes // client_count
                if client_count > 0
                else 0
            ),
            "tx": (
                tx_bytes // client_count
                if client_count > 0
                else 0
            ),
            "last_handshake": timestamp,
        }
        for remote_ip, count in ip_counts.items()
    ]


def _connected_ips(
    socket_table: str,
    *,
    effective_port: int,
) -> dict[str, int]:
    ip_counts = {}
    for line in socket_table.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local_port_text = parts[2].split(":")[-1]
        if not local_port_text.isdigit():
            continue
        local_port = int(local_port_text)
        if local_port not in (effective_port, 443):
            continue
        remote_parts = parts[3].split(":")
        remote_ip = ":".join(remote_parts[:-1]).strip("[]")
        ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1
    return ip_counts


def _iptables_counter(
    host,
    *,
    chain: str,
    marker: str,
) -> int:
    result = host.run(
        [
            "iptables",
            "-t",
            "filter",
            "-L",
            chain,
            "-n",
            "-v",
            "-x",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return 0

    total = 0
    for line in result.stdout.splitlines():
        if marker not in line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            total += int(parts[1])
    return total


def _format_bytes(total: int) -> str:
    size = float(total)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return (
                f"{int(size)} B"
                if unit == "B"
                else f"{size:.2f} {unit}"
            )
        size /= 1024.0
    return f"{size:.2f} PB"
