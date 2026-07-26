"""Runtime observation for TrustTunnel."""
from __future__ import annotations

from collections.abc import Callable

from hydra.core.state_models import PluginState
from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess


def status(
    state: PluginStateAccess | None,
    *,
    health: Callable[[PluginStateAccess], dict[str, object]],
    get_total_traffic: Callable[[PluginStateAccess], int],
) -> PluginStatus:
    """Observe runtime using only the explicitly supplied desired state."""
    from hydra.core.singbox import is_installed

    installed = is_installed()
    protocol = (
        state.protocols.get("trusttunnel")
        if state is not None
        else None
    )
    enabled = bool(protocol and protocol.enabled)
    info = {}
    health_report: dict[str, object] | None = None
    if installed and enabled and state is not None:
        try:
            info["Общий трафик"] = _format_bytes(
                get_total_traffic(state)
            )
        except Exception:
            pass
        try:
            health_report = health(state)
            errors = health_report.get("errors", [])
            if errors:
                info["Проверка"] = str(errors[0])
        except Exception:
            health_report = None

    effective_port = 443
    if state is not None:
        try:
            from hydra.core.sni_router import get_effective_port

            effective_port = get_effective_port("trusttunnel", state)
        except Exception:
            pass
    return PluginStatus(
        installed=installed,
        enabled=enabled,
        running=(
            installed
            and enabled
            and bool(health_report and health_report.get("ok"))
        ),
        port=effective_port,
        info=info,
    )


def traffic(state: PluginStateAccess) -> dict[str, int]:
    result = {}
    for user in state.users:
        used = user.credentials.get("trusttunnel", {}).get(
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
    transport_of: Callable[[PluginState | None], str],
    collect: Callable[
        [list[str], int, str, dict[tuple[str, str], int]],
        None,
    ],
    now: Callable[[], float],
) -> list[dict]:
    """Read socket tables; never load desired state implicitly."""
    if not which("ss"):
        return []

    effective_port = 443
    protocol = None
    if state is not None:
        protocol = state.protocols.get("trusttunnel")
        try:
            from hydra.core.sni_router import get_effective_port

            effective_port = get_effective_port("trusttunnel", state)
        except Exception:
            pass

    selected_transport = transport_of(protocol)
    counts: dict[tuple[str, str], int] = {}
    if selected_transport in ("tcp", "both"):
        collect(
            ["ss", "-t", "-H", "-n", "state", "established"],
            effective_port,
            "TCP",
            counts,
        )
    if selected_transport in ("quic", "both"):
        collect(
            ["ss", "-u", "-H", "-n"],
            effective_port,
            "QUIC",
            counts,
        )

    timestamp = int(now())
    return [
        {
            "online": True,
            "email": f"{remote_ip} ({kind}, {count} Conns)",
            "rx": 0,
            "tx": 0,
            "last_handshake": timestamp,
        }
        for (kind, remote_ip), count in counts.items()
    ]


def split_endpoint(endpoint: str) -> tuple[str, int | None]:
    endpoint = endpoint.strip()
    if endpoint.startswith("[") and "]:" in endpoint:
        host, _, port = endpoint[1:].partition("]:")
    else:
        host, separator, port = endpoint.rpartition(":")
        if not separator:
            return endpoint.strip("[]"), None
    return host.strip("[]"), int(port) if port.isdigit() else None


def collect_ss_clients(
    cmd: list[str],
    port: int,
    kind: str,
    counts: dict[tuple[str, str], int],
    *,
    host,
    split: Callable[[str], tuple[str, int | None]],
) -> None:
    try:
        result = host.run(cmd, capture_output=True, text=True)
    except OSError:
        return
    if result.returncode != 0:
        return
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        _, local_port = split(parts[-2])
        remote_host, _ = split(parts[-1])
        if (
            local_port != port
            or not remote_host
            or remote_host == "*"
        ):
            continue
        key = (kind, remote_host)
        counts[key] = counts.get(key, 0) + 1


def health(
    state: PluginStateAccess,
    *,
    validate: Callable[..., list[str]],
    transport_of: Callable[[PluginState | None], str],
    host,
) -> dict[str, object]:
    protocol = state.protocols.get("trusttunnel")
    errors = validate(state)
    report: dict[str, object] = {
        "ok": not errors,
        "transport": transport_of(protocol),
        "errors": errors,
        "singbox": False,
        "caddy_l4": False,
    }
    try:
        from hydra.core.singbox import is_running

        report["singbox"] = is_running()
    except Exception:
        pass
    try:
        result = host.run(
            ["systemctl", "is-active", "--quiet", "caddy-l4"],
            capture_output=True,
        )
        report["caddy_l4"] = result.returncode == 0
    except OSError:
        pass
    report["ok"] = bool(
        report["ok"]
        and report["singbox"]
        and report["caddy_l4"]
    )
    return report


def total_traffic(state: PluginStateAccess) -> int:
    return sum(
        int(
            user.credentials.get("trusttunnel", {}).get(
                "traffic_used_bytes",
                0,
            )
        )
        for user in state.users
    )


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
