"""Read-only NaiveProxy service and socket observation."""
from __future__ import annotations

import shutil
import time

from hydra.plugins.base import PluginStatus
from hydra.plugins.context import PluginStateAccess


def _format_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return (
                f"{int(size)} B"
                if unit == "B"
                else f"{size:.2f} {unit}"
            )
        size /= 1024.0
    return f"{size:.2f} PB"


def _socket_remote_counts(
    output: str,
    *,
    accepted_ports: set[int],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local_port_text = parts[2].split(":")[-1]
        if (
            not local_port_text.isdigit()
            or int(local_port_text) not in accepted_ports
        ):
            continue
        remote_parts = parts[3].split(":")
        remote_ip = ":".join(remote_parts[:-1]).strip("[]")
        counts[remote_ip] = counts.get(remote_ip, 0) + 1
    return counts


def _counter_bytes(output: str, marker: str) -> int:
    total = 0
    for line in output.splitlines():
        if marker not in line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            total += int(parts[1])
    return total


class NaiveObservationMixin:
    """Read service state, sockets, and legacy firewall counters."""

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        layout = self._runtime_layout()
        installed = self._installed()
        running = False
        if installed:
            result = self._host_backend().run(
                ["systemctl", "is-active", layout.service_name],
                capture_output=True,
                text=True,
            )
            running = result.stdout.strip() == "active"

        info: dict[str, str] = {}
        if installed and running:
            try:
                info["Общий трафик"] = _format_bytes(
                    self._get_total_traffic(),
                )
            except Exception:
                pass

        effective_port = layout.default_port
        if state is not None:
            try:
                from hydra.core.sni_router import get_effective_port

                effective_port = get_effective_port("naive", state)
                protocol = state.protocols.get("naive")
                if protocol is not None and protocol.config:
                    mode = protocol.config.get("network", "tcp")
                    labels = {
                        "tcp": "HTTP/2 (TCP)",
                        "quic": "QUIC (UDP)",
                        "both": "HTTP/2 + QUIC",
                    }
                    info["Транспорт"] = labels.get(mode, str(mode))
            except Exception:
                pass

        return PluginStatus(
            installed=installed,
            enabled=layout.caddyfile.exists(),
            running=running,
            port=effective_port,
            info=info,
        )

    def connected_clients(
        self,
        state: PluginStateAccess | None = None,
    ) -> list[dict]:
        if not shutil.which("ss"):
            return []

        layout = self._runtime_layout()
        effective_port = layout.default_port
        if state is not None:
            from hydra.core.sni_router import get_effective_port

            effective_port = get_effective_port("naive", state)
        accepted_ports = {layout.default_port, effective_port}
        host = self._host_backend()
        counts: dict[str, int] = {}
        for protocol in ("-t", "-u"):
            result = host.run(
                [
                    "ss",
                    protocol,
                    "-H",
                    "-n",
                    "state",
                    "established",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                continue
            for address, count in _socket_remote_counts(
                result.stdout,
                accepted_ports=accepted_ports,
            ).items():
                counts[address] = counts.get(address, 0) + count

        rx_bytes = self._iptables_counter("INPUT", "naive-rx")
        tx_bytes = self._iptables_counter("OUTPUT", "naive-tx")
        client_count = len(counts)
        now = int(time.time())
        return [
            {
                "online": True,
                "email": f"{address} ({count} Conn)",
                "rx": rx_bytes // client_count if client_count else 0,
                "tx": tx_bytes // client_count if client_count else 0,
                "last_handshake": now,
            }
            for address, count in counts.items()
        ]

    def _iptables_counter(self, chain: str, marker: str) -> int:
        result = self._host_backend().run(
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
        return _counter_bytes(result.stdout, marker)

    def _get_total_traffic(self) -> int:
        return self._iptables_counter(
            "INPUT",
            "naive-",
        ) + self._iptables_counter(
            "OUTPUT",
            "naive-",
        )
