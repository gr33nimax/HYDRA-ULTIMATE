"""NaiveProxy runtime reconciliation and rollback."""
from __future__ import annotations

import time
from pathlib import Path

from hydra.plugins.context import PluginStateAccess

from .constants import DATA_DIR


def _accounting_rule(
    *,
    protocol: str,
    chain: str,
    port: int,
) -> list[str]:
    inbound = chain == "INPUT"
    direction = "rx" if inbound else "tx"
    protocol_suffix = "-udp" if protocol == "udp" else ""
    return [
        "iptables",
        "-I",
        chain,
        "1",
        "-p",
        protocol,
        "--dport" if inbound else "--sport",
        str(port),
        "-m",
        "comment",
        "--comment",
        f"naive-{direction}{protocol_suffix}",
    ]


class NaiveRuntimeMixin:
    """All host-mutating NaiveProxy operations live behind this boundary."""

    _pending_cfg: str | None

    def snapshot(self, state: PluginStateAccess):
        del state
        layout = self._runtime_layout()
        runtime = self._host_backend().run(
            ["systemctl", "is-active", layout.service_name],
            capture_output=True,
            text=True,
        )
        return {
            "config": (
                layout.caddyfile.read_bytes()
                if layout.caddyfile.exists()
                else None
            ),
            "service": (
                layout.service_file.read_bytes()
                if layout.service_file.exists()
                else None
            ),
            "running": (
                runtime.returncode == 0
                and runtime.stdout.strip() == "active"
            ),
        }

    def rollback(
        self,
        state: PluginStateAccess,
        snapshot,
    ) -> bool:
        del state
        layout = self._runtime_layout()
        previous = snapshot or {}
        for key, path in (
            ("config", layout.caddyfile),
            ("service", layout.service_file),
        ):
            content = previous.get(key)
            if content is None:
                path.unlink(missing_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(path.suffix + ".rollback")
            temporary.write_bytes(content)
            temporary.replace(path)

        host = self._host_backend()
        host.run(["systemctl", "daemon-reload"], capture_output=True)
        action = "restart" if previous.get("running") else "stop"
        result = host.run(
            ["systemctl", action, layout.service_name],
            capture_output=True,
        )
        return result.returncode == 0

    def apply(self, state: PluginStateAccess) -> bool:
        if not self._pending_cfg:
            return False

        layout = self._runtime_layout()
        layout.config_dir.mkdir(parents=True, exist_ok=True)
        layout.log_dir.mkdir(parents=True, exist_ok=True)
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._create_fake_site()

        pending = layout.caddyfile.with_suffix(".pending")
        pending.write_text(self._pending_cfg)
        pending.chmod(0o640)
        error = self._validate_caddy(pending)
        if error:
            pending.unlink(missing_ok=True)
            print(f"  Caddyfile validation error: {error}")
            return False
        pending.replace(layout.caddyfile)

        host = self._host_backend()
        enabled = host.run(
            ["systemctl", "enable", layout.service_name],
            capture_output=True,
        )
        restarted = host.run(
            ["systemctl", "reload-or-restart", layout.service_name],
            capture_output=True,
        )
        if enabled.returncode != 0 or restarted.returncode != 0:
            return False

        protocol = state.protocols.get("naive")
        network = (
            protocol.config.get("network", "tcp")
            if protocol is not None
            else "tcp"
        )
        self._sync_transport_firewall(network)
        time.sleep(2)
        return True

    def on_disable(self, state: PluginStateAccess) -> None:
        del state
        from hydra.utils.firewall import close_tcp, close_udp

        layout = self._runtime_layout()
        self._host_backend().run(
            ["systemctl", "stop", layout.service_name],
            capture_output=True,
        )
        close_tcp(layout.default_port, "naive")
        close_udp(layout.default_port, "naive-quic")
        self._remove_iptables_rules()

    def _sync_transport_firewall(self, network: str) -> None:
        from hydra.utils.firewall import close_udp, open_tcp, open_udp

        layout = self._runtime_layout()
        port = layout.default_port
        open_tcp(port, "naive")
        if network in ("quic", "both"):
            open_udp(port, "naive-quic")
        else:
            close_udp(port, "naive-quic")

        self._remove_iptables_rules()
        host = self._host_backend()
        protocols = (
            ("tcp", "udp")
            if network in ("quic", "both")
            else ("tcp",)
        )
        for protocol in protocols:
            for chain in ("INPUT", "OUTPUT"):
                host.run(
                    _accounting_rule(
                        protocol=protocol,
                        chain=chain,
                        port=port,
                    ),
                    capture_output=True,
                )

    def _remove_iptables_rules(self) -> None:
        host = self._host_backend()
        for chain in ("INPUT", "OUTPUT"):
            result = host.run(
                ["iptables", "-S", chain],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                if "naive-" not in line:
                    continue
                parts = line.split()
                if parts and parts[0] == "-A":
                    parts[0] = "-D"
                    host.run(
                        ["iptables", *parts],
                        capture_output=True,
                    )

    @staticmethod
    def _create_fake_site() -> None:
        from hydra.core.decoy import ensure_decoy_site

        ensure_decoy_site("naive")

    def _validate_caddy(
        self,
        config_path: Path | None = None,
    ) -> str | None:
        layout = self._runtime_layout()
        result = self._host_backend().run(
            [
                str(layout.binary),
                "validate",
                "--config",
                str(config_path or layout.caddyfile),
                "--adapter",
                "caddyfile",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return (result.stderr or result.stdout or "")[:4000]
        return None
