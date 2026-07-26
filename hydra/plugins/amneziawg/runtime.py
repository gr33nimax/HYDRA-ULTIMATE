"""Host lifecycle and runtime reconciliation for AmneziaWG."""
from __future__ import annotations

import platform
import re
import shutil
import subprocess
from pathlib import Path

from hydra.core.host import HOST
from hydra.plugins.context import PluginStateAccess

from .constants import (
    AWG_BIN,
    AWG_INTERFACE,
    AWG_INTERFACE_1,
    AWG_PARAMS,
    AWG_UNIT,
    AWG_UNIT_1,
    DEFAULT_PORT,
)


class AwgRuntimeMixin:
    """Own all AmneziaWG writes, process control, and firewall mutations."""

    def apply(self, state: PluginStateAccess) -> bool:
        """Persist the completed render and reconcile both interfaces."""
        desktop_conf = self._conf_path("desktop")
        mobile_conf = self._conf_path("mobile")
        ok = True
        if self._pending_conf:
            desktop_conf.parent.mkdir(parents=True, exist_ok=True)
            desktop_conf.write_text(self._pending_conf, encoding="utf-8")
            desktop_conf.chmod(0o600)
            ok = ok and self._apply_iface(
                AWG_INTERFACE,
                desktop_conf,
                AWG_UNIT,
            )

        mobile_enabled = self._profile_config(state, "mobile") is not None
        if mobile_enabled and self._pending_conf_1:
            mobile_conf.parent.mkdir(parents=True, exist_ok=True)
            mobile_conf.write_text(self._pending_conf_1, encoding="utf-8")
            mobile_conf.chmod(0o600)
            ok = ok and self._apply_iface(
                AWG_INTERFACE_1,
                mobile_conf,
                AWG_UNIT_1,
            )
        elif mobile_enabled:
            return False
        else:
            HOST.run(["systemctl", "stop", AWG_UNIT_1], capture_output=True)
            HOST.run(["systemctl", "disable", AWG_UNIT_1], capture_output=True)
            mobile_conf.unlink(missing_ok=True)
            self._pending_conf_1 = None
        return ok

    def snapshot(self, state: PluginStateAccess):
        def read(path: Path):
            return path.read_bytes() if path.exists() else None

        return {
            "awg0": read(self._conf_path("desktop")),
            "awg1": read(self._conf_path("mobile")),
            "running0": self._is_up(),
            "running1": self._is_up_iface(AWG_INTERFACE_1),
        }

    def rollback(self, state: PluginStateAccess, snapshot) -> bool:
        previous = snapshot or {}
        paths = (
            ("awg0", self._conf_path("desktop")),
            ("awg1", self._conf_path("mobile")),
        )
        for key, path in paths:
            content = previous.get(key)
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                path.chmod(0o600)
        ok = True
        units = (
            (AWG_UNIT, previous.get("running0")),
            (AWG_UNIT_1, previous.get("running1")),
        )
        for unit, running in units:
            command = (
                ["systemctl", "restart", unit]
                if running
                else ["systemctl", "stop", unit]
            )
            ok = HOST.run(command, capture_output=True).returncode == 0 and ok
        return ok

    def _apply_iface(
        self,
        interface: str,
        conf_path: Path,
        unit: str,
    ) -> bool:
        """Sync an active interface or start it through its systemd unit."""
        HOST.run(["systemctl", "enable", unit], capture_output=True)
        active_ip = self._active_ip_iface(interface)
        config_ip = None
        if conf_path.exists():
            match = re.search(
                r"Address\s*=\s*(\d+\.\d+\.\d+\.\d+)",
                conf_path.read_text(encoding="utf-8"),
            )
            if match:
                config_ip = match.group(1)
        if active_ip and config_ip and active_ip != config_ip:
            HOST.run(["systemctl", "restart", unit], capture_output=True)
            return self._is_up_iface(interface)
        if self._is_up_iface(interface):
            result = HOST.run(
                [
                    "bash",
                    "-c",
                    f"awg syncconf {interface} <(awg-quick strip {interface})",
                ],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0

        result = HOST.run(
            ["systemctl", "start", unit],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            fallback = HOST.run(
                ["awg-quick", "up", interface],
                capture_output=True,
                text=True,
            )
            if fallback.returncode != 0:
                detail = (
                    fallback.stderr
                    or fallback.stdout
                    or result.stderr
                    or result.stdout
                    or "unknown error"
                ).strip()
                raise RuntimeError(f"failed to start {interface}: {detail}")
            result = fallback
        return result.returncode == 0

    @staticmethod
    def _active_ip_iface(interface: str) -> str | None:
        if platform.system() != "Linux":
            return None
        try:
            result = HOST.run(
                ["ip", "-o", "-4", "addr", "show", interface],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0 or not isinstance(result.stdout, str):
                return None
            match = re.search(
                r"inet\s+(\d+\.\d+\.\d+\.\d+)",
                result.stdout,
            )
            return match.group(1) if match else None
        except Exception:
            return None

    def on_enable(self, state: PluginStateAccess) -> None:
        ready, detail = self._ensure_kernel_module()
        if not ready:
            raise RuntimeError(detail)
        self._ensure_ip_forward()
        try:
            from hydra.plugins.amneziawg.tuning import hw_tune_all

            hw_tune_all()
        except Exception:
            pass
        try:
            self._remove_nat(state)
        except Exception:
            pass
        self._ensure_forward()

    def on_disable(self, state: PluginStateAccess) -> None:
        self._remove_forward()
        try:
            self._remove_nat(state)
        except Exception:
            pass
        HOST.run(["systemctl", "stop", AWG_UNIT], capture_output=True)
        HOST.run(["systemctl", "stop", AWG_UNIT_1], capture_output=True)

    @staticmethod
    def _ensure_ip_forward() -> None:
        result = HOST.run(
            ["sysctl", "-n", "net.ipv4.ip_forward"],
            capture_output=True,
            text=True,
        )
        if result.stdout.strip() == "1":
            return
        HOST.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True,
        )
        HOST.run(
            [
                "sed",
                "-i",
                "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g",
                "/etc/sysctl.conf",
            ],
            capture_output=True,
        )
        HOST.run(
            [
                "sh",
                "-c",
                "grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || "
                "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf",
            ],
            capture_output=True,
        )

    def _remove_nat(self, state: PluginStateAccess) -> None:
        _, _, network = self._network(state)
        HOST.run(
            [
                "iptables",
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                network,
                "-o",
                self._wan_iface(),
                "-j",
                "MASQUERADE",
            ],
            capture_output=True,
        )

    def _runtime_interfaces(self) -> tuple[str, ...]:
        if self._conf_path("mobile").exists():
            return AWG_INTERFACE, AWG_INTERFACE_1
        return (AWG_INTERFACE,)

    def _ensure_forward(self) -> None:
        for interface in self._runtime_interfaces():
            for direction in ("-i", "-o"):
                result = HOST.run(
                    [
                        "iptables",
                        "-C",
                        "FORWARD",
                        direction,
                        interface,
                        "-j",
                        "ACCEPT",
                    ],
                    capture_output=True,
                )
                if result.returncode != 0:
                    HOST.run(
                        [
                            "iptables",
                            "-I",
                            "FORWARD",
                            direction,
                            interface,
                            "-j",
                            "ACCEPT",
                        ],
                        capture_output=True,
                    )
            tcp_rule = [
                "-i",
                interface,
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
            ]
            result = HOST.run(
                [
                    "iptables",
                    "-t",
                    "mangle",
                    "-C",
                    "FORWARD",
                    *tcp_rule,
                    "-j",
                    "TCPMSS",
                    "--clamp-mss-to-pmtu",
                ],
                capture_output=True,
            )
            if result.returncode != 0:
                HOST.run(
                    [
                        "iptables",
                        "-t",
                        "mangle",
                        "-I",
                        "FORWARD",
                        *tcp_rule,
                        "-j",
                        "TCPMSS",
                        "--clamp-mss-to-pmtu",
                    ],
                    capture_output=True,
                )

    def _remove_forward(self) -> None:
        for interface in self._runtime_interfaces():
            for direction in ("-i", "-o"):
                HOST.run(
                    [
                        "iptables",
                        "-D",
                        "FORWARD",
                        direction,
                        interface,
                        "-j",
                        "ACCEPT",
                    ],
                    capture_output=True,
                )
            HOST.run(
                [
                    "iptables",
                    "-t",
                    "mangle",
                    "-D",
                    "FORWARD",
                    "-i",
                    interface,
                    "-p",
                    "tcp",
                    "--tcp-flags",
                    "SYN,RST",
                    "SYN",
                    "-j",
                    "TCPMSS",
                    "--clamp-mss-to-pmtu",
                ],
                capture_output=True,
            )

    @staticmethod
    def _wan_iface() -> str:
        result = HOST.run(
            ["sh", "-c", "ip route show default | awk '{print $5}'"],
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() or "eth0"

    @staticmethod
    def _is_up() -> bool:
        if platform.system() != "Linux":
            return False
        return (
            HOST.run(
                ["ip", "link", "show", AWG_INTERFACE],
                capture_output=True,
            ).returncode
            == 0
        )

    def _is_up_iface(self, interface: str) -> bool:
        if interface == AWG_INTERFACE:
            return self._is_up()
        if platform.system() != "Linux":
            return False
        return (
            HOST.run(
                ["ip", "link", "show", interface],
                capture_output=True,
            ).returncode
            == 0
        )

    def _current_port(self) -> int:
        try:
            result = self._awg("show", AWG_INTERFACE)
            match = re.search(r"listening port:\s*(\d+)", result.stdout)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        try:
            match = re.search(
                r"ListenPort\s*=\s*(\d+)",
                self._interface_block(),
            )
            return int(match.group(1)) if match else DEFAULT_PORT
        except Exception:
            return DEFAULT_PORT

    @staticmethod
    def _params() -> dict[str, str]:
        result: dict[str, str] = {}
        if AWG_PARAMS.exists():
            for line in AWG_PARAMS.read_text().splitlines():
                match = re.match(r"(\w+)='?([^']*)'?", line.strip())
                if match:
                    result[match.group(1)] = match.group(2)
        return result

    @staticmethod
    def _awg(
        *args,
        _input: str = "",
    ) -> subprocess.CompletedProcess:
        binary = shutil.which("awg") or str(AWG_BIN)
        kwargs: dict = {"capture_output": True, "text": True}
        if _input:
            kwargs["input"] = _input
        return HOST.run([binary, *args], **kwargs)
