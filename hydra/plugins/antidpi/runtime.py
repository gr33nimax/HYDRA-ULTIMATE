"""Injected systemd and host runtime adapter for AntiDPI."""

# audit: allow-generated-runtime-subprocess
from __future__ import annotations

import ipaddress
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from hydra.plugins.antidpi.firewall import FirewallAdapter
from hydra.plugins.antidpi.firewall_rules import SET_V4, SET_V6
from hydra.plugins.antidpi.model import ban_duration
from hydra.plugins.antidpi.state_store import AntiDPIStateStore, lock_state_file

# AmneziaWG kernel debug hooks owned by earlier versions.  AntiScan does not
# observe AmneziaWG at all, so these names survive only to switch the hooks
# back off on an upgraded host.
AWG_DEBUG_FUNCTIONS = (
    "wg_receive_handshake_packet",
    "wg_noise_handshake_consume_initiation",
    "prepare_awg_message",
)


def _is_true(value: object) -> bool:
    """Return True only for the JSON boolean ``true``."""
    return isinstance(value, bool) and value


def _as_int(value: object, default: int = 0) -> int:
    """Return an integer from untrusted state, or ``default``."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default
    if isinstance(value, str):
        try:
            return int(value.strip())
        except (TypeError, ValueError):
            return default
    return default


class HostCommands(Protocol):
    def which(self, executable: str) -> str | None:
        """Return the resolved path of an executable, or ``None``."""
        ...


CommandRunner = Callable[..., object]
FailureReporter = Callable[[str], bool]


@dataclass(frozen=True)
class RuntimePaths:
    state: Path
    script: Path
    service: Path
    awg_debug_service: Path
    awg_debug_controls: tuple[Path, ...]
    project_root: Path
    # ``awg_debug_service``/``awg_debug_controls`` are retained only so the
    # upgrade path can delete the artifacts a previous version installed.


class AntiDPIRuntime(FirewallAdapter):
    """Privileged AntiDPI operations behind injected host ports."""

    def __init__(
        self,
        *,
        run: CommandRunner,
        host: HostCommands,
        fail: FailureReporter,
        paths: RuntimePaths,
    ) -> None:
        super().__init__(run=run, fail=fail)
        self.host = host
        self.paths = paths

    def install_dependencies(self, missing: list[str]) -> None:
        packages = []
        if any(name in missing for name in ("ipset", "iptables", "ip6tables")):
            packages.extend(("ipset", "iptables"))
        for command, timeout in (
            (["apt-get", "install", "-y", "-qq", *packages], 180),
            (["dnf", "install", "-y", "-q", *packages], 180),
            (["yum", "install", "-y", "-q", *packages], 180),
            (["apk", "add", "--no-cache", *packages], 180),
            (["pacman", "-S", "--noconfirm", *packages], 180),
        ):
            if not packages or self.host.which(command[0]) is None:
                continue
            result = self.run(command, text=True, timeout=timeout)
            if getattr(result, "returncode", 1) == 0:
                return
            self.fail(
                self.result_error(
                    result,
                    "установка firewall dependencies",
                ),
            )

    def remove_awg_debug_artifacts(self) -> bool:
        """Undo the AmneziaWG debug service owned by earlier versions.

        The contraction removed every AmneziaWG observation, so an upgraded
        host must not keep its kernel debug hook enabled.  The cleanup is
        idempotent: a host that never had the service stays healthy.
        """
        control = next(
            (path for path in self.paths.awg_debug_controls if path.exists()),
            None,
        )
        if control is not None:
            try:
                control.write_text(
                    "".join(f"module amneziawg func {name} -p\n" for name in AWG_DEBUG_FUNCTIONS),
                    encoding="utf-8",
                )
            except OSError:
                # Best effort: the service removal below is the real cleanup.
                pass
        service = self.paths.awg_debug_service
        self.run(["systemctl", "disable", "--now", service.name])
        try:
            service.unlink(missing_ok=True)
        except OSError:
            return False
        self.run(["systemctl", "daemon-reload"])
        return not service.exists()

    def restore_bans(self, store: AntiDPIStateStore) -> bool:
        now = time.time()
        with lock_state_file(store.path):
            data = store.load()
            banned = data.get("banned", {})
            if not isinstance(banned, dict):
                return False
            ok = True
            for raw, metadata in list(banned.items()):
                restored = self._restore_one(raw, metadata, now=now)
                if restored is None:
                    banned.pop(raw, None)
                else:
                    ok = restored and ok
            data["banned"] = banned
            store.save(data)
            return ok

    def _restore_one(
        self,
        raw: str,
        metadata: object,
        *,
        now: float,
    ) -> bool | None:
        try:
            address = ipaddress.ip_address(raw)
            mapping = metadata if isinstance(metadata, dict) else {}
            banned_at = float(mapping.get("at", 0))
            duration = ban_duration(metadata)
        except (ValueError, TypeError):
            return None
        permanent = _is_true(mapping.get("permanent"))
        remaining = 0 if permanent else _as_int(duration - max(0, now - banned_at))
        if not permanent and remaining <= 0:
            return None
        set_name = SET_V6 if address.version == 6 else SET_V4
        result = self.run(
            [
                "ipset",
                "add",
                set_name,
                address.compressed,
                "timeout",
                str(remaining),
                "-exist",
            ],
        )
        return getattr(result, "returncode", 1) == 0

    def write_service(self) -> None:
        self.paths.script.parent.mkdir(parents=True, exist_ok=True)
        wrapper = (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.path.insert(0, {str(self.paths.project_root)!r})\n"
            "from hydra.entrypoints.antidpi_agent import main\n"
            "main()\n"
        )
        self.paths.script.write_text(wrapper, encoding="utf-8")
        self.paths.script.chmod(0o755)
        self.paths.service.parent.mkdir(parents=True, exist_ok=True)
        self.paths.service.write_text(
            self._service_unit(),
            encoding="utf-8",
        )

    def _service_unit(self) -> str:
        return f"""[Unit]
Description=HYDRA Anti-DPI probe detector
After=network-online.target caddy-l4.service
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory={self.paths.project_root}
ExecStart={sys.executable} {self.paths.script}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
# iptables serializes host-wide updates through /run/xtables.lock.
ReadWritePaths=/var/lib/hydra /var/log/caddy-l4 /run
# AF_INET/AF_INET6 are required for outbound Telegram HTTPS notifications.
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
# The ipset match extension opens a netlink socket while iptables parses
# `-m set --match-set`.  With CAP_NET_ADMIN alone every -C and -I fails with
# "Can't open socket to ipset", so reconciliation reports a failure and a lost
# DROP rule could never be re-installed.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"""
