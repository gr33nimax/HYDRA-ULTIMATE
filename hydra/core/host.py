"""Injectable boundary for privileged host operations.

Production uses the local Linux host. Tests and future helper processes can
provide another backend without monkeypatching every plugin's subprocess call.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import CompletedProcess
from typing import Sequence

from hydra.utils import commands


@dataclass(frozen=True)
class HostPaths:
    systemd_dir: Path = field(default_factory=lambda: Path(
        os.environ.get("HYDRA_SYSTEMD_DIR", "/etc/systemd/system")
    ))
    iptables_rules: Path = field(default_factory=lambda: Path(
        os.environ.get("HYDRA_IPTABLES_RULES", "/etc/iptables/rules.v4")
    ))


@dataclass
class HostBackend:
    paths: HostPaths = field(default_factory=HostPaths)

    def run(self, args: Sequence[object], *, timeout: float = commands.DEFAULT_TIMEOUT,
            check: bool = False, text: bool = False) -> CompletedProcess:
        return commands.run(args, timeout=timeout, check=check, text=text)

    def which(self, executable: str) -> str | None:
        return shutil.which(executable)

    def atomic_write(self, path: Path, content: str | bytes, *, mode: int = 0o644) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        pending = path.with_name(f".{path.name}.{os.getpid()}.pending")
        if isinstance(content, bytes):
            pending.write_bytes(content)
        else:
            pending.write_text(content, encoding="utf-8")
        pending.chmod(mode)
        pending.replace(path)

    def systemd(self, action: str, unit: str, *, timeout: float = commands.DEFAULT_TIMEOUT) -> CompletedProcess:
        return self.run(["systemctl", action, unit], timeout=timeout)

    def persist_firewall(self) -> bool:
        if self.which("netfilter-persistent"):
            return self.run(["netfilter-persistent", "save"]).returncode == 0
        result = self.run(["iptables-save"], text=True)
        if result.returncode != 0 or not result.stdout:
            return False
        self.atomic_write(self.paths.iptables_rules, result.stdout, mode=0o600)
        return True


HOST = HostBackend()
