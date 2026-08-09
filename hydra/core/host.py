"""Injectable boundary for privileged host operations.

Production uses the local Linux host. Tests and future helper processes can
provide another backend without monkeypatching every plugin's subprocess call.
"""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import CompletedProcess, Popen
from typing import Any, Sequence

from hydra.utils import commands


@dataclass(frozen=True)
class HostPaths:
    systemd_dir: Path = field(default_factory=lambda: Path(
        os.environ.get("HYDRA_SYSTEMD_DIR", "/etc/systemd/system")
    ))
    iptables_rules: Path = field(default_factory=lambda: Path(
        os.environ.get("HYDRA_IPTABLES_RULES", "/etc/iptables/rules.v4")
    ))
    nftables_rules: Path = field(default_factory=lambda: Path(
        os.environ.get("HYDRA_NFTABLES_RULES", "/etc/nftables.conf")
    ))


@dataclass
class HostBackend:
    paths: HostPaths = field(default_factory=HostPaths)

    def run(self, args: Sequence[object], *, timeout: float = commands.DEFAULT_TIMEOUT,
            check: bool = False, text: bool = False,
            input: bytes | str | None = None,
            env: dict[str, str] | None = None, capture_output: bool = True,
            cwd: str | os.PathLike[str] | None = None,
            stdout=None, stderr=None, encoding: str | None = None,
            errors: str | None = None) -> CompletedProcess:
        options = {
            "timeout": timeout, "check": check, "text": text,
            "input": input, "env": env,
        }
        if not capture_output:
            options["capture_output"] = False
        for key, value in (
            ("cwd", cwd), ("stdout", stdout), ("stderr", stderr),
            ("encoding", encoding), ("errors", errors),
        ):
            if value is not None:
                options[key] = value
        return commands.run(args, **options)

    def popen(self, args: Sequence[object], *, timeout: float = commands.DEFAULT_TIMEOUT,
              **kwargs: Any) -> Popen:
        return commands.popen(args, timeout=timeout, **kwargs)

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

    def atomic_copy(
        self,
        source: Path,
        target: Path,
        *,
        mode: int | None = None,
    ) -> None:
        """Copy one verified artifact into place without exposing a partial file."""
        target.parent.mkdir(parents=True, exist_ok=True)
        pending = target.with_name(f".{target.name}.{os.getpid()}.pending")
        pending.unlink(missing_ok=True)
        try:
            shutil.copy2(source, pending)
            if mode is not None:
                pending.chmod(mode)
            pending.replace(target)
        finally:
            pending.unlink(missing_ok=True)

    def ensure_directory(self, path: Path, *, mode: int = 0o755) -> None:
        """Create a managed host directory and enforce its permissions."""
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(mode)

    @staticmethod
    def remove_file(path: Path, *, missing_ok: bool = True) -> None:
        """Remove one explicitly scoped managed file."""
        path.unlink(missing_ok=missing_ok)

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
