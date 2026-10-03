"""Injectable boundary for privileged host operations.

Production uses the local Linux host. Tests and future helper processes can
provide another backend without monkeypatching every plugin's subprocess call.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import CompletedProcess, Popen
from typing import Any, Sequence

from hydra.utils import commands


@dataclass(frozen=True)
class HostPaths:
    systemd_dir: Path = field(default_factory=lambda: Path(os.environ.get("HYDRA_SYSTEMD_DIR", "/etc/systemd/system")))
    iptables_rules: Path = field(
        default_factory=lambda: Path(os.environ.get("HYDRA_IPTABLES_RULES", "/etc/iptables/rules.v4"))
    )
    nftables_rules: Path = field(
        default_factory=lambda: Path(os.environ.get("HYDRA_NFTABLES_RULES", "/etc/nftables.conf"))
    )


@dataclass
class HostBackend:
    paths: HostPaths = field(default_factory=HostPaths)

    def run(
        self,
        args: Sequence[object],
        *,
        timeout: float = commands.DEFAULT_TIMEOUT,
        check: bool = False,
        text: bool = False,
        input: bytes | str | None = None,
        env: dict[str, str] | None = None,
        capture_output: bool = True,
        cwd: str | os.PathLike[str] | None = None,
        stdout=None,
        stderr=None,
        encoding: str | None = None,
        errors: str | None = None,
    ) -> CompletedProcess:
        options = {
            "timeout": timeout,
            "check": check,
            "text": text,
            "input": input,
            "env": env,
        }
        if not capture_output:
            options["capture_output"] = False
        for key, value in (
            ("cwd", cwd),
            ("stdout", stdout),
            ("stderr", stderr),
            ("encoding", encoding),
            ("errors", errors),
        ):
            if value is not None:
                options[key] = value
        return commands.run(args, **options)

    def popen(self, args: Sequence[object], *, timeout: float = commands.DEFAULT_TIMEOUT, **kwargs: Any) -> Popen:
        return commands.popen(args, timeout=timeout, **kwargs)

    def which(self, executable: str) -> str | None:
        return shutil.which(executable)

    def read_bytes(self, path: Path, *, max_bytes: int) -> bytes:
        """Read one bounded regular file without following a final symlink."""
        if type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
                raise ValueError("host file is not regular or exceeds its size limit")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(65536, max_bytes + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError("host file exceeds its size limit")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def atomic_write(
        self,
        path: Path,
        content: str | bytes,
        *,
        mode: int = 0o644,
        durable: bool = False,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        pending = path.with_name(f".{path.name}.{os.getpid()}.pending")
        if isinstance(content, bytes):
            pending.write_bytes(content)
        else:
            pending.write_text(content, encoding="utf-8")
        pending.chmod(mode)
        if durable:
            with pending.open("r+b") as handle:
                handle.flush()
                os.fsync(handle.fileno())
        pending.replace(path)
        if durable and os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    def atomic_create(
        self,
        path: Path,
        content: str | bytes,
        *,
        mode: int = 0o600,
        durable: bool = False,
    ) -> bool:
        """Durably create one file without replacing a concurrent winner."""
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, pending_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".pending",
            dir=path.parent,
        )
        pending = Path(pending_name)
        try:
            pending.chmod(mode)
            payload = content.encode("utf-8") if isinstance(content, str) else content
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("atomic file creation made no write progress")
                view = view[written:]
            if durable:
                os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            try:
                os.link(pending, path)
            except FileExistsError:
                return False
            if durable and os.name != "nt":
                directory_fd = os.open(
                    path.parent,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            return True
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            pending.unlink(missing_ok=True)

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
