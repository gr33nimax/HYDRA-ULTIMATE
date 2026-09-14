"""Installation and kernel readiness checks for AmneziaWG."""

from __future__ import annotations

import os
import platform
import shutil

from hydra.core.host import HOST

from .constants import (
    AWG_BIN,
    AWG_CONF_DIR,
    AWG_INSTALL_DIR,
    AWG_UNIT,
    AWG_UNIT_1,
    DEFAULT_SERVER_IPV4,
)
from .directives import AwgDirectiveError, canonical_mode


class AwgInstallationMixin:
    """Install/remove host assets and validate the running kernel module."""

    def install(self) -> bool:
        if self._installed():
            ready, detail = self._ensure_kernel_module()
            if not ready:
                print(f"  {detail}")
            return ready
        try:
            HOST.run(["rm", "-rf", str(AWG_INSTALL_DIR)], capture_output=True)
            clone = HOST.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "https://github.com/wiresock/amneziawg-install.git",
                    str(AWG_INSTALL_DIR),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if clone.returncode != 0:
                print(f"  git clone: {clone.stderr[:300]}")
                return False

            print("  Авто-установка AmneziaWG (компиляция модуля, это долго)...")
            environment = os.environ.copy()
            environment["AUTO_INSTALL"] = "y"
            environment["ENABLE_IPV6"] = "n"
            environment["SERVER_PUB_IP"] = self._public_ip()
            environment["SERVER_AWG_IPV4"] = DEFAULT_SERVER_IPV4
            HOST.run(
                ["bash", "amneziawg-install.sh"],
                cwd=str(AWG_INSTALL_DIR),
                env=environment,
                timeout=900,
            )
            ready, detail = self._ensure_kernel_module()
            if not ready:
                print(f"  {detail}")
                return False
            return self._installed()
        except Exception as exc:
            print(f"  install error: {exc}")
            return False

    def installer_identity(self) -> str:
        """Return the pinned managed installer revision without mutating it."""
        script = AWG_INSTALL_DIR / "amneziawg-install.sh"
        if not script.is_file() or not (AWG_INSTALL_DIR / ".git").exists():
            raise RuntimeError("managed AmneziaWG installer is unavailable")
        remote = HOST.run(
            ["git", "-C", str(AWG_INSTALL_DIR), "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        revision = HOST.run(
            ["git", "-C", str(AWG_INSTALL_DIR), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if remote.returncode != 0 or revision.returncode != 0 or "wiresock/amneziawg-install" not in remote.stdout:
            raise RuntimeError("managed AmneziaWG installer identity is invalid")
        return revision.stdout.strip()

    def _managed_installer(self) -> str:
        self.installer_identity()
        return str(AWG_INSTALL_DIR / "amneziawg-install.sh")

    def observed_protocol_mode(self) -> str:
        """Read the upstream protocol status without changing the host."""
        script = self._managed_installer()
        result = HOST.run(
            ["bash", script, "--protocol-status"],
            cwd=str(AWG_INSTALL_DIR),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError("failed to read AmneziaWG protocol status")
        try:
            return canonical_mode(result.stdout.strip(), from_upstream=True)
        except AwgDirectiveError as exc:
            raise RuntimeError("invalid protocol status from managed installer") from exc

    def migrate_protocol_mode(self, mode: object) -> None:
        """Invoke exactly one upstream capability-checked migration command."""
        command = {
            "2.0": "--disable-awg3",
            "3.0": "--enable-awg3",
            "3.1": "--enable-awg31",
        }[canonical_mode(mode)]
        script = self._managed_installer()
        result = HOST.run(
            ["bash", script, command],
            cwd=str(AWG_INSTALL_DIR),
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode != 0:
            raise RuntimeError("AmneziaWG protocol migration failed")

    def uninstall(self) -> bool:
        for unit in (AWG_UNIT, AWG_UNIT_1):
            HOST.run(["systemctl", "stop", unit], capture_output=True)
            HOST.run(["systemctl", "disable", unit], capture_output=True)
        HOST.run(
            [
                "apt-get",
                "purge",
                "-y",
                "-qq",
                "amneziawg",
                "amneziawg-tools",
                "amneziawg-dkms",
            ],
            capture_output=True,
        )
        HOST.run(["modprobe", "-r", "amneziawg"], capture_output=True)
        HOST.run(
            [
                "rm",
                "-rf",
                str(AWG_CONF_DIR),
                "/usr/bin/awg",
                "/usr/bin/awg-quick",
                "/usr/local/bin/awg",
                "/usr/local/bin/awg-quick",
                str(AWG_INSTALL_DIR),
            ],
            capture_output=True,
        )
        return True

    @staticmethod
    def _installed() -> bool:
        return AWG_BIN.exists() or shutil.which("awg") is not None

    @staticmethod
    def _ensure_kernel_module() -> tuple[bool, str]:
        loaded = HOST.run(["lsmod"], capture_output=True, text=True)
        if loaded.returncode == 0 and "amneziawg" in loaded.stdout:
            return True, ""
        result = HOST.run(
            ["modprobe", "amneziawg"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return True, ""

        running_kernel = platform.release()
        dkms = HOST.run(["dkms", "status"], capture_output=True, text=True) if HOST.which("dkms") else None
        other_kernels = []
        if dkms is not None and dkms.returncode == 0:
            for line in dkms.stdout.splitlines():
                if "amneziawg" in line and ": installed" in line and running_kernel not in line:
                    parts = [part.strip() for part in line.split(",")]
                    if len(parts) >= 2:
                        other_kernels.append(parts[1])
        if other_kernels:
            built = ", ".join(sorted(set(other_kernels)))
            return False, (
                f"Модуль AmneziaWG собран для ядра {built}, но сейчас "
                f"запущено {running_kernel}. Перезагрузите сервер и повторите "
                "включение."
            )
        error = (result.stderr or result.stdout or "module is unavailable").strip()
        return False, (f"Модуль AmneziaWG недоступен для ядра {running_kernel}: {error}")

    @staticmethod
    def _public_ip() -> str:
        result = HOST.run(
            [
                "curl",
                "-s",
                "-4",
                "--max-time",
                "5",
                "https://api.ipify.org",
            ],
            capture_output=True,
            text=True,
        )
        return result.stdout.strip() if result.returncode == 0 else "127.0.0.1"
