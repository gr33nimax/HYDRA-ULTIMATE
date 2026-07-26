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
)


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

            print(
                "  Авто-установка AmneziaWG "
                "(компиляция модуля, это долго)..."
            )
            environment = os.environ.copy()
            environment["AUTO_INSTALL"] = "y"
            environment["ENABLE_IPV6"] = "n"
            environment["SERVER_PUB_IP"] = self._public_ip()
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
        dkms = (
            HOST.run(["dkms", "status"], capture_output=True, text=True)
            if HOST.which("dkms")
            else None
        )
        other_kernels = []
        if dkms is not None and dkms.returncode == 0:
            for line in dkms.stdout.splitlines():
                if (
                    "amneziawg" in line
                    and ": installed" in line
                    and running_kernel not in line
                ):
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
        error = (
            result.stderr or result.stdout or "module is unavailable"
        ).strip()
        return False, (
            f"Модуль AmneziaWG недоступен для ядра {running_kernel}: {error}"
        )

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
