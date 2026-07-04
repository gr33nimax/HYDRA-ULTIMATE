"""
hydra/plugins/fail2ban/plugin.py — Fail2ban: защита от перебора.
"""
from __future__ import annotations

import subprocess
import re
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState

F2B_BIN = Path("/usr/bin/fail2ban-client")
JAIL_DIR = Path("/etc/fail2ban/jail.d")
F2B_LOG = Path("/var/log/fail2ban.log")


class Fail2banPlugin(BasePlugin):
    meta = PluginMeta(
        name="fail2ban",
        description="Fail2ban: защита от перебора паролей и сканирования портов",
        category=PluginCategory.SECURITY,
        version="2.0.0",
    )

    def install(self) -> bool:
        if self._installed():
            return True

        r = subprocess.run(
            ["bash", "-c", "apt-get update -qq && apt-get install -y -qq fail2ban"],
            capture_output=True, text=True, timeout=180,
        )
        if r.returncode != 0:
            return False

        self._write_jails()
        subprocess.run(["systemctl", "enable", "--now", "fail2ban"], capture_output=True)
        return True

    def uninstall(self) -> bool:
        subprocess.run(["systemctl", "stop", "fail2ban"], capture_output=True)
        subprocess.run(["systemctl", "disable", "fail2ban"], capture_output=True)
        subprocess.run(["apt-get", "remove", "-y", "-qq", "fail2ban"], capture_output=True, timeout=120)
        if JAIL_DIR.exists():
            (JAIL_DIR / "sshd.local").unlink(missing_ok=True)
            for f in JAIL_DIR.glob("hydra-*.local"):
                f.unlink(missing_ok=True)
        Path("/etc/fail2ban/filter.d/sing-box.conf").unlink(missing_ok=True)
        return True

    def _write_jails(self) -> None:
        JAIL_DIR.mkdir(parents=True, exist_ok=True)
        
        # Отключаем дефолтный системный sshd джейл, чтобы избежать дублирования
        try:
            path_disable = JAIL_DIR / "sshd.local"
            path_disable.write_text("[sshd]\nenabled = false\n", encoding="utf-8")
        except Exception:
            pass

        # Создаем фильтр для sing-box, если его нет
        try:
            filter_dir = Path("/etc/fail2ban/filter.d")
            filter_dir.mkdir(parents=True, exist_ok=True)
            filter_path = filter_dir / "sing-box.conf"
            filter_content = """[Definition]
failregex = (?:WARNING|ERROR).*inbound/.*(?:handshake failed|decryption failed|authentication failed|connection failed|rejected|invalid).*from \\[?(?:::ffff:)?<HOST>\\]?:\\d+
            inbound/.*(?:handshake failed|decryption failed|authentication failed|connection failed|rejected|invalid).*from \\[?(?:::ffff:)?<HOST>\\]?:\\d+
            inbound/.*from \\[?(?:::ffff:)?<HOST>\\]?:\\d+.*(?:handshake failed|decryption failed|authentication failed|connection failed|rejected|invalid)
ignoreregex =
"""
            filter_path.write_text(filter_content, encoding="utf-8")
        except Exception:
            pass

        jails = {
            "hydra-singbox": {
                "enabled": "true",
                "filter": "sing-box",
                "backend": "systemd",
                "journalmatch": "_SYSTEMD_UNIT=sing-box.service",
                "maxretry": "5",
                "bantime": "3600",
                "findtime": "600",
            },
            "hydra-sshd": {
                "enabled": "true",
                "filter": "sshd",
                "logpath": "/var/log/auth.log",
                "maxretry": "5",
                "bantime": "3600",
                "findtime": "600",
            },
        }
        for name, opts in jails.items():
            path = JAIL_DIR / f"{name}.local"
            parts = []
            for k, v in opts.items():
                parts.append(f"{k} = {v}")
            path.write_text(f"[{name}]\n" + "\n".join(parts) + "\n")

    def _installed(self) -> bool:
        return F2B_BIN.exists()

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def apply(self, state: AppState) -> bool:
        r = subprocess.run(["fail2ban-client", "reload"], capture_output=True, timeout=15)
        if r.returncode != 0:
            subprocess.run(["systemctl", "restart", "fail2ban"], capture_output=True, timeout=20)
        return self.status().running

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        banned = 0
        if installed:
            r = subprocess.run(["systemctl", "is-active", "fail2ban"], capture_output=True, text=True)
            running = r.stdout.strip() == "active"
            if running:
                r2 = subprocess.run(["fail2ban-client", "status"], capture_output=True, text=True, timeout=10)
                m = re.search(r"Jail list:\s*(.*)", r2.stdout)
                if m:
                    jails = [j.strip() for j in m.group(1).split(",") if j.strip()]
                    for j in jails:
                        r3 = subprocess.run(["fail2ban-client", "status", j], capture_output=True, text=True, timeout=10)
                        for line in r3.stdout.splitlines():
                            if "Currently banned" in line:
                                n = re.search(r":\s*(\d+)", line)
                                if n:
                                    banned += int(n.group(1))
        return PluginStatus(
            installed=installed,
            enabled=running,
            running=running,
            info={"banned_ips": banned},
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        subprocess.run(["systemctl", "start", "fail2ban"], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        subprocess.run(["systemctl", "stop", "fail2ban"], capture_output=True)
