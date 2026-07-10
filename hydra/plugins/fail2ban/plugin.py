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

        self._write_jails(None)
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
        filter_dir = Path("/etc/fail2ban/filter.d")
        for name in ("hydra-anytls", "hydra-mieru", "hydra-trusttunnel", "hydra-naive", "hydra-awg", "hydra-portscan"):
            (filter_dir / f"{name}.conf").unlink(missing_ok=True)
        (filter_dir / "sing-box.conf").unlink(missing_ok=True)
        (filter_dir / "awg-invalid.conf").unlink(missing_ok=True)
        return True

    def _write_jails(self, state: AppState | None = None) -> None:
        JAIL_DIR.mkdir(parents=True, exist_ok=True)
        filter_dir = Path("/etc/fail2ban/filter.d")
        filter_dir.mkdir(parents=True, exist_ok=True)

        # Миграция: удаляем устаревшие файлы от старого формата
        old_files = [
            JAIL_DIR / "hydra-singbox.local",
            JAIL_DIR / "hydra-awg.local",
            filter_dir / "sing-box.conf",
            filter_dir / "awg-invalid.conf",
        ]
        for f in old_files:
            try:
                f.unlink(missing_ok=True)
            except Exception:
                pass
        
        # Отключаем дефолтный системный sshd джейл, чтобы избежать дублирования
        try:
            path_disable = JAIL_DIR / "sshd.local"
            path_disable.write_text("[sshd]\nenabled = false\n", encoding="utf-8")
        except Exception:
            pass

        # Создаем фильтры для всех протоколов
        filters = {
            "hydra-anytls": r"""[Definition]
failregex = inbound/anytls\[.*\]:\s+process connection from \[?(?:::ffff:)?<HOST>\]?:\d+:\s+.*
ignoreregex =
""",
            "hydra-mieru": r"""[Definition]
failregex = inbound/mieru\[.*\]:\s+process connection from \[?(?:::ffff:)?<HOST>\]?:\d+:\s+.*
ignoreregex =
""",
            "hydra-trusttunnel": r"""[Definition]
failregex = inbound/trusttunnel\[.*\]:\s+process connection from \[?(?:::ffff:)?<HOST>\]?:\d+:\s+.*
ignoreregex =
""",
            "hydra-naive": r"""[Definition]
failregex = "remote_ip":\s*"<HOST>".*"status":\s*(?:407|401|403)
            "status":\s*(?:407|401|403).*"remote_ip":\s*"<HOST>"
ignoreregex =
""",
            "hydra-awg": r"""[Definition]
failregex = amneziawg.*Invalid.*from <HOST>
            amneziawg.*Handshake.*failed.*<HOST>
            wireguard.*Invalid.*from <HOST>
ignoreregex =
""",
            "hydra-portscan": r"""[Definition]
failregex = HYDRA-PORTSCAN.*SRC=<HOST>
ignoreregex =
"""
        }

        for fname, fcontent in filters.items():
            try:
                (filter_dir / f"{fname}.conf").write_text(fcontent, encoding="utf-8")
            except Exception:
                pass

        def is_proto_enabled(proto_name: str) -> bool:
            if not state:
                return True
            p = state.protocols.get(proto_name)
            return p.enabled if p else False

        jails = {
            "hydra-anytls": {
                "enabled": "true" if is_proto_enabled("anytls") else "false",
                "filter": "hydra-anytls",
                "backend": "systemd",
                "journalmatch": "_SYSTEMD_UNIT=sing-box.service",
                "maxretry": "3",
                "bantime": "3600",
                "findtime": "300",
            },
            "hydra-mieru": {
                "enabled": "true" if is_proto_enabled("mieru") else "false",
                "filter": "hydra-mieru",
                "backend": "systemd",
                "journalmatch": "_SYSTEMD_UNIT=sing-box.service",
                "maxretry": "3",
                "bantime": "3600",
                "findtime": "300",
            },
            "hydra-trusttunnel": {
                "enabled": "true" if is_proto_enabled("trusttunnel") else "false",
                "filter": "hydra-trusttunnel",
                "backend": "systemd",
                "journalmatch": "_SYSTEMD_UNIT=sing-box.service",
                "maxretry": "3",
                "bantime": "3600",
                "findtime": "300",
            },
            "hydra-naive": {
                "enabled": "true" if is_proto_enabled("naive") else "false",
                "filter": "hydra-naive",
                "backend": "auto",
                "logpath": "/var/log/caddy-naive/access.log",
                "maxretry": "5",
                "bantime": "7200",
                "findtime": "300",
            },
            "hydra-sshd": {
                "enabled": "true",
                "filter": "sshd",
                "backend": "systemd",
                "maxretry": "5",
                "bantime": "3600",
                "findtime": "600",
            },
            "hydra-recidive": {
                "enabled": "true",
                "filter": "recidive",
                "logpath": "/var/log/fail2ban.log",
                "maxretry": "3",
                "findtime": "86400",
                "bantime": "604800",
                "banaction": "iptables-allports",
            },
            "hydra-portscan": {
                "enabled": "false",
                "filter": "hydra-portscan",
                "backend": "systemd",
                "journalmatch": "_TRANSPORT=kernel",
                "maxretry": "15",
                "findtime": "120",
                "bantime": "3600",
                "banaction": "iptables-allports",
            }
        }

        # Опциональный джейл для AWG kernel log
        import shutil
        awg_installed = Path("/usr/bin/awg").exists() or shutil.which("awg") is not None
        awg_enabled = awg_installed
        if state:
            p = state.protocols.get("amneziawg")
            if p:
                awg_enabled = awg_enabled and p.enabled

        if awg_installed:
            jails["hydra-awg"] = {
                "enabled": "true" if awg_enabled else "false",
                "filter": "hydra-awg",
                "backend": "systemd",
                "journalmatch": "_TRANSPORT=kernel",
                "maxretry": "5",
                "bantime": "1800",
                "findtime": "300",
            }

        for name, opts in jails.items():
            try:
                path = JAIL_DIR / f"{name}.local"
                parts = []
                for k, v in opts.items():
                    parts.append(f"{k} = {v}")
                path.write_text(f"[{name}]\n" + "\n".join(parts) + "\n", encoding="utf-8")
            except Exception:
                pass

    def _installed(self) -> bool:
        return F2B_BIN.exists()

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def apply(self, state: AppState) -> bool:
        if not self._installed():
            return False
        self._write_jails(state)
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
