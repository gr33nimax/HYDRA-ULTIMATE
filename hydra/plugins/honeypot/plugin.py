"""
hydra/plugins/honeypot/plugin.py — Honeypot-порт: ловушка для сканеров.
"""
from __future__ import annotations

import json
import subprocess
import textwrap
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState

HONEYPOT_SCRIPT = Path("/usr/local/bin/hydra-honeypot.py")
HONEYPOT_SERVICE = Path("/etc/systemd/system/hydra-honeypot.service")
HONEYPOT_STATE = Path("/var/lib/hydra/honeypot.json")
HONEYPOT_LOG = Path("/var/log/hydra-honeypot.log")
HONEYPOT_PORT = 9999


class HoneypotPlugin(BasePlugin):
    meta = PluginMeta(
        name="honeypot",
        description="Honeypot: ловушка для сканеров портов с авто-баном через UFW",
        category=PluginCategory.SECURITY,
        version="2.0.0",
    )

    def install(self) -> bool:
        return True

    def uninstall(self) -> bool:
        self._remove_service()
        HONEYPOT_STATE.unlink(missing_ok=True)
        return True

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def apply(self, state: AppState) -> bool:
        return True

    def status(self) -> PluginStatus:
        r = subprocess.run(["systemctl", "is-active", "hydra-honeypot"], capture_output=True, text=True)
        active = r.stdout.strip() == "active"
        state = self._load_state()
        banned = len(state.get("banned", {}))
        return PluginStatus(
            installed=HONEYPOT_SCRIPT.exists(),
            enabled=active,
            running=active,
            port=state.get("port", HONEYPOT_PORT),
            info={"banned_ips": banned},
        )

    def _write_script(self, port: int, whitelist: list[str]) -> None:
        wl = repr(whitelist)
        script = textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import socket, subprocess, json, time
            from pathlib import Path
            from datetime import datetime

            PORT      = {port}
            WHITELIST = set({wl})
            LOG       = Path("{HONEYPOT_LOG}")
            STATE     = Path("{HONEYPOT_STATE}")
            LOG.parent.mkdir(parents=True, exist_ok=True)

            def log(msg):
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with LOG.open("a") as f:
                    f.write(f"[{{ts}}] {{msg}}\\n")

            def ban(ip):
                try:
                    r = subprocess.run(["ufw", "deny", "from", ip, "to", "any", "comment", "honeypot"],
                                       capture_output=True, timeout=10)
                    ok = r.returncode == 0
                except Exception:
                    ok = False
                log(f"BAN {{ip}} -- ufw={{'OK' if ok else 'FAIL'}}")
                if STATE.exists():
                    data = json.loads(STATE.read_text())
                else:
                    data = {{}}
                banned = data.setdefault("banned", {{}})
                if ip not in banned:
                    banned[ip] = {{"banned_at": datetime.now().isoformat(), "source": "honeypot"}}
                STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
                return ok

            srv = socket.socket(socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except Exception:
                pass
            srv.bind(("", PORT))
            srv.listen(64)
            srv.settimeout(5)
            log(f"Honeypot listening on port {{PORT}}")

            while True:
                try:
                    conn, addr = srv.accept()
                    ip = addr[0].replace("::ffff:", "")
                    conn.close()
                    if ip in WHITELIST:
                        log(f"SKIP {{ip}} (whitelist)")
                        continue
                    log(f"CONNECT {{ip}}:{{addr[1]}}")
                    ban(ip)
                except socket.timeout:
                    continue
                except Exception as e:
                    log(f"ERROR {{e}}")
                    time.sleep(1)
        """)
        HONEYPOT_SCRIPT.write_text(script)
        HONEYPOT_SCRIPT.chmod(0o755)

    def _install_service(self, port: int, whitelist: list[str]) -> bool:
        self._write_script(port, whitelist)
        svc = textwrap.dedent(f"""\
            [Unit]
            Description=Hydra Honeypot Port {port}
            After=network.target

            [Service]
            Type=simple
            ExecStart=/usr/bin/python3 {HONEYPOT_SCRIPT}
            Restart=always
            RestartSec=5
            User=root
            StandardOutput=journal
            StandardError=journal

            [Install]
            WantedBy=multi-user.target
        """)
        HONEYPOT_SERVICE.write_text(svc)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", "--now", "hydra-honeypot"], capture_output=True)
        return self.status().running

    def _remove_service(self) -> None:
        subprocess.run(["systemctl", "disable", "--now", "hydra-honeypot"], capture_output=True)
        HONEYPOT_SERVICE.unlink(missing_ok=True)
        HONEYPOT_SCRIPT.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

    def _load_state(self) -> dict:
        if HONEYPOT_STATE.exists():
            try:
                return json.loads(HONEYPOT_STATE.read_text())
            except Exception:
                pass
        return {"banned": {}, "port": HONEYPOT_PORT, "whitelist": ["127.0.0.1", "::1"]}

    def _save_state(self, data: dict) -> None:
        HONEYPOT_STATE.parent.mkdir(parents=True, exist_ok=True)
        HONEYPOT_STATE.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        HONEYPOT_STATE.chmod(0o600)

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        cfg = self._load_state()
        self._install_service(cfg.get("port", HONEYPOT_PORT), cfg.get("whitelist", ["127.0.0.1", "::1"]))

    def on_disable(self, state: AppState) -> None:
        self._remove_service()
