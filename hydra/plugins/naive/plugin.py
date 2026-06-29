"""hydra/plugins/naive/plugin.py — NaiveProxy: Caddy + forwardproxy, Chromium HTTP/2 fingerprint.

Контракт v2 — TRANSPORT-плагин с needs_domain=True:
  • configure() — генерит Caddyfile в памяти.
  • apply() — пишет Caddyfile, caddy validate + systemctl reload.
  • per-user: детерминированные username/password из uuid через derive_key.
  • traffic — iptables accounting (как mieru).
  • nft_tproxy_ports=[443] — трафик заворачивается в sing-box через TPROXY.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, User
from hydra.utils.crypto import derive_key
from hydra.utils.downloader import download_github_asset, verify_elf
from hydra.utils.net import public_ip

BIN_PATH = Path("/usr/local/bin/caddy-naive")
CFG_DIR = Path("/etc/caddy-naive")
CADDYFILE = CFG_DIR / "Caddyfile"
FAKE_SITE_DIR = Path("/var/www/naive-fake")
LOG_DIR = Path("/var/log/caddy-naive")
SERVICE_FILE = Path("/etc/systemd/system/caddy-naive.service")
SERVICE_NAME = "caddy-naive"

DEFAULT_PORT = 443

GITHUB_REPO = "Michaol/caddy-naive"


class NaivePlugin(BasePlugin):
    meta = PluginMeta(
        name="naive",
        description="NaiveProxy: Caddy + forwardproxy, Chromium HTTP/2 fingerprint",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=True,
    )

    def __init__(self):
        self._pending_cfg: str | None = None

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        if self._installed():
            return True

        print("  Скачиваю caddy-naive...")
        if not self._download_binary():
            print("  Не удалось установить caddy-naive.")
            return False

        self._create_fake_site()
        self._install_service()
        return self._installed()

    def uninstall(self) -> bool:
        subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
        subprocess.run(["systemctl", "disable", SERVICE_NAME], capture_output=True)
        if SERVICE_FILE.exists():
            SERVICE_FILE.unlink()
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "reset-failed"], capture_output=True)

        if BIN_PATH.exists():
            BIN_PATH.unlink()
        for d in (CFG_DIR, FAKE_SITE_DIR, LOG_DIR):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: генерит Caddyfile в памяти
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        domain = state.network.domain
        port = DEFAULT_PORT

        if not domain:
            self._pending_cfg = None
            return ConfigFragment()

        users = []
        for user in state.users:
            if user.blocked:
                continue
            username = self._derive_username(user.uuid)
            password = self._derive_password(user.uuid)
            users.append({"username": username, "password": password})

        ps = state.protocols.get("naive")
        probe_secret = (ps.config.get("probe_secret", "") if ps and ps.config else "")

        caddyfile = self._build_caddyfile(
            domain=domain,
            port=port,
            users=users,
            probe_secret=probe_secret,
        )

        self._pending_cfg = caddyfile
        return ConfigFragment(
            nft_tproxy_ports=[port],
        )

    def apply(self, state: AppState) -> bool:
        if not self._pending_cfg:
            return False

        CFG_DIR.mkdir(parents=True, exist_ok=True)
        CADDYFILE.write_text(self._pending_cfg)
        CADDYFILE.chmod(0o640)

        err = self._validate_caddy()
        if err:
            print(f"  Caddyfile validation error: {err}")
            return False

        subprocess.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
        time.sleep(2)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("naive", {})
        user.credentials["naive"]["username"] = self._derive_username(user.uuid)
        user.credentials["naive"]["password"] = self._derive_password(user.uuid)
        self.configure(state)
        self.apply(state)

    def on_user_remove(self, user: User, state: AppState) -> None:
        self.configure(state)
        self.apply(state)

    def on_user_block(self, user: User, state: AppState) -> None:
        self.configure(state)
        self.apply(state)

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентский конфиг
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        domain = state.network.domain
        if not domain:
            return ""
        username = self._derive_username(user.uuid)
        password = self._derive_password(user.uuid)
        port = DEFAULT_PORT

        outbound = {
            "type": "naive",
            "tag": f"naive-{username}",
            "server": domain,
            "server_port": port,
            "username": username,
            "password": password,
            "tls": {
                "enabled": True,
                "server_name": domain,
            },
        }

        full = {
            "log": {"level": "info"},
            "dns": {
                "servers": [
                    {"tag": "google", "address": "8.8.8.8"},
                    {"tag": "local", "address": "1.1.1.1", "detour": "direct"},
                ],
            },
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": outbound["tag"]},
        }
        return json.dumps(full, indent=2)

    def client_link(self, user: User, state: AppState) -> str:
        domain = state.network.domain
        if not domain:
            return ""
        username = self._derive_username(user.uuid)
        password = self._derive_password(user.uuid)
        port = DEFAULT_PORT

        user_q = urllib.parse.quote(username, safe="")
        pass_q = urllib.parse.quote(password, safe="")
        tag = urllib.parse.quote(username, safe="")
        return f"naive+https://{user_q}:{pass_q}@{domain}:{port}/#{tag}"

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        if installed:
            r = subprocess.run(
                ["systemctl", "is-active", SERVICE_NAME],
                capture_output=True, text=True,
            )
            running = r.stdout.strip() == "active"

        return PluginStatus(
            installed=installed,
            enabled=CADDYFILE.exists(),
            running=running,
            port=DEFAULT_PORT,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        """iptables accounting по username → email (как в mieru)."""
        if not self._installed():
            return {}

        username_to_email: dict[str, str] = {}
        for u in state.users:
            if u.blocked:
                continue
            uname = self._derive_username(u.uuid)
            username_to_email[uname] = u.email

        result: dict[str, int] = {}
        for username, email in username_to_email.items():
            for chain in ("INPUT", "OUTPUT"):
                r = subprocess.run(
                    ["iptables", "-t", "filter", "-L", chain, "-n", "-v", "-x"],
                    capture_output=True, text=True,
                )
                if r.returncode != 0:
                    continue
                for line in r.stdout.splitlines():
                    if username in line:
                        parts = line.split()
                        if len(parts) >= 2 and parts[0].isdigit():
                            result[email] = result.get(email, 0) + int(parts[0])
        return result

    def connected_clients(self) -> list[dict]:
        return []

    # ═════════════════════════════════════════════════════════════════════
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        self.configure(state)
        self.apply(state)
        r = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True, text=True,
        )
        if r.stdout.strip() != "active":
            subprocess.run(["systemctl", "enable", "--now", SERVICE_NAME], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _derive_username(uuid: str) -> str:
        return "u" + derive_key("naive-user", uuid)[:8]

    @staticmethod
    def _derive_password(uuid: str) -> str:
        return derive_key("naive-pass", uuid)

    @staticmethod
    def _installed() -> bool:
        return BIN_PATH.exists() or shutil.which("caddy-naive") is not None

    def _download_binary(self) -> bool:
        dest = Path("/tmp/caddy-naive-install")
        dest.mkdir(parents=True, exist_ok=True)
        binary = dest / "caddy-linux-amd64"

        if not download_github_asset(GITHUB_REPO, "caddy-linux-amd64", binary):
            return False

        if not verify_elf(binary):
            return False

        shutil.copy2(str(binary), str(BIN_PATH))
        BIN_PATH.chmod(0o755)
        return True

    @staticmethod
    def _create_fake_site() -> None:
        FAKE_SITE_DIR.mkdir(parents=True, exist_ok=True)
        (FAKE_SITE_DIR / "index.html").write_text(
            "<!DOCTYPE html><html><head><title>Welcome</title></head>"
            "<body><h1>Welcome</h1><p>This site is under maintenance.</p></body></html>\n"
        )

    @staticmethod
    def _install_service() -> None:
        SERVICE_FILE.write_text(
            "[Unit]\n"
            "Description=NaiveProxy (caddy-forwardproxy-naive)\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=notify\n"
            f"ExecStart={BIN_PATH} run "
            f"--config {CADDYFILE} --adapter caddyfile\n"
            "ExecReload=/bin/kill -USR1 $MAINPID\n"
            "Restart=on-failure\n"
            "RestartSec=5\n"
            "LimitNOFILE=1048576\n"
            f"ReadWritePaths={CFG_DIR} {LOG_DIR} {FAKE_SITE_DIR}\n"
            "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
            "NoNewPrivileges=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)

    def _build_caddyfile(
        self,
        domain: str,
        port: int,
        users: list[dict],
        probe_secret: str,
    ) -> str:
        auth_lines = ""
        for u in users:
            auth_lines += f"            basic_auth {u['username']} {u['password']}\n"

        probe_line = ""
        if probe_secret:
            probe_line = f"            probe_resistance {probe_secret}\n"

        return f"""\
{{
    http_port 0
    order forward_proxy before file_server
}}

:{port}, {domain}:{port} {{
    tls {{
        on_demand
    }}
    forward_proxy {{
{auth_lines}            hide_ip
            hide_via
{probe_line}    }}
    file_server {{
        root {FAKE_SITE_DIR}
    }}
    log {{
        output file {LOG_DIR}/access.log {{
            roll_size 10mb
            roll_keep 3
        }}
    }}
}}
"""

    def _validate_caddy(self) -> str | None:
        r = subprocess.run(
            [str(BIN_PATH), "validate",
             "--config", str(CADDYFILE), "--adapter", "caddyfile"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return (r.stderr or r.stdout or "")[:300]
        return None
