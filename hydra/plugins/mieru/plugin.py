"""
hydra/plugins/mieru/plugin.py — Mieru (mita): mTLS-туннель с random padding.

Контракт v2 — эталонный TRANSPORT-плагин:
  • configure() — чистая, генерит /etc/mita/server.json в памяти.
  • apply() — пишет конфиг, mita apply config, systemctl reload.
  • per-user: детерминированные креды из uuid через derive_key.
  • traffic → iptables accounting, connected_clients → mita status.
  • nft_tproxy_ports — трафик заворачивается в sing-box через TPROXY.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, User
from hydra.utils.crypto import derive_key
from hydra.utils.downloader import download_github_asset, verify_elf, extract_tarball
from hydra.utils.firewall import open_range, close_range
from hydra.utils.net import local_ip, public_ip, command_exists

MITA_BIN = Path("/usr/local/bin/mita")
MIERU_BIN = Path("/usr/local/bin/mieru")
CFG_DIR = Path("/etc/mita")
SERVER_CFG = CFG_DIR / "server.json"
SERVICE_FILE = Path("/etc/systemd/system/mita.service")
SERVICE_NAME = "mita"

DEFAULT_PORT_START = 2012
DEFAULT_PORT_END = 2022
DEFAULT_PROTOCOL = "TCP"

GITHUB_REPO = "enfein/mieru"


class MieruPlugin(BasePlugin):
    meta = PluginMeta(
        name="mieru",
        description="Mieru (mita): mTLS-туннель с random padding, без домена",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=False,
    )

    def __init__(self):
        self._pending_cfg: dict | None = None

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        if self._installed():
            return True

        print("  Определяю последнюю версию mieru...")
        from hydra.utils.downloader import latest_release
        version = latest_release(GITHUB_REPO)
        if version == "unknown":
            version = "3.33.0"

        if not self._install_mita_package(version):
            print("  Не удалось установить mita.")
            return False

        self._ensure_mita_user()
        self._ensure_time_sync()
        self._install_service()
        return self._installed()

    def uninstall(self) -> bool:
        subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
        subprocess.run(["systemctl", "disable", SERVICE_NAME], capture_output=True)
        if SERVICE_FILE.exists():
            SERVICE_FILE.unlink()
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "reset-failed"], capture_output=True)

        for b in (MITA_BIN, MIERU_BIN):
            if b.exists():
                b.unlink()
        if CFG_DIR.exists():
            import shutil as _sh
            _sh.rmtree(CFG_DIR, ignore_errors=True)

        close_range(DEFAULT_PROTOCOL.lower(), DEFAULT_PORT_START, DEFAULT_PORT_END)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: генерит server.json в памяти
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        port_start = DEFAULT_PORT_START
        port_end = DEFAULT_PORT_END
        protocol = DEFAULT_PROTOCOL

        users = []
        for user in state.users:
            if user.blocked:
                continue
            username = self._derive_username(user.uuid)
            password = self._derive_password(user.uuid)
            users.append({"name": username, "password": password})

        if not users:
            return ConfigFragment()

        if port_start == port_end:
            port_binding = {"port": port_start, "protocol": protocol}
        else:
            port_binding = {"portRange": f"{port_start}-{port_end}", "protocol": protocol}

        cfg = {
            "portBindings": [port_binding],
            "users": users,
            "loggingLevel": "INFO",
            "mtu": 1400,
        }

        self._pending_cfg = cfg
        return ConfigFragment(
            nft_tproxy_ports=[port_start],
        )

    def apply(self, state: AppState) -> bool:
        if not self._pending_cfg:
            return False

        CFG_DIR.mkdir(parents=True, exist_ok=True)
        SERVER_CFG.write_text(json.dumps(self._pending_cfg, indent=2))
        SERVER_CFG.chmod(0o600)

        err = self._apply_config()
        if err:
            print(f"  mita apply config error: {err}")
            return False

        subprocess.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
        time.sleep(2)
        return True

    def _apply_config(self) -> str | None:
        """mita apply config. Возвращает ошибку или None."""
        r = subprocess.run(
            [str(MITA_BIN), "apply", "config", str(SERVER_CFG)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return (r.stderr or r.stdout or "")[:300]
        return None

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("mieru", {})
        user.credentials["mieru"]["username"] = self._derive_username(user.uuid)
        user.credentials["mieru"]["password"] = self._derive_password(user.uuid)
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
        """Sing-box outbound JSON + полный конфиг для импорта."""
        username = self._derive_username(user.uuid)
        password = self._derive_password(user.uuid)
        server_ip = state.network.server_ip or public_ip()

        outbound = {
            "type": "mieru",
            "tag": f"mieru-{username}",
            "server": server_ip,
            "server_port": DEFAULT_PORT_START,
            "transport": DEFAULT_PROTOCOL,
            "username": username,
            "password": password,
            "multiplexing": "MULTIPLEXING_HIGH",
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
        """mierus:// ссылка для Karing."""
        username = self._derive_username(user.uuid)
        password = self._derive_password(user.uuid)
        server_ip = state.network.server_ip or public_ip()

        return (
            f"mierus://{username}:{password}@{server_ip}"
            f"?port={DEFAULT_PORT_START}&protocol={DEFAULT_PROTOCOL}"
            f"&profile=default&mtu=1400&multiplexing=MULTIPLEXING_HIGH"
        )

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
            enabled=SERVER_CFG.exists(),
            running=running,
            port=DEFAULT_PORT_START,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        """iptables accounting по username → email."""
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
                found = False
                for line in r.stdout.splitlines():
                    if username in line:
                        parts = line.split()
                        if len(parts) >= 2 and parts[0].isdigit():
                            result[email] = result.get(email, 0) + int(parts[0])
                            found = True
                if not found:
                    result.setdefault(email, 0)

        return result

    def connected_clients(self) -> list[dict]:
        """Пытается получить список клиентов из mita status."""
        if not self._installed():
            return []
        r = subprocess.run(
            [str(MITA_BIN), "status"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return []
        return [{"info": line.strip()} for line in r.stdout.splitlines() if line.strip()]

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
        return "u" + derive_key("mieru-user", uuid)[:8]

    @staticmethod
    def _derive_password(uuid: str) -> str:
        return derive_key("mieru-pass", uuid)

    @staticmethod
    def _installed() -> bool:
        return MITA_BIN.exists() or shutil.which("mita") is not None

    def _install_mita_package(self, version: str) -> bool:
        """Скачивает и устанавливает mita."""
        ver = version.lstrip("v")
        dest = Path("/tmp/mieru-install")
        dest.mkdir(parents=True, exist_ok=True)

        if command_exists("dpkg"):
            pattern = f"mita_{ver}_linux_amd64.deb"
            deb_dest = dest / f"mita_{ver}_amd64.deb"
            if download_github_asset(GITHUB_REPO, pattern, deb_dest):
                r = subprocess.run(
                    ["dpkg", "-i", str(deb_dest)],
                    capture_output=True, text=True,
                )
                if r.returncode == 0:
                    return True
                subprocess.run(["apt-get", "install", "-f", "-y"], capture_output=True)

        pattern = f"mita_{ver}_linux_amd64.tar.gz"
        tarball = dest / f"mita_{ver}.tar.gz"
        if not download_github_asset(GITHUB_REPO, pattern, tarball):
            return False

        extract_tarball(tarball, dest)
        candidate = dest / "mita"
        if candidate.exists():
            shutil.move(str(candidate), str(MITA_BIN))
            MITA_BIN.chmod(0o755)
            if verify_elf(MITA_BIN):
                return True
        return False

    @staticmethod
    def _ensure_mita_user() -> None:
        r = subprocess.run(["id", "mita"], capture_output=True)
        if r.returncode != 0:
            subprocess.run(
                ["useradd", "--system", "--no-create-home",
                 "--shell", "/usr/sbin/nologin", "mita"],
                capture_output=True,
            )

    @staticmethod
    def _ensure_time_sync() -> None:
        if shutil.which("chronyc") or shutil.which("ntpd"):
            return
        subprocess.run(["apt-get", "install", "-y", "chrony"], capture_output=True)
        subprocess.run(["systemctl", "enable", "--now", "chrony"], capture_output=True)

    def _install_service(self) -> None:
        SERVICE_FILE.write_text(
            "[Unit]\n"
            "Description=Mieru Proxy Server (mita)\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            f"ExecStart={MITA_BIN} run\n"
            "RuntimeDirectory=mita\n"
            "Restart=on-failure\n"
            "RestartSec=5\n"
            "NoNewPrivileges=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)
