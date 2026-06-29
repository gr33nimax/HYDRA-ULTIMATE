"""hydra/plugins/telemt/plugin.py — Telemt MTProxy: Rust MTProto proxy с multi-user secret.

Контракт v2 — TRANSPORT-плагин:
  • configure() — генерит telemt.toml в памяти.
  • apply() — пишет конфиг, systemctl reload-or-restart.
  • per-user: детерминированный secret (32 hex) из uuid.
  • traffic — iptables accounting (как mieru).
  • nft_tproxy_ports=[8443].
"""
from __future__ import annotations

import hashlib
import json
import platform
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, User
from hydra.utils.crypto import derive_key
from hydra.utils.downloader import latest_release, verify_elf
from hydra.utils.net import public_ip

BIN_PATH = Path("/usr/local/bin/telemt")
CONFIG_DIR = Path("/etc/telemt")
CONFIG_FILE = CONFIG_DIR / "telemt.toml"
WORK_DIR = Path("/var/lib/telemt")
SERVICE_FILE = Path("/etc/systemd/system/telemt.service")
SERVICE_NAME = "telemt"

DEFAULT_PORT = 8443

GITHUB_REPO = "telemt/telemt"


class TelemtPlugin(BasePlugin):
    meta = PluginMeta(
        name="telemt",
        description="Telemt MTProxy: Rust MTProto proxy, multi-user secret",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=False,
    )

    def __init__(self):
        self._pending_cfg: str | None = None

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        if self._installed():
            return True

        print("  Скачиваю telemt...")
        if not self._download_binary():
            print("  Не удалось установить telemt.")
            return False

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
        for d in (CONFIG_DIR, WORK_DIR):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: генерит telemt.toml в памяти
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        port = DEFAULT_PORT
        domain = state.network.domain
        server_ip = state.network.server_ip or public_ip()

        has_ipv4 = True
        has_ipv6 = False
        if state.network.server_ip:
            if ":" in state.network.server_ip:
                has_ipv4 = False
                has_ipv6 = True

        users = {}
        for user in state.users:
            if user.blocked:
                continue
            username = self._derive_username(user.uuid)
            secret = self._derive_secret(user.uuid)
            users[username] = secret

        toml = self._build_toml(
            port=port,
            ipv4=has_ipv4,
            ipv6=has_ipv6,
            tls_domain=domain,
            users=users,
        )

        self._pending_cfg = toml
        return ConfigFragment(
            nft_tproxy_ports=[port],
        )

    def apply(self, state: AppState) -> bool:
        if not self._pending_cfg:
            return False

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(self._pending_cfg)
        CONFIG_FILE.chmod(0o640)

        subprocess.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
        time.sleep(2)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("telemt", {})
        user.credentials["telemt"]["username"] = self._derive_username(user.uuid)
        user.credentials["telemt"]["secret"] = self._derive_secret(user.uuid)
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
        link = self.client_link(user, state)
        if not link:
            return ""
        return json.dumps({"link": link, "protocol": "telemt"})

    def client_link(self, user: User, state: AppState) -> str:
        secret = self._derive_secret(user.uuid)
        server_ip = state.network.server_ip or public_ip()
        port = DEFAULT_PORT
        domain = state.network.domain
        tls_secret = self._make_tls_secret(secret, domain) if domain else secret
        return f"tg://proxy?server={server_ip}&port={port}&secret={tls_secret}"

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
            enabled=CONFIG_FILE.exists(),
            running=running,
            port=DEFAULT_PORT,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
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
        return "u" + derive_key("telemt-user", uuid)[:8]

    @staticmethod
    def _derive_secret(uuid: str) -> str:
        """32 hex-символа (MTProto secret, 16 байт), детерминирован от uuid."""
        return hashlib.sha256(f"telemt-secret|{uuid}".encode()).hexdigest()[:32]

    @staticmethod
    def _make_tls_secret(base_secret: str, domain: str) -> str:
        """Секрет с TLS: ee{hex_secret}{domain_hex}."""
        return f"ee{base_secret}{domain.encode().hex()}"

    @staticmethod
    def _installed() -> bool:
        return BIN_PATH.exists() or shutil.which("telemt") is not None

    def _download_binary(self) -> bool:
        arch = "aarch64" if platform.machine().lower() in ("aarch64", "arm64") else "x86_64"
        libc = "gnu"
        asset_pattern = f"telemt-{arch}-linux-{libc}.tar.gz"

        dest = Path("/tmp/telemt-install")
        dest.mkdir(parents=True, exist_ok=True)
        archive = dest / asset_pattern

        if not latest_release(GITHUB_REPO) == "unknown":
            if not self._download_and_extract(asset_pattern, dest, archive):
                return False
        else:
            return False

        return True

    def _download_and_extract(self, asset_pattern: str, dest: Path, archive: Path) -> bool:
        from hydra.utils.downloader import download_github_asset

        if not download_github_asset(GITHUB_REPO, asset_pattern, archive):
            print(f"  Не удалось скачать {asset_pattern}")
            return False

        extract_dir = dest / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)

        try:
            with tarfile.open(str(archive), "r:gz") as tf:
                tf.extractall(path=str(extract_dir))

            found = list(extract_dir.rglob("telemt"))
            if not found:
                print("  Бинарник telemt не найден в архиве")
                return False

            shutil.copy2(str(found[0]), str(BIN_PATH))
            BIN_PATH.chmod(0o755)

            if not verify_elf(BIN_PATH):
                print("  Скачанный файл не является ELF-бинарником")
                return False

            print(f"  telemt установлен: {BIN_PATH}")
            return True
        except Exception as e:
            print(f"  Ошибка распаковки: {e}")
            return False

    @staticmethod
    def _install_service() -> None:
        SERVICE_FILE.write_text(
            "[Unit]\n"
            "Description=Telemt MTProxy Server\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            "User=root\n"
            f"WorkingDirectory={WORK_DIR}\n"
            f"ExecStart={BIN_PATH} {CONFIG_FILE}\n"
            "ExecReload=/bin/kill -HUP $MAINPID\n"
            "Restart=on-failure\n"
            "RestartSec=10\n"
            "LimitNOFILE=1048576\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)

    def _build_toml(
        self,
        port: int,
        ipv4: bool,
        ipv6: bool,
        tls_domain: str,
        users: dict[str, str],
    ) -> str:
        net_prefer = 6 if (ipv6 and not ipv4) else 4
        arr = ", ".join(f'"{u}"' for u in users)

        lines = [
            "[general]",
            "prefer_ipv6 = false",
            "fast_mode = true",
            "use_middle_proxy = false",
            "",
            "[network]",
            f"ipv4 = {str(ipv4).lower()}",
            f"ipv6 = {str(ipv6).lower()}",
            f"prefer = {net_prefer}",
            "",
            "[general.modes]",
            "classic = false",
            "secure = false",
            "tls = true",
            "",
            "[general.links]",
            f"show = [{arr}]",
            "",
            "[server]",
            f"port = {port}",
            "",
        ]

        if ipv4:
            lines += ['[[server.listeners]]', 'ip = "0.0.0.0"', ""]
        if ipv6:
            lines += ['[[server.listeners]]', 'ip = "::"', ""]

        lines += [
            "[timeouts]",
            "client_handshake = 300",
            "client_keepalive = 60",
            "client_ack = 300",
            "",
            "[censorship]",
            f'tls_domain = "{tls_domain}"',
            "mask = true",
            "mask_port = 443",
            "fake_cert_len = 2048",
            "",
            "[access]",
            "replay_check_len = 65536",
            "ignore_time_skew = false",
            "",
            "[access.users]",
        ]

        for name, secret in users.items():
            lines.append(f'{name} = "{secret}"')

        lines += [
            "",
            "[[upstreams]]",
            'type = "direct"',
            "enabled = true",
            "weight = 10",
        ]

        return "\n".join(lines) + "\n"
