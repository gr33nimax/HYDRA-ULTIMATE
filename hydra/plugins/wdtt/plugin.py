"""hydra/plugins/wdtt/plugin.py — qWDTT: WireGuard-over-VK-TURN туннель.

Контракт v2 — TRANSPORT-плагин:
  • configure() — генерит passwords.json в памяти (per-user из uuid).
  • apply() — пишет конфиг, перезапускает wdtt-server.
  • per-user: детерминированный пароль из uuid через derive_key.
  • client_link — qwdtt:// ссылка с VK-хешем из конфига.
  • Сборка бинарника из Go-исходников SpaceNeuroX/proxy-turn-vk-android.
  • nft_tproxy_ports=[56000] — DTLS-порт для nftables TPROXY.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, User
from hydra.utils.crypto import derive_key
from hydra.utils.net import public_ip

BIN_PATH = Path("/usr/local/bin/wdtt-server")
CONFIG_DIR = Path("/etc/wdtt")
CONFIG_FILE = CONFIG_DIR / "config.json"
PASSWORDS_FILE = CONFIG_DIR / "passwords.json"
SERVICE_FILE = Path("/etc/systemd/system/wdtt.service")
SERVICE_NAME = "wdtt"

DEFAULT_DTLS_PORT = 56000
DEFAULT_WG_PORT = 56001
DEFAULT_WG_SUBNET = "10.66.66.0/16"
LOCAL_TUN_PORT = 9000
SYSTEM_PASSWORD = "hydra-system-wdtt"

GITHUB_REPO = "SpaceNeuroX/proxy-turn-vk-android"
SOURCE_URL = f"https://github.com/{GITHUB_REPO}/archive/refs/heads/master.tar.gz"
GO_DL_URL = "https://go.dev/dl/"


class WdttPlugin(BasePlugin):
    meta = PluginMeta(
        name="wdtt",
        description="qWDTT: WireGuard-over-VK-TURN туннель через DTLS",
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

        print("  Сборка wdtt-server из исходников...")
        if not self._build_wdtt_server():
            print("  Не удалось собрать wdtt-server.")
            return False

        self._install_service(DEFAULT_DTLS_PORT, DEFAULT_WG_PORT)
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

        i = 0
        while i < 5:
            subprocess.run(
                ["iptables", "-t", "nat", "-D", "POSTROUTING",
                 "-s", "10.66.66.0/16", "!", "-d", "10.66.66.0/16",
                 "-j", "MASQUERADE"],
                capture_output=True,
            )
            i += 1

        if CONFIG_DIR.exists():
            shutil.rmtree(CONFIG_DIR, ignore_errors=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: генерит passwords.json в памяти
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        ps = state.protocols.get("wdtt")
        cfg = ps.config if ps and ps.config else {}

        dtls_port = cfg.get("dtls_port", DEFAULT_DTLS_PORT)
        wg_port = cfg.get("wg_port", DEFAULT_WG_PORT)

        passwords = {}
        for user in state.users:
            if user.blocked:
                continue
            password = self._derive_password(user.uuid)
            passwords[password] = {
                "device_ids": [],
                "max_devices": 5,
                "expires_at": 0,
                "down_bytes": 0,
                "up_bytes": 0,
                "vk_hash": "",
                "ports": "",
                "is_deactivated": False,
            }

        self._pending_cfg = {
            "dtls_port": dtls_port,
            "wg_port": wg_port,
            "passwords": passwords,
        }

        return ConfigFragment(
            nft_tproxy_ports=[dtls_port],
        )

    def apply(self, state: AppState) -> bool:
        if not self._pending_cfg:
            return False

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        dtls_port = self._pending_cfg["dtls_port"]
        wg_port = self._pending_cfg["wg_port"]
        passwords = self._pending_cfg["passwords"]

        pw_data = {
            "main_password": SYSTEM_PASSWORD,
            "admin_id": "",
            "bot_token": "",
            "passwords": passwords,
            "devices": {},
        }
        PASSWORDS_FILE.write_text(json.dumps(pw_data, indent=2))
        PASSWORDS_FILE.chmod(0o600)

        cfg = {"dtls_port": dtls_port, "wg_port": wg_port, "wg_subnet": DEFAULT_WG_SUBNET}
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
        CONFIG_FILE.chmod(0o600)

        self._install_service(dtls_port, wg_port)

        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        sysctl = Path("/etc/sysctl.d/99-wdtt.conf")
        sysctl.write_text("net.ipv4.ip_forward = 1\n")

        r = subprocess.run(
            ["iptables", "-t", "nat", "-C", "POSTROUTING",
             "-s", DEFAULT_WG_SUBNET, "!", "-d", DEFAULT_WG_SUBNET,
             "-j", "MASQUERADE"],
            capture_output=True,
        )
        if r.returncode != 0:
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING",
                 "-s", DEFAULT_WG_SUBNET, "!", "-d", DEFAULT_WG_SUBNET,
                 "-j", "MASQUERADE"],
                capture_output=True,
            )

        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
        time.sleep(2)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("wdtt", {})
        user.credentials["wdtt"]["password"] = self._derive_password(user.uuid)
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
        return json.dumps({"link": link, "protocol": "wdtt"})

    def client_link(self, user: User, state: AppState) -> str:
        ps = state.protocols.get("wdtt")
        cfg = ps.config if ps and ps.config else {}
        dtls_port = cfg.get("dtls_port", DEFAULT_DTLS_PORT)

        password = self._derive_password(user.uuid)
        server_ip = state.network.server_ip or public_ip()

        return (
            f"qwdtt://config?name=qWDTT-{server_ip}"
            f"&peer={server_ip}:{dtls_port}"
            f"&hashes=VK_HASH"
            f"&workers=16&port={LOCAL_TUN_PORT}"
            f"&pass={password}"
        )

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        port = DEFAULT_DTLS_PORT
        if installed:
            r = subprocess.run(
                ["systemctl", "is-active", SERVICE_NAME],
                capture_output=True, text=True,
            )
            running = r.stdout.strip() == "active"
            if CONFIG_FILE.exists():
                try:
                    cfg = json.loads(CONFIG_FILE.read_text())
                    port = cfg.get("dtls_port", DEFAULT_DTLS_PORT)
                except Exception:
                    pass

        return PluginStatus(
            installed=installed,
            enabled=SERVICE_FILE.exists(),
            running=running,
            port=port,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        if not self._installed():
            return {}
        return {}

    def connected_clients(self) -> list[dict]:
        if not self._installed():
            return []
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
    def _derive_password(uuid: str) -> str:
        return derive_key("wdtt-pass", uuid)

    @staticmethod
    def _installed() -> bool:
        return BIN_PATH.exists()

    @staticmethod
    def _install_service(dtls_port: int = DEFAULT_DTLS_PORT, wg_port: int = DEFAULT_WG_PORT) -> None:
        SERVICE_FILE.write_text(
            "[Unit]\n"
            "Description=qWDTT — WireGuard over VK TURN\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            f"ExecStart={BIN_PATH} "
            f"-config-dir {CONFIG_DIR} "
            f"-password {SYSTEM_PASSWORD} "
            f"-listen 0.0.0.0:{dtls_port} "
            f"-wg-port {wg_port}\n"
            "Restart=always\n"
            "RestartSec=5\n"
            "NoNewPrivileges=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)

    # ── Сборка wdtt-server из исходников Go ─────────────────────────────

    def _build_wdtt_server(self) -> bool:
        tmp = Path(tempfile.mkdtemp())
        try:
            archive = tmp / "master.tar.gz"
            print(f"  Скачиваю исходники qWDTT...")
            urllib.request.urlretrieve(SOURCE_URL, str(archive))

            print(f"  Распаковываю...")
            subprocess.run(
                ["tar", "-xzf", str(archive), "-C", str(tmp)],
                capture_output=True, check=True,
            )

            src_dirs = list(tmp.glob("proxy-turn-vk-android-*"))
            if not src_dirs:
                print(f"  Не найдена директория с исходниками.")
                return False
            src_dir = src_dirs[0]

            gomod = src_dir / "go.mod"
            required = self._go_required_version(gomod)
            go = self._ensure_go(required)
            if not go:
                print(f"  Не удалось установить Go {required}+.")
                return False

            print(f"  Разрешаю зависимости Go-модуля...")
            r = subprocess.run(
                [go, "mod", "tidy"],
                capture_output=True, text=True,
                cwd=str(src_dir),
                env={**self._go_env(), "GOSUMDB": "off"},
            )
            if r.returncode != 0:
                print(f"  go mod tidy: {(r.stderr or '')[:300]}")
                return False

            print(f"  Компилирую wdtt-server...")
            env = {**self._go_env(), "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": self._go_arch()}
            r = subprocess.run(
                [go, "build", "-o", str(tmp / "wdtt-server"),
                 "-ldflags", "-s -w", "./server.go"],
                capture_output=True, text=True,
                env=env, cwd=str(src_dir),
            )
            if r.returncode != 0:
                print(f"  Ошибка компиляции: {(r.stderr or '')[:300]}")
                return False

            built = tmp / "wdtt-server"
            if not built.exists():
                print(f"  Бинарник не создан.")
                return False

            BIN_PATH.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(built), str(BIN_PATH))
            BIN_PATH.chmod(0o755)
            print(f"  wdtt-server установлен: {BIN_PATH}")
            return True

        except Exception as e:
            print(f"  Ошибка: {e}")
            return False
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ── Утилиты Go ───────────────────────────────────────────────────────

    @staticmethod
    def _go_env() -> dict:
        e = dict(os.environ)
        e.setdefault("GOPATH", "/root/go")
        return e

    @staticmethod
    def _go_arch() -> str:
        m = platform.machine().lower()
        return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")

    @staticmethod
    def _go_required_version(gomod: Path) -> str:
        if gomod.exists():
            try:
                m = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", gomod.read_text(), re.M)
                if m:
                    return m.group(1)
            except Exception:
                pass
        return "1.21.0"

    def _check_go(self) -> str | None:
        go = "/usr/local/bin/go" if Path("/usr/local/bin/go").exists() else shutil.which("go")
        if go:
            r = subprocess.run([go, "version"], capture_output=True, text=True)
            if r.returncode == 0:
                return go
        return None

    def _go_installed_version(self, go: str) -> tuple:
        r = subprocess.run([go, "version"], capture_output=True, text=True)
        m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", r.stdout or "")
        if not m:
            return (0, 0, 0)
        parts = re.findall(r"\d+", m.group(1))[:3]
        parts += ["0"] * (3 - len(parts))
        return tuple(int(p) for p in parts)

    def _ensure_go(self, required: str) -> str | None:
        go = self._check_go()
        if go and self._go_installed_version(go) >= self._ver_tuple(required):
            return go
        print(f"  Нужен Go {required}+, устанавливаю...")
        return self._install_go_toolchain(required)

    @staticmethod
    def _ver_tuple(s: str) -> tuple:
        parts = re.findall(r"\d+", s)[:3]
        parts += ["0"] * (3 - len(parts))
        return tuple(int(p) for p in parts)

    def _install_go_toolchain(self, required: str) -> str | None:
        arch = self._go_arch()
        try:
            req = urllib.request.Request(
                "https://go.dev/VERSION?m=text",
                headers={"User-Agent": "HYDRA-WDTT"},
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                version = r.read().decode("utf-8", errors="replace").splitlines()[0].strip()
            if not version.startswith("go"):
                version = f"go{required}"
        except Exception:
            version = f"go{required}"

        url = f"{GO_DL_URL}{version}.linux-{arch}.tar.gz"
        tarball = Path(f"/tmp/{version}.linux-{arch}.tar.gz")
        print(f"  Скачиваю {version} ({arch})...")
        try:
            urllib.request.urlretrieve(url, str(tarball))
        except Exception as e:
            print(f"  Не удалось скачать Go: {e}")
            return None

        go_dir = Path("/usr/local/go")
        if go_dir.exists():
            subprocess.run(["rm", "-rf", str(go_dir)], capture_output=True)
        r = subprocess.run(
            ["tar", "-C", "/usr/local", "-xzf", str(tarball)],
            capture_output=True,
        )
        tarball.unlink(missing_ok=True)
        if r.returncode != 0:
            print(f"  Не удалось распаковать Go.")
            return None

        for exe in ("go", "gofmt"):
            src = go_dir / "bin" / exe
            dst = Path("/usr/local/bin") / exe
            if src.exists():
                try:
                    if dst.exists() or dst.is_symlink():
                        dst.unlink()
                    dst.symlink_to(src)
                except Exception:
                    pass

        return self._check_go()
