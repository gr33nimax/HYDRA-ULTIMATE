"""hydra/plugins/wdtt/plugin.py — qWDTT: WireGuard-over-VK-TURN туннель.

Контракт v2 — TRANSPORT-плагин:
  • configure() — подготавливает настройки на основе файлов и AppState.
  • apply() — пишет конфиг, настраивает брандмауэр и NAT, перезапускает wdtt-server.
  • Независим от пользователей state.json.
  • Сборка бинарника из Go-исходников SpaceNeuroX/proxy-turn-vk-android.
"""
from __future__ import annotations

from hydra.core.host import HOST

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
from hydra.core.state import AppState, User, load_state, get_protocol
from hydra.utils import firewall

BIN_PATH = Path("/usr/local/bin/wdtt-server")
CONFIG_DIR = Path("/etc/wdtt")
CONFIG_FILE = CONFIG_DIR / "config.json"
PASSWORDS_FILE = CONFIG_DIR / "passwords.json"
SERVICE_FILE = Path("/etc/systemd/system/wdtt.service")
SERVICE_NAME = "wdtt"

DEFAULT_DTLS_PORT = 56000
DEFAULT_WG_PORT = 56001
DEFAULT_WG_SUBNET = "10.66.66.0/16"
WG_INTERFACE = "wdtt0"
WG_STATS_DIR = Path(f"/sys/class/net/{WG_INTERFACE}/statistics")
LOCAL_TUN_PORT = 9000
SYSTEM_PASSWORD = "hydra-system-wdtt"

GITHUB_REPO = "SpaceNeuroX/proxy-turn-vk-android"
SOURCE_URL = f"https://github.com/{GITHUB_REPO}/archive/refs/heads/master.tar.gz"
GO_DL_URL = "https://go.dev/dl/"

SOURCE_EXTRACT_TIMEOUT = 120
GO_MODULE_TIMEOUT = 600
GO_BUILD_TIMEOUT = 900


class WdttPlugin(BasePlugin):
    meta = PluginMeta(
        name="wdtt",
        description="qWDTT: WireGuard-over-VK-TURN туннель через DTLS",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=False,
        central_apply=False,
        required_commands=("systemctl", "iptables"),
    )

    def __init__(self):
        self._pending_cfg: dict | None = None

    # ═════════════════════════════════════════════════════════════════════
    #  Синхронизация с файловой системой
    # ═════════════════════════════════════════════════════════════════════

    def sync_fs_to_state(self, state: AppState) -> None:
        """Синхронизирует конфигурацию и статус из файлов на диске в AppState."""
        ps = get_protocol(state, self.meta.name)
        
        fs_installed = self._installed()
        if fs_installed and not ps.installed:
            ps.installed = True
            
        if fs_installed:
            r = HOST.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True)
            is_active = r.stdout.strip() == "active"
            ps.enabled = is_active

        if CONFIG_FILE.exists():
            try:
                cfg_data = json.loads(CONFIG_FILE.read_text())
                ps.config["dtls_port"] = cfg_data.get("dtls_port", DEFAULT_DTLS_PORT)
                ps.config["wg_port"] = cfg_data.get("wg_port", DEFAULT_WG_PORT)
            except Exception:
                pass

        if PASSWORDS_FILE.exists():
            try:
                pw_data = json.loads(PASSWORDS_FILE.read_text())
                ps.config["main_password"] = pw_data.get("main_password", SYSTEM_PASSWORD)
                ps.config["admin_id"] = pw_data.get("admin_id", "")
                ps.config["bot_token"] = pw_data.get("bot_token", "")
            except Exception:
                pass

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

        # Загружаем настройки для корректного создания сервиса
        state = load_state()
        ps = get_protocol(state, self.meta.name)
        dtls_port = ps.config.get("dtls_port", DEFAULT_DTLS_PORT)
        wg_port = ps.config.get("wg_port", DEFAULT_WG_PORT)
        main_password = ps.config.get("main_password", SYSTEM_PASSWORD)
        admin_id = ps.config.get("admin_id", "")
        bot_token = ps.config.get("bot_token", "")

        self._install_service(dtls_port, wg_port, main_password, admin_id, bot_token)
        return self._installed()

    def uninstall(self) -> bool:
        # Получаем порт для удаления правил файрвола
        state = load_state()
        ps = get_protocol(state, self.meta.name)
        dtls_port = ps.config.get("dtls_port", DEFAULT_DTLS_PORT)

        HOST.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
        HOST.run(["systemctl", "disable", SERVICE_NAME], capture_output=True)
        if SERVICE_FILE.exists():
            SERVICE_FILE.unlink()
        HOST.run(["systemctl", "daemon-reload"], capture_output=True)
        HOST.run(["systemctl", "reset-failed"], capture_output=True)

        if BIN_PATH.exists():
            BIN_PATH.unlink()

        self._fw_close_udp(dtls_port)
        self._remove_masquerade()

        sysctl = Path("/etc/sysctl.d/99-wdtt.conf")
        if sysctl.exists():
            sysctl.unlink()

        if CONFIG_DIR.exists():
            shutil.rmtree(CONFIG_DIR, ignore_errors=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: генерит passwords.json на основе файлов
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        self.sync_fs_to_state(state)
        
        ps = get_protocol(state, self.meta.name)
        cfg = ps.config if ps and ps.config else {}

        dtls_port = cfg.get("dtls_port", DEFAULT_DTLS_PORT)
        wg_port = cfg.get("wg_port", DEFAULT_WG_PORT)

        existing_data = {}
        if PASSWORDS_FILE.exists():
            try:
                existing_data = json.loads(PASSWORDS_FILE.read_text())
            except Exception:
                pass

        main_password = cfg.get("main_password", existing_data.get("main_password", SYSTEM_PASSWORD))
        admin_id = cfg.get("admin_id", existing_data.get("admin_id", ""))
        bot_token = cfg.get("bot_token", existing_data.get("bot_token", ""))
        passwords = existing_data.get("passwords", {})
        devices = existing_data.get("devices", {})

        self._pending_cfg = {
            "dtls_port": dtls_port,
            "wg_port": wg_port,
            "main_password": main_password,
            "admin_id": admin_id,
            "bot_token": bot_token,
            "passwords": passwords,
            "devices": devices,
        }

        # wdtt-server поднимает userspace WireGuard-интерфейс wdtt0. Подключаем
        # его к тому же TPROXY/Sing-Box pipeline, который используют остальные
        # туннельные транспорты: так общие DNS/route-правила и WARP применяются
        # к qWDTT без отдельного набора policy-routing правил.
        return ConfigFragment(nft_tproxy_ifaces=[WG_INTERFACE])

    def apply(self, state: AppState) -> bool:
        if not self._pending_cfg:
            return False

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)

        dtls_port = self._pending_cfg["dtls_port"]
        wg_port = self._pending_cfg["wg_port"]
        main_password = self._pending_cfg["main_password"]
        admin_id = self._pending_cfg["admin_id"]
        bot_token = self._pending_cfg["bot_token"]
        passwords = self._pending_cfg["passwords"]
        devices = self._pending_cfg["devices"]

        pw_data = {
            "main_password": main_password,
            "admin_id": admin_id,
            "bot_token": bot_token,
            "passwords": passwords,
            "devices": devices,
        }
        PASSWORDS_FILE.write_text(json.dumps(pw_data, indent=2, ensure_ascii=False))
        PASSWORDS_FILE.chmod(0o600)

        cfg = {"dtls_port": dtls_port, "wg_port": wg_port, "wg_subnet": DEFAULT_WG_SUBNET}
        CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
        CONFIG_FILE.chmod(0o600)

        self._install_service(dtls_port, wg_port, main_password, admin_id, bot_token)

        # IP Forwarding
        HOST.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
        sysctl = Path("/etc/sysctl.d/99-wdtt.conf")
        sysctl.write_text("net.ipv4.ip_forward = 1\n")

        # Настройка Firewall (открытие UDP порта) и MASQUERADE
        self._fw_open_udp(dtls_port)
        self._add_masquerade()

        HOST.run(["systemctl", "daemon-reload"], capture_output=True)
        HOST.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
        time.sleep(2)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы (не используются для wdtt)
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        pass

    def on_user_remove(self, user: User, state: AppState) -> None:
        pass

    def on_user_block(self, user: User, state: AppState) -> None:
        pass

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентский конфиг (не используются для wdtt)
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        return ""

    def client_link(self, user: User, state: AppState) -> str:
        return ""

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        port = DEFAULT_DTLS_PORT
        if installed:
            r = HOST.run(
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
        return {}

    def total_traffic(self, state: AppState | None = None) -> int | None:
        """Возвращает общий RX+TX интерфейса без ложной per-user атрибуции."""
        try:
            rx = int((WG_STATS_DIR / "rx_bytes").read_text().strip())
            tx = int((WG_STATS_DIR / "tx_bytes").read_text().strip())
            return max(0, rx) + max(0, tx)
        except (OSError, TypeError, ValueError):
            # None означает «источник временно недоступен». Ноль здесь нельзя
            # возвращать: краткий сбой чтения выглядел бы как сброс интерфейса
            # и привёл бы к повторному начислению всего текущего счётчика.
            return None

    def connected_clients(self) -> list[dict]:
        return []

    # ═════════════════════════════════════════════════════════════════════
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        self.configure(state)
        self.apply(state)
        r = HOST.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True, text=True,
        )
        if r.stdout.strip() != "active":
            HOST.run(["systemctl", "enable", "--now", SERVICE_NAME], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        HOST.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _derive_password(uuid: str) -> str:
        from hydra.utils.crypto import derive_key
        return derive_key("wdtt-pass", uuid)

    @staticmethod
    def _installed() -> bool:
        return BIN_PATH.exists() and SERVICE_FILE.exists()

    @staticmethod
    def _install_service(dtls_port: int = DEFAULT_DTLS_PORT, wg_port: int = DEFAULT_WG_PORT,
                         main_password: str = SYSTEM_PASSWORD, admin_id: str = "", bot_token: str = "") -> None:
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
            f"-password {main_password} "
            f"-listen 0.0.0.0:{dtls_port} "
            f"-wg-port {wg_port} "
            + (f"-admin {admin_id} " if admin_id else "")
            + (f"-bot-token {bot_token} " if bot_token else "")
            + "\n"
            "Restart=always\n"
            "RestartSec=5\n"
            "NoNewPrivileges=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        HOST.run(["systemctl", "daemon-reload"], capture_output=True)
        HOST.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)

    # ── Брандмауэр и NAT ────────────────────────────────────────────────

    @staticmethod
    def _fw_tool() -> str:
        if shutil.which("ufw"):
            r = HOST.run(["ufw", "status"], capture_output=True, text=True)
            if "Status: active" in r.stdout:
                return "ufw"
        return "iptables"

    def _fw_open_udp(self, port: int) -> None:
        if self._fw_tool() == "ufw":
            r = HOST.run(["ufw", "status"], capture_output=True, text=True)
            if not re.search(rf'^{port}/udp\b.*ALLOW', r.stdout, re.MULTILINE):
                HOST.run(["ufw", "allow", f"{port}/udp", "comment", "qWDTT DTLS"], capture_output=True)
            return

        args = ["-p", "udp", "--dport", str(port), "-j", "ACCEPT"]
        r = HOST.run(["iptables", "-t", "filter", "-C", "INPUT"] + args, capture_output=True)
        if r.returncode != 0:
            HOST.run(["iptables", "-t", "filter", "-I", "INPUT", "1"] + args, capture_output=True)
            self._ipt_persist()

    def _fw_close_udp(self, port: int) -> None:
        if shutil.which("ufw"):
            HOST.run(["ufw", "delete", "allow", f"{port}/udp"], capture_output=True)

        args = ["-p", "udp", "--dport", str(port), "-j", "ACCEPT"]
        for _ in range(5):
            r = HOST.run(["iptables", "-t", "filter", "-C", "INPUT"] + args, capture_output=True)
            if r.returncode != 0:
                break
            HOST.run(["iptables", "-t", "filter", "-D", "INPUT"] + args, capture_output=True)
        self._ipt_persist()

    @staticmethod
    def _masquerade_exists() -> bool:
        r = HOST.run(
            ["iptables", "-t", "nat", "-C", "POSTROUTING",
             "-s", DEFAULT_WG_SUBNET, "!", "-d", DEFAULT_WG_SUBNET, "-j", "MASQUERADE"],
            capture_output=True,
        )
        return r.returncode == 0

    def _add_masquerade(self) -> None:
        if not self._masquerade_exists():
            HOST.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING",
                 "-s", DEFAULT_WG_SUBNET, "!", "-d", DEFAULT_WG_SUBNET, "-j", "MASQUERADE"],
                capture_output=True,
            )
            self._ipt_persist()

    def _remove_masquerade(self) -> None:
        for _ in range(3):
            if not self._masquerade_exists():
                break
            HOST.run(
                ["iptables", "-t", "nat", "-D", "POSTROUTING",
                 "-s", DEFAULT_WG_SUBNET, "!", "-d", DEFAULT_WG_SUBNET, "-j", "MASQUERADE"],
                capture_output=True,
            )
        self._ipt_persist()

    @staticmethod
    def _ipt_persist(self=None) -> None:
        firewall.persist()

    # ── Сборка wdtt-server из исходников Go ─────────────────────────────

    def _build_wdtt_server(self) -> bool:
        tmp = Path(tempfile.mkdtemp())
        try:
            archive = tmp / "master.tar.gz"
            print(f"  Скачиваю исходники qWDTT...")
            urllib.request.urlretrieve(SOURCE_URL, str(archive))

            print(f"  Распаковываю...")
            HOST.run(
                ["tar", "-xzf", str(archive), "-C", str(tmp)],
                capture_output=True, check=True,
                timeout=SOURCE_EXTRACT_TIMEOUT,
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
            r = HOST.run(
                [go, "mod", "tidy"],
                capture_output=True, text=True,
                cwd=str(src_dir),
                env={**self._go_env(), "GOSUMDB": "off"},
                timeout=GO_MODULE_TIMEOUT,
            )
            if r.returncode != 0:
                print(f"  go mod tidy: {(r.stderr or '')[:300]}")
                return False

            print(f"  Компилирую wdtt-server...")
            env = {**self._go_env(), "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": self._go_arch()}
            r = HOST.run(
                [go, "build", "-o", str(tmp / "wdtt-server"),
                 "-ldflags", "-s -w", "./server.go"],
                capture_output=True, text=True,
                env=env, cwd=str(src_dir),
                timeout=GO_BUILD_TIMEOUT,
            )
            if r.returncode != 0:
                print(f"  Ошибка компиляции: {(r.stderr or '')[:300]}")
                return False

            built = tmp / "wdtt-server"
            if not built.exists():
                print(f"  Бинарник не создан.")
                return False

            BIN_PATH.parent.mkdir(parents=True, exist_ok=True)
            if BIN_PATH.exists():
                try:
                    BIN_PATH.unlink()
                except Exception:
                    pass

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
            r = HOST.run([go, "version"], capture_output=True, text=True)
            if r.returncode == 0:
                return go
        return None

    def _go_installed_version(self, go: str) -> tuple:
        r = HOST.run([go, "version"], capture_output=True, text=True)
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
            HOST.run(["rm", "-rf", str(go_dir)], capture_output=True)
        r = HOST.run(
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
