"""hydra/plugins/webdav/plugin.py — WebDAV Tunnel: SOCKS5 поверх WebDAV.

Контракт v2 — TRANSPORT-плагин, single-login, не per-user:
  • configure() — генерит параметры сервиса в памяти.
  • apply() — пишет systemd unit, перезапускает.
  • install — сборка из Go-исходников spkprsnts/webdav-tunnel.
  • Два режима: selfhosted (встроенный WebDAV-сервер) / external (через облако).
  • client_link — webdav[s]:// URI для клиента.
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
from hydra.utils.net import public_ip
from hydra.utils.firewall import open_tcp, close_tcp

BIN_PATH = Path("/usr/local/bin/webdav-tunnel")
CFG_DIR = Path("/etc/webdav-tunnel")
STORAGE_DIR = CFG_DIR / "data"
SERVICE_FILE = Path("/etc/systemd/system/webdav-tunnel.service")
SERVICE_NAME = "webdav-tunnel"

DEFAULT_PORT = 8443

GITHUB_REPO = "spkprsnts/webdav-tunnel"
SOURCE_URL = f"https://github.com/{GITHUB_REPO}/archive/refs/heads/main.tar.gz"
GO_DL_URL = "https://go.dev/dl/"

_SH_TUNING = {
    "poll-min": "50ms", "poll-max": "200ms", "coalesce": "5ms",
    "puts": "16", "read-max": "16", "read-min": "3", "chunk-size": "131071",
}


class WebdavPlugin(BasePlugin):
    meta = PluginMeta(
        name="webdav",
        description="WebDAV Tunnel: SOCKS5 поверх WebDAV-файлов — маскировка под облачное хранилище",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=True,
    )

    def __init__(self):
        self._pending_cfg: dict | None = None

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        if self._installed():
            return True

        print("  Сборка webdav-tunnel из исходников...")
        if not self._build_binary():
            print("  Не удалось собрать webdav-tunnel.")
            return False

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
        if CFG_DIR.exists():
            shutil.rmtree(CFG_DIR, ignore_errors=True)

        close_tcp(DEFAULT_PORT)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: собирает параметры в памяти
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        ps = state.protocols.get("webdav")
        cfg = ps.config if ps and ps.config else {}
        mode = cfg.get("mode", "selfhosted")

        if mode == "external":
            return ConfigFragment()

        port = cfg.get("port", DEFAULT_PORT)
        login = cfg.get("login", self._gen_login())
        password = cfg.get("password", self._gen_password())
        tls_cert = cfg.get("tls_cert", "")
        tls_key = cfg.get("tls_key", "")

        self._pending_cfg = {
            "mode": mode,
            "port": port,
            "login": login,
            "password": password,
            "tls_cert": tls_cert,
            "tls_key": tls_key,
            "webdav_url": cfg.get("webdav_url", ""),
            "proxy": cfg.get("proxy", ""),
        }

        return ConfigFragment(
            nft_tproxy_ports=[port],
        )

    def apply(self, state: AppState) -> bool:
        if not self._pending_cfg:
            return False

        cfg = self._pending_cfg
        mode = cfg["mode"]

        CFG_DIR.mkdir(parents=True, exist_ok=True)

        if mode == "selfhosted":
            STORAGE_DIR.mkdir(parents=True, exist_ok=True)
            open_tcp(cfg["port"], "webdav-tunnel")

        self._write_service(cfg)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
        time.sleep(2)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user (no-op — single login, делимся одной ссылкой)
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        pass

    def on_user_remove(self, user: User, state: AppState) -> None:
        pass

    def on_user_block(self, user: User, state: AppState) -> None:
        pass

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентский конфиг
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        link = self.client_link(user, state)
        if not link:
            return ""
        return json.dumps({
            "protocol": "webdav",
            "link": link,
            "client_build": f"git clone https://github.com/{GITHUB_REPO} && cd webdav-tunnel && go build -o webdav-tunnel .",
            "run_command": f"webdav-tunnel -mode client -uri \"{link}\" -socks-listen 127.0.0.1:1080",
        }, indent=2)

    def client_link(self, user: User, state: AppState) -> str:
        ps = state.protocols.get("webdav")
        cfg = ps.config if ps and ps.config else {}
        mode = cfg.get("mode", "selfhosted")
        login = cfg.get("login", self._gen_login())
        password = cfg.get("password", self._gen_password())

        if mode == "selfhosted":
            port = cfg.get("port", DEFAULT_PORT)
            server_ip = state.network.server_ip or public_ip()
            tls = bool(cfg.get("tls_cert") and cfg.get("tls_key"))
            scheme = "webdavs" if tls else "webdav"
            query = "&".join(f"{k}={v}" for k, v in _SH_TUNING.items())
            name = f"webdav-{server_ip}"
            return f"{scheme}://{login}:{password}@{server_ip}:{port}?{query}#{name}"

        webdav_url = cfg.get("webdav_url", "")
        if not webdav_url:
            return ""
        from urllib.parse import urlparse
        parsed = urlparse(webdav_url)
        scheme = "webdavs" if parsed.scheme == "https" else "webdav"
        host = parsed.hostname or "host"
        return f"{scheme}://{login}:{password}@{host}#webdav-{host}"

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        port = DEFAULT_PORT
        if installed:
            r = subprocess.run(
                ["systemctl", "is-active", SERVICE_NAME],
                capture_output=True, text=True,
            )
            running = r.stdout.strip() == "active"

        return PluginStatus(
            installed=installed,
            enabled=SERVICE_FILE.exists(),
            running=running,
            port=port,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

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
    def _installed() -> bool:
        return BIN_PATH.exists()

    @staticmethod
    def _gen_login() -> str:
        import secrets
        return "user" + "".join(secrets.choice("23456789") for _ in range(4))

    @staticmethod
    def _gen_password(length: int = 20) -> str:
        import secrets
        chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
        return "".join(secrets.choice(chars) for _ in range(length))

    @staticmethod
    def _write_service(cfg: dict) -> None:
        mode = cfg["mode"]
        parts = []

        if mode == "selfhosted":
            parts = [
                str(BIN_PATH), "-mode", "selfhosted",
                "-webdav-listen", f":{cfg['port']}",
                "-webdav-storage", str(STORAGE_DIR),
                "-login", cfg["login"], "-password", cfg["password"],
            ]
            for k, v in _SH_TUNING.items():
                parts += [f"-{k}", v]
            if cfg.get("tls_cert") and cfg.get("tls_key"):
                parts += ["-webdav-tls-cert", cfg["tls_cert"], "-webdav-tls-key", cfg["tls_key"]]
        else:
            parts = [
                str(BIN_PATH), "-mode", "server",
                "-webdav", cfg.get("webdav_url", ""),
                "-login", cfg["login"], "-password", cfg["password"],
            ]

        if cfg.get("proxy"):
            parts += ["-proxy", cfg["proxy"]]

        import shlex
        exec_start = " ".join(shlex.quote(p) for p in parts)
        cap_line = ""
        if mode == "selfhosted" and cfg.get("port", 8443) < 1024:
            cap_line = "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"

        SERVICE_FILE.write_text(
            "[Unit]\n"
            "Description=webdav-tunnel — TCP tunnel over WebDAV\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            f"ExecStart={exec_start}\n"
            "Restart=always\n"
            "RestartSec=5\n"
            f"{cap_line}"
            "NoNewPrivileges=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )

    # ── Сборка из Go-исходников ────────────────────────────────────────

    def _build_binary(self) -> bool:
        tmp = Path(tempfile.mkdtemp())
        try:
            archive = tmp / "main.tar.gz"
            print("  Скачиваю исходники webdav-tunnel...")
            urllib.request.urlretrieve(SOURCE_URL, str(archive))

            print("  Распаковываю...")
            subprocess.run(
                ["tar", "-xzf", str(archive), "-C", str(tmp)],
                capture_output=True, check=True,
            )

            src_dirs = list(tmp.glob("webdav-tunnel-*"))
            if not src_dirs:
                print("  Не найдена директория с исходниками.")
                return False
            src_dir = src_dirs[0]

            required = self._go_required_version(src_dir / "go.mod")
            go = self._ensure_go(required)
            if not go:
                print(f"  Не удалось установить Go {required}+.")
                return False

            print("  Компилирую webdav-tunnel...")
            r = subprocess.run(
                [go, "build", "-o", str(tmp / "webdav-tunnel"),
                 "-ldflags", "-s -w", "."],
                capture_output=True, text=True,
                env={**self._go_env(), "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": self._go_arch()},
                cwd=str(src_dir),
            )
            if r.returncode != 0:
                env = {**self._go_env(), "CGO_ENABLED": "0", "GOSUMDB": "off"}
                subprocess.run([go, "mod", "tidy"], capture_output=True, env=env, cwd=str(src_dir))
                r = subprocess.run(
                    [go, "build", "-o", str(tmp / "webdav-tunnel"),
                     "-ldflags", "-s -w", "."],
                    capture_output=True, text=True,
                    env=env, cwd=str(src_dir),
                )
            if r.returncode != 0:
                print(f"  Ошибка компиляции: {(r.stderr or '')[:300]}")
                return False

            built = tmp / "webdav-tunnel"
            if not built.exists():
                print("  Бинарник не создан.")
                return False

            BIN_PATH.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(built), str(BIN_PATH))
            BIN_PATH.chmod(0o755)
            print(f"  webdav-tunnel установлен: {BIN_PATH}")
            return True

        except Exception as e:
            print(f"  Ошибка: {e}")
            return False
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ── Go-утилиты ─────────────────────────────────────────────────────

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
        return "1.22.0"

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
                headers={"User-Agent": "HYDRA-WEBDAV"},
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
            print("  Не удалось распаковать Go.")
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
