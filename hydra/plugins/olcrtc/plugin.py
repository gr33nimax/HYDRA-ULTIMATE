"""hydra/plugins/olcrtc/plugin.py — olcRTC: TCP-over-WebRTC туннель.

Контракт v2 — TRANSPORT-плагин:
  • Каждый HYDRA-пользователь = отдельный systemd-сервис (линк).
  • install() — сборка бинарника из Go-исходников (openlibrecommunity/olcrtc).
  • on_user_add() — создаёт линк (Jitsi-комната, ключ, сервис).
  • on_user_remove() — удаляет линк, конфиги, runtime-данные.
  • on_user_block() — останавливает сервис (но сохраняет конфиг).
  • client_link() — возвращает YAML-конфиг клиента (нет URI-схемы).
  • nft_tproxy_ports не нужен — клиент инициирует исходящие WebRTC-соединения.
"""
from __future__ import annotations

import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, User
from hydra.utils.crypto import gen_password

OLC_REPO = "https://github.com/openlibrecommunity/olcrtc.git"
OLC_SRC_DIR = Path("/opt/olcrtc-src")
OLC_BIN = Path("/usr/local/bin/olcrtc")
OLC_GO_DIR = Path("/usr/local/go")
OLC_ETC_DIR = Path("/etc/olcrtc")
OLC_LINKS_DIR = OLC_ETC_DIR / "links"
OLC_VAR_DIR = Path("/var/lib/olcrtc")
OLC_UNIT_FILE = Path("/etc/systemd/system/olcrtc@.service")

DEFAULT_CARRIER = "jitsi"
DEFAULT_TRANSPORT = "datachannel"
DEFAULT_SOCKS_START = 8808
DEFAULT_JITSI_HOSTS = [
    "meet.handyweb.org",
    "meet.small-dm.ru",
    "meet1.arbitr.ru",
]

UNIT_CONTENT = (
    "[Unit]\n"
    "Description=olcrtc link %i (WebRTC-туннель)\n"
    "After=network-online.target\n"
    "Wants=network-online.target\n"
    "\n"
    "[Service]\n"
    "Type=simple\n"
    "ExecStart=/usr/local/bin/olcrtc /etc/olcrtc/links/%i.yaml\n"
    "WorkingDirectory=/var/lib/olcrtc/%i\n"
    "Restart=on-failure\n"
    "RestartSec=5\n"
    "User=root\n"
    "NoNewPrivileges=true\n"
    "\n"
    "[Install]\n"
    "WantedBy=multi-user.target\n"
)


class OlcrtcPlugin(BasePlugin):
    meta = PluginMeta(
        name="olcrtc",
        description="olcRTC: TCP-over-WebRTC, маскировка под видеозвонок Jitsi/Телемост",
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

        OLC_LINKS_DIR.mkdir(parents=True, exist_ok=True)
        OLC_VAR_DIR.mkdir(parents=True, exist_ok=True)

        print("  Клонирую исходники olcrtc...")
        if not self._clone_source():
            print("  Не удалось клонировать репозиторий.")
            return False

        required = self._go_required_version()
        go = self._ensure_go(required)
        if not go:
            print(f"  Не удалось установить Go {required}+.")
            return False

        print("  Собираю бинарник...")
        if not self._build_binary(go):
            print("  Сборка не удалась.")
            return False

        self._ensure_unit_file()
        return self._installed()

    def uninstall(self) -> bool:
        st = self._load_links()
        for name in list(st.keys()):
            self._delete_link(name, st)

        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

        if OLC_BIN.exists():
            OLC_BIN.unlink()

        for d in (OLC_SRC_DIR, OLC_ETC_DIR, OLC_VAR_DIR):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)

        if OLC_UNIT_FILE.exists():
            OLC_UNIT_FILE.unlink()

        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: olcrtc не требует портов/inbounds
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        ps = state.protocols.get("olcrtc")
        cfg = ps.config if ps and ps.config else {}

        self._pending_cfg = {
            "carrier": cfg.get("carrier", DEFAULT_CARRIER),
            "transport": cfg.get("transport", DEFAULT_TRANSPORT),
            "jitsi_host": cfg.get("jitsi_host", DEFAULT_JITSI_HOSTS[0]),
        }

        return ConfigFragment()

    def apply(self, state: AppState) -> bool:
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        if not self._installed():
            return

        ps = state.protocols.get("olcrtc")
        cfg = ps.config if ps and ps.config else {}
        carrier = cfg.get("carrier", DEFAULT_CARRIER)
        transport = cfg.get("transport", DEFAULT_TRANSPORT)
        jitsi_host = cfg.get("jitsi_host", DEFAULT_JITSI_HOSTS[0])

        name = self._sanitize_name(user.uuid)
        key = secrets.token_hex(32)
        socks_port = self._next_socks_port()
        data_dir = OLC_VAR_DIR / name / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        if carrier == "jitsi":
            room_path = "olc-" + secrets.token_hex(4)
            room_id = f"https://{jitsi_host}/{room_path}"
        else:
            room_id = cfg.get("room_id", "")

        server_yaml = self._server_yaml(carrier, room_id, key, transport, str(data_dir))
        OLC_LINKS_DIR.mkdir(parents=True, exist_ok=True)
        (OLC_LINKS_DIR / f"{name}.yaml").write_text(server_yaml, encoding="utf-8")

        client_yaml = self._client_yaml(carrier, room_id, key, transport, socks_port)
        (OLC_LINKS_DIR / f"{name}.client.yaml").write_text(client_yaml, encoding="utf-8")

        self._ensure_unit_file()
        unit = f"olcrtc@{name}"
        subprocess.run(["systemctl", "enable", "--now", unit], capture_output=True, timeout=20)
        time.sleep(2)

        user.credentials.setdefault("olcrtc", {})
        user.credentials["olcrtc"] = {
            "carrier": carrier,
            "transport": transport,
            "room_id": room_id,
            "key": key,
            "socks_port": socks_port,
            "link_name": name,
        }

    def on_user_remove(self, user: User, state: AppState) -> None:
        creds = user.credentials.get("olcrtc", {})
        name = creds.get("link_name")
        if name:
            st = self._load_links()
            self._delete_link(name, st)
        user.credentials.pop("olcrtc", None)

    def on_user_block(self, user: User, state: AppState) -> None:
        creds = user.credentials.get("olcrtc", {})
        name = creds.get("link_name")
        if name:
            subprocess.run(["systemctl", "stop", f"olcrtc@{name}"], capture_output=True)

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентский конфиг
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        creds = user.credentials.get("olcrtc", {})
        if not creds:
            return ""
        yaml = self._client_yaml(
            creds["carrier"], creds["room_id"], creds["key"],
            creds["transport"], creds["socks_port"],
        )
        return json.dumps({
            "protocol": "olcrtc",
            "client_yaml": yaml,
            "socks_port": creds["socks_port"],
            "instructions": (
                "1. Соберите olcrtc под свою ОС: https://github.com/openlibrecommunity/olcrtc\n"
                "2. Сохраните client_yaml в файл (например client.yaml)\n"
                "3. Запустите: olcrtc client.yaml\n"
                f"4. SOCKS5 поднимется на 127.0.0.1:{creds['socks_port']}\n"
            ),
        }, indent=2)

    def client_link(self, user: User, state: AppState) -> str:
        creds = user.credentials.get("olcrtc", {})
        if not creds:
            return ""
        return self._client_yaml(
            creds["carrier"], creds["room_id"], creds["key"],
            creds["transport"], creds["socks_port"],
        )

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = self._installed()
        st = self._load_links() if installed else {}
        active = 0
        for name in st:
            r = subprocess.run(
                ["systemctl", "is-active", f"olcrtc@{name}"],
                capture_output=True, text=True,
            )
            if r.stdout.strip() == "active":
                active += 1

        return PluginStatus(
            installed=installed,
            enabled=self._installed(),
            running=active > 0,
            port=0,
            info={"links": len(st), "active": active},
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def connected_clients(self) -> list[dict]:
        st = self._load_links()
        result = []
        for name in st:
            r = subprocess.run(
                ["systemctl", "is-active", f"olcrtc@{name}"],
                capture_output=True, text=True,
            )
            result.append({
                "name": name,
                "active": r.stdout.strip() == "active",
            })
        return result

    # ═════════════════════════════════════════════════════════════════════
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        st = self._load_links()
        for name in st:
            subprocess.run(
                ["systemctl", "enable", "--now", f"olcrtc@{name}"],
                capture_output=True,
            )

    def on_disable(self, state: AppState) -> None:
        st = self._load_links()
        for name in st:
            subprocess.run(
                ["systemctl", "disable", "--now", f"olcrtc@{name}"],
                capture_output=True,
            )

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _sanitize_name(raw: str) -> str:
        return re.sub(r"[^a-z0-9_-]", "", raw.strip().lower())[:32]

    @staticmethod
    def _server_yaml(carrier: str, room_id: str, key: str,
                     transport: str, data_dir: str) -> str:
        lines = [
            "mode: srv",
            "auth:",
            f"  provider: {carrier}",
            "room:",
            f'  id: "{room_id}"',
            "crypto:",
            f'  key: "{key}"',
            "net:",
            f"  transport: {transport}",
            '  dns: "8.8.8.8:53"',
        ]
        if transport == "vp8channel":
            lines += ["vp8:", "  fps: 60", "  batch_size: 64"]
        elif transport == "videochannel":
            lines += [
                "video:", "  width: 1080", "  height: 1080", "  fps: 60",
                '  bitrate: "5000k"', '  hw: "none"',
            ]
        lines += [f'data: "{data_dir}"', "debug: false"]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _client_yaml(carrier: str, room_id: str, key: str,
                     transport: str, socks_port: int) -> str:
        lines = [
            "mode: cnc",
            "auth:",
            f"  provider: {carrier}",
            "room:",
            f'  id: "{room_id}"',
            "crypto:",
            f'  key: "{key}"',
            "net:",
            f"  transport: {transport}",
            '  dns: "8.8.8.8:53"',
        ]
        if transport == "vp8channel":
            lines += ["vp8:", "  fps: 60", "  batch_size: 64"]
        elif transport == "videochannel":
            lines += [
                "video:", "  width: 1080", "  height: 1080", "  fps: 60",
                '  bitrate: "5000k"', '  hw: "none"',
            ]
        lines += [
            "socks:",
            '  host: "127.0.0.1"',
            f"  port: {socks_port}",
            'data: "olcrtc-client-data"',
            "debug: false",
        ]
        return "\n".join(lines) + "\n"

    @staticmethod
    def _next_socks_port() -> int:
        return DEFAULT_SOCKS_START

    @staticmethod
    def _load_links() -> dict:
        result = {}
        if OLC_LINKS_DIR.exists():
            for f in OLC_LINKS_DIR.glob("*.yaml"):
                name = f.stem
                if name.endswith(".client"):
                    continue
                result[name] = {"yaml": str(f)}
        return result

    def _delete_link(self, name: str, st: dict) -> None:
        subprocess.run(
            ["systemctl", "disable", "--now", f"olcrtc@{name}"],
            capture_output=True, timeout=20,
        )
        (OLC_LINKS_DIR / f"{name}.yaml").unlink(missing_ok=True)
        (OLC_LINKS_DIR / f"{name}.client.yaml").unlink(missing_ok=True)
        shutil.rmtree(OLC_VAR_DIR / name, ignore_errors=True)

    @staticmethod
    def _installed() -> bool:
        return OLC_BIN.exists()

    def _ensure_unit_file(self) -> None:
        OLC_UNIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        OLC_UNIT_FILE.write_text(UNIT_CONTENT)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)

    # ── Go toolchain ────────────────────────────────────────────────────

    def _clone_source(self) -> bool:
        if OLC_SRC_DIR.exists() and (OLC_SRC_DIR / ".git").exists():
            r = subprocess.run(
                ["git", "-C", str(OLC_SRC_DIR), "pull", "--ff-only"],
                capture_output=True, text=True, timeout=60,
            )
            if r.returncode == 0:
                return True
            shutil.rmtree(OLC_SRC_DIR, ignore_errors=True)
        OLC_SRC_DIR.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["git", "clone", "--depth", "1", OLC_REPO, str(OLC_SRC_DIR)],
            capture_output=True, timeout=180,
        )
        return r.returncode == 0 and OLC_SRC_DIR.exists()

    def _build_binary(self, go: str) -> bool:
        env = dict(os.environ)
        env.update({
            "CGO_ENABLED": "0",
            "GOOS": "linux",
            "GOARCH": self._go_arch(),
        })
        r = subprocess.run(
            [go, "build", "-trimpath", "-ldflags", "-s -w",
             "-o", str(OLC_BIN), "./cmd/olcrtc"],
            capture_output=True, text=True,
            env=env, cwd=str(OLC_SRC_DIR), timeout=900,
        )
        if r.returncode != 0:
            print(f"  go build error: {(r.stderr or '')[:300]}")
            return False
        return OLC_BIN.exists()

    @staticmethod
    def _go_arch() -> str:
        m = platform.machine().lower()
        return {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(m, "amd64")

    def _go_required_version(self) -> str:
        gomod = OLC_SRC_DIR / "go.mod"
        if gomod.exists():
            try:
                m = re.search(r"^go\s+(\d+\.\d+(?:\.\d+)?)", gomod.read_text(), re.M)
                if m:
                    return m.group(1)
            except Exception:
                pass
        return "1.26.0"

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
                headers={"User-Agent": "HYDRA-OLCRTC"},
            )
            with urllib.request.urlopen(req, timeout=15) as r:
                version = r.read().decode("utf-8", errors="replace").splitlines()[0].strip()
            if not version.startswith("go"):
                version = f"go{required}"
        except Exception:
            version = f"go{required}"

        url = f"https://go.dev/dl/{version}.linux-{arch}.tar.gz"
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
