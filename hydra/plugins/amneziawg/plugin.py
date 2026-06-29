"""
hydra/plugins/amneziawg/plugin.py — AmneziaWG 2.0 (wiresock kernel-модуль).

Контракт v2:
  • configure() — ЧИСТАЯ: генерит секции [Peer] в памяти, не трогает систему.
  • apply() — пишет awg0.conf, применяет syncconf / поднимает интерфейс.
  • per-user: on_user_add/remove/block → пересборка + apply.
  • traffic(state) — строит pub→email из state.users.
  • connected_clients() — без PEER_MAP, использует self._peer_map.
"""
from __future__ import annotations

import base64
import hashlib
import re
import shutil
import subprocess
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, User

AWG_INSTALL_DIR = Path("/opt/awg-install")
AWG_BIN = Path("/usr/bin/awg")
AWG_CONF_DIR = Path("/etc/amnezia/amneziawg")
AWG_CONF = AWG_CONF_DIR / "awg0.conf"
AWG_PARAMS = AWG_CONF_DIR / "params"
AWG_INTERFACE = "awg0"
AWG_UNIT = "awg-quick@awg0"

DEFAULT_NETWORK = "10.66.66.0/24"
DEFAULT_PORT = 51820
DEFAULT_OBFUSCATION = {
    "Jc": "4", "Jmin": "40", "Jmax": "70",
    "S1": "8", "S2": "72",
}
OBFUSCATION_KEYS = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
                    "H1", "H2", "H3", "H4"]


class AmneziaWGPlugin(BasePlugin):
    meta = PluginMeta(
        name="amneziawg",
        description="AmneziaWG 2.0: WireGuard с обфускацией (kernel-модуль)",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=False,
    )

    def __init__(self):
        self._pending_conf: str | None = None
        self._peer_map: dict[str, str] = {}

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        """Устанавливает AmneziaWG через wiresock/amneziawg-install (AUTO_INSTALL)."""
        if self._installed():
            return True

        import os
        try:
            subprocess.run(["rm", "-rf", str(AWG_INSTALL_DIR)], capture_output=True)
            r = subprocess.run(
                ["git", "clone", "--depth", "1",
                 "https://github.com/wiresock/amneziawg-install.git",
                 str(AWG_INSTALL_DIR)],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode != 0:
                print(f"  git clone: {r.stderr[:300]}")
                return False

            print("  Авто-установка AmneziaWG (компиляция модуля, это долго)...")
            env = os.environ.copy()
            env["AUTO_INSTALL"] = "y"
            env["ENABLE_IPV6"] = "n"
            env["SERVER_PUB_IP"] = self._public_ip()
            subprocess.run(
                ["bash", "amneziawg-install.sh"],
                cwd=str(AWG_INSTALL_DIR), env=env, timeout=900,
            )

            if "amneziawg" not in subprocess.run(
                ["lsmod"], capture_output=True, text=True).stdout:
                subprocess.run(["modprobe", "amneziawg"], capture_output=True)

            return self._installed()
        except Exception as e:
            print(f"  install error: {e}")
            return False

    def uninstall(self) -> bool:
        """Полностью удаляет AmneziaWG: служба, пакеты, модуль, файлы."""
        subprocess.run(["systemctl", "stop", AWG_UNIT], capture_output=True)
        subprocess.run(["systemctl", "disable", AWG_UNIT], capture_output=True)
        subprocess.run(["apt-get", "purge", "-y", "-qq",
            "amneziawg", "amneziawg-tools", "amneziawg-dkms"], capture_output=True)
        subprocess.run(["modprobe", "-r", "amneziawg"], capture_output=True)
        subprocess.run(["rm", "-rf",
            str(AWG_CONF_DIR),
            "/usr/bin/awg", "/usr/bin/awg-quick",
            "/usr/local/bin/awg", "/usr/local/bin/awg-quick",
            str(AWG_INSTALL_DIR),
        ], capture_output=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: генерит конфиг в памяти, без side-effects
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        """Собирает секции [Peer] из state.users. НЕ пишет файл, не вызывает syncconf."""
        if not AWG_CONF.exists():
            return ConfigFragment()

        iface_block = self._interface_block()
        existing_ips = self._existing_peer_ips()
        base, server_octet, network = self._network()

        used = set(existing_ips.values()) | {server_octet}
        peer_map: dict[str, str] = {}
        blocks = [iface_block.rstrip(), ""]

        for user in state.users:
            if user.blocked:
                continue
            pub = self._derive_pubkey(user.uuid)
            psk = self._derive_psk(user.uuid)

            if pub in existing_ips:
                octet = existing_ips[pub]
            else:
                octet = self._first_free(used)
                used.add(octet)

            peer_map[pub] = user.email
            blocks += [
                f"### {user.email}",
                "[Peer]",
                f"PublicKey = {pub}",
                f"PresharedKey = {psk}",
                f"AllowedIPs = {base}.{octet}/32",
                "",
            ]

        self._pending_conf = "\n".join(blocks) + "\n"
        self._peer_map = peer_map

        return ConfigFragment(
            route_rules=[{"ip_cidr": [network], "outbound": "direct"}],
        )

    def apply(self, state: AppState) -> bool:
        """Пишет awg0.conf и применяет syncconf / поднимает интерфейс."""
        if not self._pending_conf:
            return False
        AWG_CONF.write_text(self._pending_conf)
        AWG_CONF.chmod(0o600)
        return self._apply()

    def _apply(self) -> bool:
        """Применяет awg0.conf без разрыва туннеля (или поднимает интерфейс)."""
        if self._is_up():
            r = subprocess.run(
                ["bash", "-c", f"awg syncconf {AWG_INTERFACE} <(awg-quick strip {AWG_INTERFACE})"],
                capture_output=True, text=True,
            )
            return r.returncode == 0
        r = subprocess.run(["systemctl", "start", AWG_UNIT], capture_output=True)
        if r.returncode != 0:
            r = subprocess.run(["awg-quick", "up", AWG_INTERFACE], capture_output=True)
        return r.returncode == 0

    # ── разбор awg0.conf ────────────────────────────────────────────────

    def _interface_block(self) -> str:
        """Возвращает секцию [Interface] из awg0.conf (до первого [Peer])."""
        text = AWG_CONF.read_text() if AWG_CONF.exists() else ""
        out: list[str] = []
        for line in text.splitlines():
            if line.strip() == "[Peer]" or line.strip().startswith("### "):
                break
            out.append(line)
        return "\n".join(out)

    def _existing_peer_ips(self) -> dict[str, str]:
        """Возвращает {pubkey: octet} из текущих [Peer]-секций."""
        if not AWG_CONF.exists():
            return {}
        result: dict[str, str] = {}
        cur_pub = None
        for line in AWG_CONF.read_text().splitlines():
            line = line.strip()
            m = re.match(r"PublicKey\s*=\s*(\S+)", line)
            if m:
                cur_pub = m.group(1)
                continue
            m = re.match(r"AllowedIPs\s*=\s*(\d+)\.(\d+)\.(\d+)\.(\d+)", line)
            if m and cur_pub:
                result[cur_pub] = m.group(4)
                cur_pub = None
        return result

    def _network(self) -> tuple[str, str, str]:
        """('10.66.66', server_octet, '10.66.66.0/24') из Address в awg0.conf."""
        if AWG_CONF.exists():
            m = re.search(r"Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.(\d+)", AWG_CONF.read_text())
            if m:
                base = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
                return base, m.group(4), f"{base}.0/24"
        base = DEFAULT_NETWORK.rsplit(".", 1)[0]
        return base, "1", DEFAULT_NETWORK

    @staticmethod
    def _first_free(used: set[str]) -> str:
        for i in range(2, 255):
            if str(i) not in used:
                return str(i)
        return "254"

    def _obfuscation(self) -> dict[str, str]:
        """Поля обфускации из [Interface] (для клиентского конфига)."""
        text = self._interface_block()
        out: dict[str, str] = {}
        for key in OBFUSCATION_KEYS:
            m = re.search(rf"^{key}\s*=\s*(\S+)", text, re.M)
            if m:
                out[key] = m.group(1)
        for k, v in DEFAULT_OBFUSCATION.items():
            out.setdefault(k, v)
        return out

    # ── детерминированные ключи пира ────────────────────────────────────

    @staticmethod
    def _derive_priv(uuid: str) -> str:
        return base64.b64encode(hashlib.sha256(f"awg-priv|{uuid}".encode()).digest()).decode()

    @staticmethod
    def _derive_psk(uuid: str) -> str:
        return base64.b64encode(hashlib.sha256(f"awg-psk|{uuid}".encode()).digest()).decode()

    def _derive_pubkey(self, uuid: str) -> str:
        return self._awg("pubkey", _input=self._derive_priv(uuid)).stdout.strip()

    def _server_pubkey(self) -> str:
        m = re.search(r"PrivateKey\s*=\s*(\S+)", self._interface_block())
        if not m:
            return ""
        return self._awg("pubkey", _input=m.group(1)).stdout.strip()

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
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
        """Валидный клиентский .conf. Гарантирует, что пир есть на сервере."""
        if not AWG_CONF.exists():
            return ""

        self.configure(state)
        self.apply(state)

        pub = self._derive_pubkey(user.uuid)
        ip = self._existing_peer_ips().get(pub)
        if not ip:
            return ""
        base, _, _ = self._network()

        server_pub = self._server_pubkey()
        port = self._current_port()
        endpoint = state.network.server_ip or self._params().get("SERVER_PUB_IP") or self._public_ip()
        obf = self._obfuscation()

        mtu_m = re.search(r"^MTU\s*=\s*(\d+)", self._interface_block(), re.M)
        mtu = mtu_m.group(1) if mtu_m else "1420"

        dns = self._params().get("CLIENT_DNS_1", "1.1.1.1")
        dns2 = self._params().get("CLIENT_DNS_2", "")
        dns_line = f"{dns}, {dns2}" if dns2 else dns
        if state.network.dnscrypt_enabled:
            dns_line = endpoint

        lines = [
            "[Interface]",
            f"PrivateKey = {self._derive_priv(user.uuid)}",
            f"Address = {base}.{ip}/32",
            f"DNS = {dns_line}",
            f"MTU = {mtu}",
            "",
        ]
        for key in OBFUSCATION_KEYS:
            if key in obf:
                lines.append(f"{key} = {obf[key]}")
        lines += [
            "",
            "[Peer]",
            f"PublicKey = {server_pub}",
            f"PresharedKey = {self._derive_psk(user.uuid)}",
            f"Endpoint = {endpoint}:{port}",
            "AllowedIPs = 0.0.0.0/0",
            "PersistentKeepalive = 25",
        ]
        return "\n".join(lines)

    def client_link(self, user: User, state: AppState) -> str:
        """Ссылка wg:// для AmneziaWG-клиентов на базе клиентского конфига."""
        conf = self.generate_client_config(user, state)
        if not conf:
            return ""

        def f(key):
            m = re.search(rf"^{key}\s*=\s*(.+)$", conf, re.M)
            return m.group(1).strip() if m else None

        ep = f("Endpoint")
        if not ep or ":" not in ep:
            return ""
        host, port = ep.rsplit(":", 1)

        params = []
        if f("PrivateKey"):   params.append(f"private_key={f('PrivateKey')}")
        if f("Address"):      params.append(f"local_address={f('Address')}")
        params.append("enable_amnezia=true")
        for key in OBFUSCATION_KEYS:
            v = f(key)
            if v:
                params.append(f"{key.lower()}={v}")
        if f("PublicKey"):    params.append(f"public_key={f('PublicKey')}")
        if f("PresharedKey"): params.append(f"pre_shared_key={f('PresharedKey')}")
        params.append("persistent_keepalive_interval=25")
        return f"wg://{host}:{port}?{'&'.join(params)}#{user.email}%20AWG"

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = self._installed()
        return PluginStatus(
            installed=installed,
            enabled=AWG_CONF.exists(),
            running=installed and self._is_up(),
            port=self._current_port() if installed else 0,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        """{email: bytes}. Строит pubkey→email из state.users."""
        if not self._installed() or not self._is_up():
            return {}
        r = self._awg("show", AWG_INTERFACE, "transfer")
        if r.returncode != 0:
            return {}

        pub_to_email = {
            self._derive_pubkey(u.uuid): u.email
            for u in state.users if not u.blocked
        }

        result: dict[str, int] = {}
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                pub, rx, tx = parts[0], parts[1], parts[2]
                email = pub_to_email.get(pub)
                if email:
                    result[email] = result.get(email, 0) + int(rx) + int(tx)
        return result

    def connected_clients(self) -> list[dict]:
        """Список пиров с email, трафиком и последним рукопожатием."""
        if not self._installed() or not self._is_up():
            return []
        r = self._awg("show", AWG_INTERFACE, "dump")
        if r.returncode != 0:
            return []
        clients: list[dict] = []
        for line in r.stdout.strip().splitlines()[1:]:
            p = line.split("\t")
            if len(p) < 8:
                continue
            pub = p[0]
            handshake = int(p[4]) if p[4].isdigit() else 0
            clients.append({
                "pubkey": pub,
                "email": self._peer_map.get(pub, "?"),
                "endpoint": p[2],
                "last_handshake": handshake,
                "online": handshake > 0,
                "rx": int(p[5]) if p[5].isdigit() else 0,
                "tx": int(p[6]) if p[6].isdigit() else 0,
            })
        return clients

    # ═════════════════════════════════════════════════════════════════════
    #  Управление интерфейсом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        self.configure(state)
        self.apply(state)
        if not self._is_up():
            subprocess.run(["systemctl", "enable", "--now", AWG_UNIT], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        subprocess.run(["systemctl", "stop", AWG_UNIT], capture_output=True)

    # ═════════════════════════════════════════════════════════════════════
    #  Низкоуровневые помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _installed() -> bool:
        return AWG_BIN.exists() or shutil.which("awg") is not None

    def _is_up(self) -> bool:
        return subprocess.run(
            ["ip", "link", "show", AWG_INTERFACE], capture_output=True).returncode == 0

    def _current_port(self) -> int:
        r = self._awg("show", AWG_INTERFACE)
        m = re.search(r"listening port:\s*(\d+)", r.stdout)
        if m:
            return int(m.group(1))
        m = re.search(r"ListenPort\s*=\s*(\d+)", self._interface_block())
        return int(m.group(1)) if m else DEFAULT_PORT

    def _params(self) -> dict[str, str]:
        out: dict[str, str] = {}
        if AWG_PARAMS.exists():
            for line in AWG_PARAMS.read_text().splitlines():
                m = re.match(r"(\w+)='?([^']*)'?", line.strip())
                if m:
                    out[m.group(1)] = m.group(2)
        return out

    def _awg(self, *args, _input: str = "") -> subprocess.CompletedProcess:
        bin_path = shutil.which("awg") or str(AWG_BIN)
        kw: dict = {"capture_output": True, "text": True}
        if _input:
            kw["input"] = _input
        return subprocess.run([bin_path, *args], **kw)

    @staticmethod
    def _public_ip() -> str:
        r = subprocess.run(
            ["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
            capture_output=True, text=True,
        )
        return r.stdout.strip() if r.returncode == 0 else "127.0.0.1"
