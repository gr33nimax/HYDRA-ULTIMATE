"""
hydra/plugins/amneziawg/plugin.py — AmneziaWG 2.0 через wiresock kernel-модуль.

Архитектура:
  Клиент → AWG (awg0, kernel) → iptables NAT → интернет

Установка: https://github.com/wiresock/amneziawg-install
Конфиг: /etc/amnezia/amneziawg/awg0.conf
Пиры: по одному на каждого незаблокированного HYDRA-юзера
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, ConfigFragment
from hydra.core.state import AppState, User

AWG_INSTALL_DIR = Path("/opt/awg-install")
AWG_BIN = Path("/usr/bin/awg")
AWG_QUICK = Path("/usr/bin/awg-quick")
AWG_CONF_DIR = Path("/etc/amnezia/amneziawg")
AWG_CONF = AWG_CONF_DIR / "awg0.conf"
AWG_INTERFACE = "awg0"
AWG_NETWORK = "10.8.20.0/24"
AWG_SERVER_IP = "10.8.20.1"
AWG_PORT = 51820

STATE_FILE = Path("/var/lib/hydra/awg_state.json")

# Обфускация по умолчанию
OBFUSCATION = {
    "Jc": 4, "Jmin": 40, "Jmax": 70,
    "S1": 8, "S2": 72,
    "H1": 1748384502, "H2": 410655843,
    "H3": 3426724947, "H4": 4202318234,
}

# Внешний интерфейс для NAT
def _get_public_iface() -> str:
    r = subprocess.run(
        ["ip", "route", "show", "default"],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        parts = r.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return "eth0"


class AmneziaWGPlugin(BasePlugin):
    meta = PluginMeta(
        name="amneziawg",
        description="AmneziaWG 2.0: WireGuard с обфускацией (kernel-модуль wiresock)",
        version="1.0.0",
    )

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        """Устанавливает AmneziaWG. При повторном вызове — полная переустановка."""
        if AWG_BIN.exists() or shutil.which("awg"):
            self._down()
            subprocess.run(["modprobe", "-r", "amneziawg"], capture_output=True)
            # Полная зачистка пакетов и файлов
            subprocess.run(["apt-get", "purge", "-y", "-qq",
                "amneziawg", "amneziawg-tools", "amneziawg-dkms"], capture_output=True)
            subprocess.run(["rm", "-rf",
                "/etc/amnezia/amneziawg",
                "/usr/bin/awg", "/usr/bin/awg-quick",
                "/usr/local/bin/awg", "/usr/local/bin/awg-quick",
                str(AWG_INSTALL_DIR),
            ], capture_output=True)
            subprocess.run(["depmod", "-a"], capture_output=True)

        try:
            subprocess.run(["rm", "-rf", str(AWG_INSTALL_DIR)], capture_output=True)
            r = subprocess.run(
                ["git", "clone", "--depth", "1",
                 "https://github.com/wiresock/amneziawg-install.git",
                 str(AWG_INSTALL_DIR)],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode != 0:
                print(f"  {r.stderr[:300]}")
                return False

            print("  Авто-установка AmneziaWG...")
            server_ip = self._get_server_ip()
            env = os.environ.copy()
            env["AUTO_INSTALL"] = "y"
            env["ENABLE_IPV6"] = "n"
            env["SERVER_PUB_IP"] = server_ip
            r = subprocess.run(
                ["bash", "amneziawg-install.sh"],
                cwd=str(AWG_INSTALL_DIR),
                env=env,
                timeout=600,
            )

            lsmod = subprocess.run(["lsmod"], capture_output=True, text=True)
            if "amneziawg" not in lsmod.stdout:
                subprocess.run(["modprobe", "amneziawg"], capture_output=True)

            return AWG_BIN.exists()
        except Exception:
            return False

    def uninstall(self) -> bool:
        self._down()
        AWG_CONF.unlink(missing_ok=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Конфигурация — управление пирами через awg CLI (не трогаем awg0.conf)
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        """Добавляет/удаляет пиров через awg CLI. НЕ пишет awg0.conf."""
        users = [u for u in state.users if not u.blocked]
        current_peers = self._list_peer_pubkeys()
        wanted_peers = {self._derive_pubkey(u.uuid) for u in users}

        # Удалить лишних
        for pubkey in current_peers - wanted_peers:
            self._awg("set", AWG_INTERFACE, "peer", pubkey, "remove")

        # Добавить недостающих + сохранить PSK для всех
        for user in users:
            pubkey = self._derive_pubkey(user.uuid)
            if pubkey not in current_peers:
                peer_ip = self._peer_ip(user, state)
                psk = self._gen_psk()
                psk_file = Path(f"/tmp/awg-psk-{user.email}")
                psk_file.write_text(psk)
                self._awg("set", AWG_INTERFACE, "peer", pubkey,
                          "preshared-key", str(psk_file),
                          "allowed-ips", peer_ip)
                psk_file.unlink(missing_ok=True)
            # Всегда обновляем сохранённый PSK
            self._save_psk(user.email)

        self._setup_nat(self._network())

        return ConfigFragment(
            route_rules=[{"ip_cidr": [self._network()], "outbound": "direct"}],
        )

    def _list_peer_pubkeys(self) -> set[str]:
        r = self._awg("show", AWG_INTERFACE)
        keys: set[str] = set()
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("peer:"):
                keys.add(line.split(":", 1)[1].strip())
        return keys

    def _derive_pubkey(self, uuid: str) -> str:
        return self._awg("pubkey", _input=self._derive_key(uuid)).stdout.strip()

    def _gen_psk(self) -> str:
        return self._awg("genpsk").stdout.strip()

    def _save_psk(self, email: str) -> None:
        psk_store = AWG_CONF_DIR / f"psk-{email}"
        if not psk_store.exists():
            psk_store.write_text(self._gen_psk())

    def _peer_ip(self, user: User, state: AppState) -> str:
        network = self._network()
        base = network.rsplit(".", 2)[0]
        idx = next((i for i, u in enumerate(state.users) if u.email == user.email and not u.blocked), 0)
        return f"{base}.{idx + 2}/32"

    def _network(self) -> str:
        """Извлекает сеть из адреса сервера в awg0.conf."""
        if AWG_CONF.exists():
            import re
            text = AWG_CONF.read_text()
            m = re.search(r"Address\s*=\s*(\S+)", text)
            if m:
                parts = m.group(1).split(".")
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return AWG_NETWORK

    def _setup_nat(self, network: str) -> None:
        iface = _get_public_iface()
        rules_check = subprocess.run(
            ["iptables", "-t", "nat", "-C", "POSTROUTING",
             "-s", network, "-o", iface, "-j", "MASQUERADE"],
            capture_output=True,
        )
        if rules_check.returncode != 0:
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING",
                 "-s", network, "-o", iface, "-j", "MASQUERADE"],
                capture_output=True,
            )
        # IP forwarding
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True,
        )

    @staticmethod
    def _derive_key(seed: str) -> str:
        h = hashlib.sha256(seed.encode()).digest()
        return base64.b64encode(h[:32]).decode()

    @staticmethod
    def _get_server_ip() -> str:
        r = subprocess.run(
            ["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
            capture_output=True, text=True,
        )
        return r.stdout.strip() if r.returncode == 0 else "127.0.0.1"

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентский конфиг
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        """Генерирует клиентский .conf из awg0.conf (надёжный источник данных)."""
        import re
        if not AWG_CONF.exists():
            return ""

        conf_text = AWG_CONF.read_text()
        server_priv = re.search(r"PrivateKey\s*=\s*(\S+)", conf_text)
        port = re.search(r"ListenPort\s*=\s*(\d+)", conf_text)
        addr = re.search(r"Address\s*=\s*(\S+)", conf_text)

        # Обфускация
        jc = re.search(r"^Jc\s*=\s*(\S+)", conf_text, re.M)
        jmin = re.search(r"^Jmin\s*=\s*(\S+)", conf_text, re.M)
        jmax = re.search(r"^Jmax\s*=\s*(\S+)", conf_text, re.M)
        s1 = re.search(r"^S1\s*=\s*(\S+)", conf_text, re.M)
        s2 = re.search(r"^S2\s*=\s*(\S+)", conf_text, re.M)
        s3 = re.search(r"^S3\s*=\s*(\S+)", conf_text, re.M)
        s4 = re.search(r"^S4\s*=\s*(\S+)", conf_text, re.M)
        h1 = re.search(r"^H1\s*=\s*(\S+)", conf_text, re.M)
        h2 = re.search(r"^H2\s*=\s*(\S+)", conf_text, re.M)
        h3 = re.search(r"^H3\s*=\s*(\S+)", conf_text, re.M)
        h4 = re.search(r"^H4\s*=\s*(\S+)", conf_text, re.M)
        mtu = re.search(r"^MTU\s*=\s*(\d+)", conf_text, re.M)

        # PSK — из сохранённого файла
        psk = None
        psk_store = AWG_CONF_DIR / f"psk-{user.email}"
        if psk_store.exists():
            psk = psk_store.read_text().strip()

        server_pub = self._awg("pubkey", _input=server_priv.group(1)).stdout.strip() if server_priv else ""

        base = addr.group(1).rsplit(".", 1)[0] if addr else "10.8.20"
        peer_idx = next((i for i, u in enumerate(state.users) if u.email == user.email and not u.blocked), 0)

        server_ip = state.network.server_ip or self._get_server_ip()
        dns = "1.1.1.1, 1.0.0.1"
        if state.network.dnscrypt_enabled:
            dns = server_ip

        lines = [
            "[Interface]",
            f"PrivateKey = {self._derive_key(user.uuid)}",
            f"Address = {base}.{peer_idx + 2}/32",
            f"DNS = {dns}",
            f"MTU = {mtu.group(1) if mtu else '1420'}",
            "",
            "# Обфускация",
            f"Jc = {jc.group(1) if jc else '4'}",
            f"Jmin = {jmin.group(1) if jmin else '40'}",
            f"Jmax = {jmax.group(1) if jmax else '70'}",
            f"S1 = {s1.group(1) if s1 else '8'}",
            f"S2 = {s2.group(1) if s2 else '72'}",
        ]
        if s3: lines.append(f"S3 = {s3.group(1)}")
        if s4: lines.append(f"S4 = {s4.group(1)}")
        if h1: lines.append(f"H1 = {h1.group(1)}")
        if h2: lines.append(f"H2 = {h2.group(1)}")
        if h3: lines.append(f"H3 = {h3.group(1)}")
        if h4: lines.append(f"H4 = {h4.group(1)}")

        lines += [
            "",
            "[Peer]",
            f"PublicKey = {server_pub}",
        ]
        if psk:
            lines.append(f"PresharedKey = {psk.group(1)}")
        lines += [
            f"Endpoint = {server_ip}:{port.group(1) if port else '51820'}",
            "AllowedIPs = 0.0.0.0/0",
            "PersistentKeepalive = 25",
        ]
        return "\n".join(lines)

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = AWG_BIN.exists()
        running = False
        if installed:
            r = subprocess.run(["ip", "link", "show", AWG_INTERFACE], capture_output=True)
            running = r.returncode == 0
        return PluginStatus(
            installed=installed,
            enabled=AWG_CONF.exists(),
            running=running,
            port=self._current_port(),
        )

    def _current_port(self) -> int:
        r = self._awg("show", AWG_INTERFACE)
        import re
        m = re.search(r"listening port:\s*(\d+)", r.stdout)
        return int(m.group(1)) if m else AWG_PORT

    def _awg(self, *args, _input: str = "") -> subprocess.CompletedProcess:
        bin_path = shutil.which("awg") or "/usr/bin/awg"
        kw = {"capture_output": True, "text": True}
        if _input:
            kw["input"] = _input
        return subprocess.run([bin_path, *args], **kw)

    def traffic(self) -> dict[str, int]:
        if not AWG_CONF.exists() or not shutil.which("awg"):
            return {}

        r = self._awg("show", AWG_INTERFACE, "transfer")
        if r.returncode != 0:
            return {}

        traffic: dict[str, int] = {}
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                traffic[parts[0]] = int(parts[1]) + int(parts[2])
        return traffic

    def connected_peers(self) -> list[dict]:
        if not shutil.which("awg"):
            return []
        r = self._awg("show", AWG_INTERFACE)
        if r.returncode != 0:
            return []

        peers: list[dict] = []
        current: dict = {}
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("peer:"):
                if current:
                    peers.append(current)
                current = {"pubkey": line.split(":", 1)[1].strip()}
            elif ":" in line and current:
                k, v = line.split(":", 1)
                current[k.strip()] = v.strip()
        if current:
            peers.append(current)
        return peers

    # ═════════════════════════════════════════════════════════════════════
    #  Управление
    # ═════════════════════════════════════════════════════════════════════

    def _up(self) -> bool:
        """Поднимает интерфейс."""
        r = subprocess.run(
            ["ip", "link", "set", AWG_INTERFACE, "up"],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0

    def _down(self) -> None:
        subprocess.run(["ip", "link", "set", AWG_INTERFACE, "down"], capture_output=True)

    def on_enable(self, state: AppState) -> None:
        self.configure(state)
        self._up()

    def on_disable(self, state: AppState) -> None:
        self._down()
