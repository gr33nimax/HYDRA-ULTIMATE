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
        if AWG_BIN.exists():
            self._down()
            if AWG_INSTALL_DIR.exists():
                subprocess.run(
                    ["bash", "awg-remove.sh"],
                    cwd=str(AWG_INSTALL_DIR), capture_output=True, timeout=60,
                )
            subprocess.run(["rm", "-rf", str(AWG_INSTALL_DIR)], capture_output=True)

        try:
            r = subprocess.run(
                ["git", "clone", "--depth", "1",
                 "https://github.com/wiresock/amneziawg-install.git",
                 str(AWG_INSTALL_DIR)],
                capture_output=True, text=True, timeout=120,
            )
            if r.returncode != 0:
                print(f"  {r.stderr[:300]}")
                return False

            r = subprocess.run(
                ["bash", "awg-install.sh"],
                cwd=str(AWG_INSTALL_DIR),
                capture_output=True, text=True, timeout=300,
            )
            if r.returncode != 0:
                print(f"  {r.stderr[:500]}")
                return False

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
    #  Конфигурация
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        keys = self._load_or_generate_keys()
        users = [u for u in state.users if not u.blocked]
        proto = state.protocols.get("amneziawg")
        config = proto.config if proto else {}
        mtus = {True: 1200, False: 1420}
        mtu = mtus[state.network.warp_enabled]

        port = config.get("port", AWG_PORT)
        network = config.get("network", AWG_NETWORK)

        conf = self._build_conf(keys, users, port, network, mtu)
        AWG_CONF_DIR.mkdir(parents=True, exist_ok=True)
        AWG_CONF.write_text(conf)

        self._setup_nat(network)

        return ConfigFragment(
            route_rules=[{
                "ip_cidr": [network],
                "outbound": "direct",
            }],
        )

    def _load_or_generate_keys(self) -> dict:
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text())
            except Exception:
                pass

        private = subprocess.run(
            ["awg", "genkey"], capture_output=True, text=True,
        ).stdout.strip()
        public = subprocess.run(
            ["awg", "pubkey"], input=private, capture_output=True, text=True,
        ).stdout.strip()

        keys = {"private": private, "public": public, "port": AWG_PORT}
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(keys, indent=2))
        return keys

    def _build_conf(self, keys: dict, users: list, port: int, network: str, mtu: int) -> str:
        lines = [
            "[Interface]",
            f"PrivateKey = {keys['private']}",
            f"Address = {AWG_SERVER_IP}/24",
            f"ListenPort = {port}",
            f"MTU = {mtu}",
            "",
            "# Обфускация",
            f"Jc = {OBFUSCATION['Jc']}",
            f"Jmin = {OBFUSCATION['Jmin']}",
            f"Jmax = {OBFUSCATION['Jmax']}",
            f"S1 = {OBFUSCATION['S1']}",
            f"S2 = {OBFUSCATION['S2']}",
            f"H1 = {OBFUSCATION['H1']}",
            f"H2 = {OBFUSCATION['H2']}",
            f"H3 = {OBFUSCATION['H3']}",
            f"H4 = {OBFUSCATION['H4']}",
            "",
        ]

        for idx, user in enumerate(users):
            peer_ip = f"10.8.20.{idx + 2}"
            client_private = self._derive_key(user.uuid)
            client_public = subprocess.run(
                ["awg", "pubkey"], input=client_private,
                capture_output=True, text=True,
            ).stdout.strip()

            lines += [
                f"# Peer: {user.email}",
                "[Peer]",
                f"PublicKey = {client_public}",
                f"AllowedIPs = {peer_ip}/32",
                "",
            ]

        return "\n".join(lines)

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

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентский конфиг
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        keys = self._load_or_generate_keys()
        proto = state.protocols.get("amneziawg")
        config = proto.config if proto else {}
        port = config.get("port", AWG_PORT)
        mtus = {True: 1200, False: 1420}
        mtu = mtus[state.network.warp_enabled]

        server_ip = state.network.server_ip or state.network.domain or "SERVER_IP"

        client_private = self._derive_key(user.uuid)
        client_public = subprocess.run(
            ["awg", "pubkey"], input=client_private,
            capture_output=True, text=True,
        ).stdout.strip()

        dns = "1.1.1.1"
        if state.network.dnscrypt_enabled:
            dns = server_ip

        peer_idx = next((i for i, u in enumerate(state.users) if u.email == user.email and not u.blocked), 0)
        peer_ip = f"10.8.20.{peer_idx + 2}"

        return "\n".join([
            "[Interface]",
            f"PrivateKey = {client_private}",
            f"Address = {peer_ip}/32",
            f"DNS = {dns}",
            f"MTU = {mtu}",
            "",
            "# Обфускация",
            f"Jc = {OBFUSCATION['Jc']}",
            f"Jmin = {OBFUSCATION['Jmin']}",
            f"Jmax = {OBFUSCATION['Jmax']}",
            f"S1 = {OBFUSCATION['S1']}",
            f"S2 = {OBFUSCATION['S2']}",
            f"H1 = {OBFUSCATION['H1']}",
            f"H2 = {OBFUSCATION['H2']}",
            f"H3 = {OBFUSCATION['H3']}",
            f"H4 = {OBFUSCATION['H4']}",
            "",
            "[Peer]",
            f"PublicKey = {keys['public']}",
            f"Endpoint = {server_ip}:{port}",
            "AllowedIPs = 0.0.0.0/0",
            "PersistentKeepalive = 25",
        ])

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
        if AWG_CONF.exists():
            import re
            text = AWG_CONF.read_text()
            m = re.search(r"ListenPort\s*=\s*(\d+)", text)
            if m:
                return int(m.group(1))
        return AWG_PORT

    def traffic(self) -> dict[str, int]:
        if not AWG_CONF.exists():
            return {}

        r = subprocess.run(
            ["awg", "show", AWG_INTERFACE, "transfer"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return {}

        traffic: dict[str, int] = {}
        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                traffic[parts[0]] = int(parts[1]) + int(parts[2])
        return traffic

    def connected_peers(self) -> list[dict]:
        """Список подключённых пиров с деталями."""
        r = subprocess.run(
            ["awg", "show", AWG_INTERFACE],
            capture_output=True, text=True,
        )
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
        r = subprocess.run(
            ["awg-quick", "up", str(AWG_CONF)],
            capture_output=True, text=True, timeout=30,
        )
        return r.returncode == 0

    def _down(self) -> None:
        subprocess.run(
            ["awg-quick", "down", str(AWG_CONF)],
            capture_output=True,
        )

    def on_enable(self, state: AppState) -> None:
        self.configure(state)
        self._up()

    def on_disable(self, state: AppState) -> None:
        self._down()
