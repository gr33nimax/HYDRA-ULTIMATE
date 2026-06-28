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
        # Всегда предпочитаем реальный awg0.conf (переживает переустановки)
        existing = self._read_existing_keys()
        if existing:
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            STATE_FILE.write_text(json.dumps(existing, indent=2))
            return existing
        # Fallback: читаем из state или генерируем
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text())
            except Exception:
                pass
        # Генерация (только если ничего нет)
        private = self._awg("genkey").stdout.strip()
        keys = {"private": private, "port": AWG_PORT,
                "jc": OBFUSCATION["Jc"], "jmin": OBFUSCATION["Jmin"],
                "jmax": OBFUSCATION["Jmax"],
                "s1": OBFUSCATION["S1"], "s2": OBFUSCATION["S2"],
                "s3": 0, "s4": 0,
                "h1": f"{OBFUSCATION['H1']}-{OBFUSCATION['H1']+100000000}",
                "h2": f"{OBFUSCATION['H2']}-{OBFUSCATION['H2']+100000000}",
                "h3": f"{OBFUSCATION['H3']}-{OBFUSCATION['H3']+100000000}",
                "h4": f"{OBFUSCATION['H4']}-{OBFUSCATION['H4']+100000000}",
        }
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(keys, indent=2))
        return keys

    def _build_conf(self, keys: dict, users: list, port: int, network: str, mtu: int) -> str:
        server_ip = network.rsplit(".", 2)[0] + ".1"
        lines = [
            "[Interface]",
            f"PrivateKey = {keys['private']}",
            f"Address = {server_ip}/24",
            f"ListenPort = {port}",
            f"MTU = {mtu}",
            "",
            "# Обфускация",
            f"Jc = {keys.get('jc', OBFUSCATION['Jc'])}",
            f"Jmin = {keys.get('jmin', OBFUSCATION['Jmin'])}",
            f"Jmax = {keys.get('jmax', OBFUSCATION['Jmax'])}",
            f"S1 = {keys.get('s1', OBFUSCATION['S1'])}",
            f"S2 = {keys.get('s2', OBFUSCATION['S2'])}",
        ]
        if keys.get('s3'):
            lines.append(f"S3 = {keys['s3']}")
        if keys.get('s4'):
            lines.append(f"S4 = {keys['s4']}")
        for h in ('h1', 'h2', 'h3', 'h4'):
            if keys.get(h):
                lines.append(f"H{int(h[1])} = {keys[h]}")
        lines.append("")

        base = network.rsplit(".", 2)[0]
        for idx, user in enumerate(users):
            peer_ip = f"{base}.{idx + 2}"
            client_private = self._derive_key(user.uuid)
            client_public = self._awg("pubkey", _input=client_private).stdout.strip()

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
        keys = self._load_or_generate_keys()
        port = self._current_port()
        mtus = {True: 1200, False: 1420}
        mtu = mtus[state.network.warp_enabled]
        network = keys.get("network", AWG_NETWORK)
        base = network.rsplit(".", 2)[0]

        server_ip = state.network.server_ip or self._get_server_ip()
        client_private = self._derive_key(user.uuid)
        peer_idx = next((i for i, u in enumerate(state.users) if u.email == user.email and not u.blocked), 0)
        peer_ip = f"{base}.{peer_idx + 2}"

        dns = "1.1.1.1"
        if state.network.dnscrypt_enabled:
            dns = server_ip

        server_pub = self._awg("pubkey", _input=keys["private"]).stdout.strip()

        lines = [
            "[Interface]",
            f"PrivateKey = {client_private}",
            f"Address = {peer_ip}/32",
            f"DNS = {dns}",
            f"MTU = {mtu}",
            "",
            "# Обфускация",
            f"Jc = {keys.get('jc', OBFUSCATION['Jc'])}",
            f"Jmin = {keys.get('jmin', OBFUSCATION['Jmin'])}",
            f"Jmax = {keys.get('jmax', OBFUSCATION['Jmax'])}",
            f"S1 = {keys.get('s1', OBFUSCATION['S1'])}",
            f"S2 = {keys.get('s2', OBFUSCATION['S2'])}",
        ]
        if keys.get('s3'):
            lines.append(f"S3 = {keys['s3']}")
        if keys.get('s4'):
            lines.append(f"S4 = {keys['s4']}")
        for h in ('h1', 'h2', 'h3', 'h4'):
            if keys.get(h):
                lines.append(f"H{int(h[1])} = {keys[h]}")
        lines += [
            "",
            "[Peer]",
            f"PublicKey = {server_pub}",
            f"Endpoint = {server_ip}:{port}",
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
        if AWG_CONF.exists():
            import re
            text = AWG_CONF.read_text()
            m = re.search(r"ListenPort\s*=\s*(\d+)", text)
            if m:
                return int(m.group(1))
        return AWG_PORT

    def _read_existing_keys(self) -> dict | None:
        """Читает все параметры из существующего awg0.conf."""
        if not AWG_CONF.exists():
            return None
        import re
        text = AWG_CONF.read_text()
        priv = re.search(r"PrivateKey\s*=\s*(\S+)", text)
        port = re.search(r"ListenPort\s*=\s*(\d+)", text)
        addr = re.search(r"Address\s*=\s*(\S+)", text)
        jc = re.search(r"Jc\s*=\s*(\S+)", text)
        jmin = re.search(r"Jmin\s*=\s*(\S+)", text)
        jmax = re.search(r"Jmax\s*=\s*(\S+)", text)
        s1 = re.search(r"S1\s*=\s*(\S+)", text)
        s2 = re.search(r"S2\s*=\s*(\S+)", text)
        s3 = re.search(r"S3\s*=\s*(\S+)", text)
        s4 = re.search(r"S4\s*=\s*(\S+)", text)
        h1 = re.search(r"H1\s*=\s*(\S+)", text)
        h2 = re.search(r"H2\s*=\s*(\S+)", text)
        h3 = re.search(r"H3\s*=\s*(\S+)", text)
        h4 = re.search(r"H4\s*=\s*(\S+)", text)
        if priv:
            return {
                "private": priv.group(1),
                "port": int(port.group(1)) if port else AWG_PORT,
                "network": addr.group(1).rsplit(".", 1)[0] + ".0/24" if addr else AWG_NETWORK,
                "jc": int(jc.group(1)) if jc else OBFUSCATION["Jc"],
                "jmin": int(jmin.group(1)) if jmin else OBFUSCATION["Jmin"],
                "jmax": int(jmax.group(1)) if jmax else OBFUSCATION["Jmax"],
                "s1": int(s1.group(1)) if s1 else OBFUSCATION["S1"],
                "s2": int(s2.group(1)) if s2 else OBFUSCATION["S2"],
                "s3": int(s3.group(1)) if s3 else 0,
                "s4": int(s4.group(1)) if s4 else 0,
                "h1": h1.group(1) if h1 else "",
                "h2": h2.group(1) if h2 else "",
                "h3": h3.group(1) if h3 else "",
                "h4": h4.group(1) if h4 else "",
            }
        return None

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
        """Применяет пиров через awg addconf (работает на живом интерфейсе)."""
        if AWG_CONF.exists() and self._current_peers_config():
            r = subprocess.run(
                ["awg", "addconf", AWG_INTERFACE, str(self._peers_conf_file())],
                capture_output=True, timeout=10,
            )
            if r.returncode != 0:
                return False
        r = subprocess.run(
            ["ip", "link", "set", AWG_INTERFACE, "up"],
            capture_output=True, timeout=10,
        )
        return r.returncode == 0

    def _peers_conf_file(self) -> Path:
        return AWG_CONF_DIR / "peers.conf"

    def _current_peers_config(self) -> str | None:
        """Извлекает только [Peer] секции из awg0.conf."""
        if not AWG_CONF.exists():
            return None
        lines = AWG_CONF.read_text().splitlines()
        peers: list[str] = []
        in_peer = False
        for line in lines:
            if line.startswith("[Peer]"):
                in_peer = True
                peers.append(line)
            elif line.startswith("[Interface]"):
                in_peer = False
            elif in_peer and line.strip():
                peers.append(line)
        if peers:
            pf = self._peers_conf_file()
            pf.write_text("\n".join(peers) + "\n")
            return pf
        return None

    def _down(self) -> None:
        subprocess.run(["ip", "link", "set", AWG_INTERFACE, "down"], capture_output=True)

    def on_enable(self, state: AppState) -> None:
        self.configure(state)
        self._up()

    def on_disable(self, state: AppState) -> None:
        self._down()
