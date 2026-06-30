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
import ipaddress
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

DEFAULT_PORT = 51820
_KNOWN_SUBNETS = ["10.66.66.0/16", "172.17.0.0/16"]
_PREFERRED_SUBNETS = ["10.67.67.0/24"]
DEFAULT_OBFUSCATION = {
    "Jc": "4", "Jmin": "40", "Jmax": "70",
    "S1": "8", "S2": "72", "S3": "12", "S4": "20",
    "H1": "1", "H2": "2", "H3": "3", "H4": "4",
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

        existing_ips = self._existing_peer_ips()
        base, server_octet, network = self._network(state)
        iface_block = self._interface_block_for_network(base, server_octet)

        used = set(existing_ips.values()) | {server_octet}
        peer_map: dict[str, str] = {}
        blocks = [iface_block.rstrip(), ""]

        for user in state.users:
            if user.blocked:
                continue
            keys = self._get_or_create_keys(user, state)
            pub = keys["public_key"]
            psk = keys["preshared_key"]

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

    def _interface_block_for_network(self, base: str, server_octet: str) -> str:
        """Возвращает [Interface] с Address из выбранной AWG-сети."""
        block = self._interface_block()
        address = f"Address = {base}.{server_octet}/24"
        if re.search(r"^Address\s*=", block, re.M):
            return re.sub(r"^Address\s*=.*$", address, block, flags=re.M)
        return f"{block.rstrip()}\n{address}" if block.strip() else address

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

    def _network(self, state: AppState) -> tuple[str, str, str]:
        """('10.x.y', server_octet, '10.x.y.0/24') из state или awg0.conf."""
        network = self._resolve_network(state)
        base = network.rsplit(".", 1)[0]
        server_octet = "1"
        if AWG_CONF.exists():
            m = re.search(r"Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.(\d+)", AWG_CONF.read_text())
            if m and f"{m.group(1)}.{m.group(2)}.{m.group(3)}" == base:
                server_octet = m.group(4)
        return base, server_octet, network

    def _resolve_network(self, state: AppState) -> str:
        """Автовыбор свободной /24 подсети: из state → awg0.conf → сканирование."""
        ps = state.protocols.get("amneziawg")
        used = self._used_networks(state)
        if ps and ps.config.get("network") and self._is_network_free(ps.config["network"], used):
            return ps.config["network"]
        if AWG_CONF.exists():
            m = re.search(r"Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.", AWG_CONF.read_text())
            if m:
                network = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.0/24"
                if self._is_network_free(network, used):
                    if ps:
                        ps.config["network"] = network
                    return network
        for network in _PREFERRED_SUBNETS:
            if self._is_network_free(network, used):
                if ps:
                    ps.config["network"] = network
                return network
        for i in range(100, 256):
            for j in range(0, 256):
                candidate = ipaddress.ip_network(f"10.{i}.{j}.0/24", strict=False)
                if self._is_network_free(str(candidate), used):
                    net_str = str(candidate)
                    if ps:
                        ps.config["network"] = net_str
                    return net_str
        return "10.100.0.0/24"

    @staticmethod
    def _is_network_free(network: str, used: list[str]) -> bool:
        candidate = ipaddress.ip_network(network, strict=False)
        return not any(candidate.overlaps(ipaddress.ip_network(u, strict=False)) for u in used)

    @staticmethod
    def _used_networks(state: AppState) -> list[str]:
        used = list(_KNOWN_SUBNETS)
        for name, p in state.protocols.items():
            if name != "amneziawg" and p.config.get("network"):
                used.append(p.config["network"])
        return used

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

    # ── генерация и получение ключей пира ────────────────────────────────

    def _get_or_create_keys(self, user: User, state: AppState) -> dict:
        """Получает или создаёт ключи пользователя для AWG.
        
        Ключи хранятся в user.credentials["amneziawg"]:
          - private_key: приватный ключ (awg genkey)
          - public_key: публичный ключ (awg pubkey)
          - preshared_key: PSK (awg genpsk)
        """
        creds = user.credentials.get("amneziawg")
        if (creds 
            and "private_key" in creds 
            and "public_key" in creds 
            and "preshared_key" in creds):
            return creds
        
        # Генерируем новые ключи через awg
        priv_r = self._awg("genkey")
        if priv_r.returncode != 0:
            # Фоллбэк: генерация через wg если awg недоступен
            priv_r = subprocess.run(
                ["wg", "genkey"], capture_output=True, text=True
            )
        private_key = priv_r.stdout.strip()
        
        pub_r = self._awg("pubkey", _input=private_key)
        if pub_r.returncode != 0:
            pub_r = subprocess.run(
                ["wg", "pubkey"], input=private_key, 
                capture_output=True, text=True
            )
        public_key = pub_r.stdout.strip()
        
        psk_r = self._awg("genpsk")
        if psk_r.returncode != 0:
            psk_r = subprocess.run(
                ["wg", "genpsk"], capture_output=True, text=True
            )
        preshared_key = psk_r.stdout.strip()
        
        user.credentials["amneziawg"] = {
            "private_key": private_key,
            "public_key": public_key,
            "preshared_key": preshared_key,
        }
        
        from hydra.core.state import save_state
        save_state(state)
        
        return user.credentials["amneziawg"]

    def _server_pubkey(self) -> str:
        m = re.search(r"PrivateKey\s*=\s*(\S+)", self._interface_block())
        if not m:
            return ""
        r = self._awg("pubkey", _input=m.group(1))
        if r.returncode != 0:
            r = subprocess.run(
                ["wg", "pubkey"], input=m.group(1),
                capture_output=True, text=True
            )
            if r.returncode != 0:
                return ""
        return r.stdout.strip()

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        self._ensure_forward()
        self.configure(state)
        self.apply(state)

    def on_user_remove(self, user: User, state: AppState) -> None:
        self.configure(state)
        self.apply(state)

    def on_user_block(self, user: User, state: AppState) -> None:
        self.configure(state)
        self.apply(state)
        self._ensure_forward()

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентский конфиг
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        """Валидный клиентский .conf. Гарантирует, что пир есть на сервере."""
        if not AWG_CONF.exists():
            return ""

        keys = self._get_or_create_keys(user, state)
        pub = keys["public_key"]
        ip = self._existing_peer_ips().get(pub)
        if not ip:
            self.configure(state)
            self.apply(state)
            ip = self._existing_peer_ips().get(pub)
        if not ip:
            return ""
        base, _, _ = self._network(state)

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
            f"PrivateKey = {keys['private_key']}",
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
            f"PresharedKey = {keys['preshared_key']}",
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

        pub_to_email = {}
        for u in state.users:
            if not u.blocked:
                creds = u.credentials.get("amneziawg", {})
                pub = creds.get("public_key")
                if pub:
                    pub_to_email[pub] = u.email

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
        self._ensure_ip_forward()
        self.configure(state)
        self.apply(state)
        if not self._is_up():
            subprocess.run(["systemctl", "enable", "--now", AWG_UNIT], capture_output=True)
        self._ensure_nat(state)
        self._ensure_forward()

    def on_disable(self, state: AppState) -> None:
        self._remove_forward()
        self._remove_nat(state)
        subprocess.run(["systemctl", "stop", AWG_UNIT], capture_output=True)

    @staticmethod
    def _ensure_ip_forward():
        """Включает ip_forward, если выключен."""
        r = subprocess.run(["sysctl", "-n", "net.ipv4.ip_forward"], capture_output=True, text=True)
        if r.stdout.strip() != "1":
            subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
            subprocess.run(
                ["sed", "-i", "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g",
                 "/etc/sysctl.conf"], capture_output=True)
            subprocess.run(
                ["sh", "-c", "grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || "
                 "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf"], capture_output=True)

    def _ensure_nat(self, state: AppState):
        """Добавляет MASQUERADE для трафика AWG, если правила нет."""
        _, _, network = self._network(state)
        iface = self._wan_iface()
        r = subprocess.run(
            ["iptables", "-t", "nat", "-C", "POSTROUTING",
             "-s", network, "-o", iface, "-j", "MASQUERADE"],
            capture_output=True,
        )
        if r.returncode != 0:
            subprocess.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING",
                 "-s", network, "-o", iface, "-j", "MASQUERADE"],
                capture_output=True,
            )

    def _remove_nat(self, state: AppState):
        """Удаляет MASQUERADE для трафика AWG."""
        _, _, network = self._network(state)
        iface = self._wan_iface()
        subprocess.run(
            ["iptables", "-t", "nat", "-D", "POSTROUTING",
             "-s", network, "-o", iface, "-j", "MASQUERADE"],
            capture_output=True,
        )

    def _ensure_forward(self):
        """Добавляет ACCEPT в FORWARD и MSS clamping для AWG (иначе policy drop и MTU)."""
        for rule in (["-i", AWG_INTERFACE], ["-o", AWG_INTERFACE]):
            r = subprocess.run(
                ["iptables", "-C", "FORWARD", *rule, "-j", "ACCEPT"],
                capture_output=True,
            )
            if r.returncode != 0:
                subprocess.run(
                    ["iptables", "-I", "FORWARD", *rule, "-j", "ACCEPT"],
                    capture_output=True,
                )

        # MSS clamping для трафика от AWG в интернет (AWG оверхед > MTU ens3)
        for rule in (
            ["-i", AWG_INTERFACE, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN"],
        ):
            r = subprocess.run(
                ["iptables", "-t", "mangle", "-C", "FORWARD", *rule, "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                capture_output=True,
            )
            if r.returncode != 0:
                subprocess.run(
                    ["iptables", "-t", "mangle", "-I", "FORWARD", *rule, "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                    capture_output=True,
                )

    def _remove_forward(self):
        """Удаляет ACCEPT-правила AWG из FORWARD и mangle."""
        for rule in (["-i", AWG_INTERFACE], ["-o", AWG_INTERFACE]):
            subprocess.run(
                ["iptables", "-D", "FORWARD", *rule, "-j", "ACCEPT"],
                capture_output=True,
            )
        subprocess.run(
            ["iptables", "-t", "mangle", "-D", "FORWARD", "-i", AWG_INTERFACE, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            capture_output=True,
        )

    @staticmethod
    def _wan_iface() -> str:
        """Определяет интерфейс с default route (eth0 / ens3 / etc)."""
        r = subprocess.run(
            ["sh", "-c", "ip route show default | awk '{print $5}'"],
            capture_output=True, text=True,
        )
        return r.stdout.strip() or "eth0"

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
