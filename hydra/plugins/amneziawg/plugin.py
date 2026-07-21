"""
hydra/plugins/amneziawg/plugin.py — AmneziaWG 2.0 (wiresock kernel-модуль).

Контракт v2:
  • configure() — ЧИСТАЯ: генерит секции [Peer] в памяти, не трогает систему.
  • apply() — пишет awg0.conf / awg1.conf, применяет syncconf / поднимает интерфейс.
  • per-user: on_user_add/remove/block → пересборка + apply.
  • traffic(state) — строит pub→email из state.users.
  • connected_clients() — без PEER_MAP, использует self._peer_map.
"""
from __future__ import annotations

from hydra.core.host import HOST

import base64
import hashlib
import ipaddress
import re
import shutil
import subprocess
import time
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
    "Jc": "5", "Jmin": "50", "Jmax": "150",
    "S1": "40", "S2": "120", "S3": "0", "S4": "4",
    "H1": "1847293", "H2": "839102847", "H3": "49182736", "H4": "129384756",
}
OBFUSCATION_KEYS = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
                    "H1", "H2", "H3", "H4"]

# Мульти-профильный режим
AWG_CONF_1 = AWG_CONF_DIR / "awg1.conf"
AWG_INTERFACE_1 = "awg1"
AWG_UNIT_1 = "awg-quick@awg1"
DEFAULT_PORT_1 = 51821
OBFUSCATION_KEYS_EXTENDED = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
                             "H1", "H2", "H3", "H4", "I1"]


class AmneziaWGPlugin(BasePlugin):
    meta = PluginMeta(
        name="amneziawg",
        description="AmneziaWG 2.0: WireGuard с обфускацией (kernel-модуль)",
        category=PluginCategory.TRANSPORT,
        version="2.1.0",
        needs_domain=False,
    )

    def __init__(self):
        self._pending_conf: str | None = None
        self._pending_conf_1: str | None = None
        self._peer_map: dict[str, tuple[str, str]] = {}

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        """Устанавливает AmneziaWG через wiresock/amneziawg-install (AUTO_INSTALL)."""
        if self._installed():
            ready, detail = self._ensure_kernel_module()
            if not ready:
                print(f"  {detail}")
            return ready

        import os
        try:
            HOST.run(["rm", "-rf", str(AWG_INSTALL_DIR)], capture_output=True)
            r = HOST.run(
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
            HOST.run(
                ["bash", "amneziawg-install.sh"],
                cwd=str(AWG_INSTALL_DIR), env=env, timeout=900,
            )

            ready, detail = self._ensure_kernel_module()
            if not ready:
                print(f"  {detail}")
                return False
            return self._installed()
        except Exception as e:
            print(f"  install error: {e}")
            return False

    def uninstall(self) -> bool:
        """Полностью удаляет AmneziaWG: служба, пакеты, модуль, файлы."""
        HOST.run(["systemctl", "stop", AWG_UNIT], capture_output=True)
        HOST.run(["systemctl", "disable", AWG_UNIT], capture_output=True)
        HOST.run(["systemctl", "stop", AWG_UNIT_1], capture_output=True)
        HOST.run(["systemctl", "disable", AWG_UNIT_1], capture_output=True)
        HOST.run(["apt-get", "purge", "-y", "-qq",
            "amneziawg", "amneziawg-tools", "amneziawg-dkms"], capture_output=True)
        HOST.run(["modprobe", "-r", "amneziawg"], capture_output=True)
        HOST.run(["rm", "-rf",
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

        # Настраиваем awg0
        self._pending_conf = self._generate_config_for_iface(
            state,
            conf_path=AWG_CONF,
            profile_name="desktop",
            default_network="10.67.67.0/24"
        )
        
        # Настраиваем awg1 (если mobile активен)
        self._pending_conf_1 = None
        ps = state.protocols.get("amneziawg")
        if ps and "profiles" in ps.config and "mobile" in ps.config["profiles"]:
            self._pending_conf_1 = self._generate_config_for_iface(
                state,
                conf_path=AWG_CONF_1,
                profile_name="mobile",
                default_network="10.68.68.0/24"
            )

        ifaces = [AWG_INTERFACE]
        if self._pending_conf_1:
            ifaces.append(AWG_INTERFACE_1)

        return ConfigFragment(
            nft_tproxy_ifaces=ifaces,
        )

    def _generate_config_for_iface(self, state: AppState, conf_path: Path, profile_name: str, default_network: str) -> str | None:
        if not conf_path.exists():
            return None
        
        existing_ips = self._existing_peer_ips_for_conf(conf_path)
        base, server_octet, network = self._network_for_profile(state, conf_path, profile_name, default_network)
        iface_block = self._interface_block_for_conf(conf_path, base, server_octet)
        
        used = set(existing_ips.values()) | {server_octet}
        blocks = [iface_block.rstrip(), ""]
        
        for user in state.users:
            if user.blocked:
                continue
            
            keys = self._get_or_create_keys(user, state, profile=profile_name)
            pub = keys["public_key"]
            psk = keys["preshared_key"]
            
            if pub in existing_ips:
                octet = existing_ips[pub]
            else:
                octet = self._first_free(used)
                used.add(octet)
                
            self._peer_map[pub] = (user.email, "Mobile" if profile_name == "mobile" else "Desktop")
            
            blocks += [
                f"### {user.email}",
                "[Peer]",
                f"PublicKey = {pub}",
                f"PresharedKey = {psk}",
                f"AllowedIPs = {base}.{octet}/32",
                "",
            ]
            
        return "\n".join(blocks) + "\n"

    def apply(self, state: AppState) -> bool:
        """Пишет awg0.conf / awg1.conf и применяет syncconf / поднимает интерфейс."""
        ok = True
        if self._pending_conf:
            AWG_CONF.write_text(self._pending_conf, encoding="utf-8")
            AWG_CONF.chmod(0o600)
            ok = ok and self._apply_iface(AWG_INTERFACE, AWG_CONF, AWG_UNIT)
            
        if self._pending_conf_1:
            AWG_CONF_1.write_text(self._pending_conf_1, encoding="utf-8")
            AWG_CONF_1.chmod(0o600)
            ok = ok and self._apply_iface(AWG_INTERFACE_1, AWG_CONF_1, AWG_UNIT_1)
            
        return ok

    def snapshot(self, state: AppState):
        def read(path: Path):
            return path.read_bytes() if path.exists() else None
        return {
            "awg0": read(AWG_CONF),
            "awg1": read(AWG_CONF_1),
            "running0": self._is_up(),
            "running1": self._is_up_iface(AWG_INTERFACE_1),
        }

    def rollback(self, state: AppState, snapshot) -> bool:
        previous = snapshot or {}
        for key, path in (("awg0", AWG_CONF), ("awg1", AWG_CONF_1)):
            content = previous.get(key)
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
                path.chmod(0o600)
        ok = True
        for unit, running in ((AWG_UNIT, previous.get("running0")), (AWG_UNIT_1, previous.get("running1"))):
            command = ["systemctl", "restart", unit] if running else ["systemctl", "stop", unit]
            ok = HOST.run(command, capture_output=True).returncode == 0 and ok
        return ok

    def _apply_iface(self, interface: str, conf_path: Path, unit: str) -> bool:
        """Применяет conf без разрыва туннеля (или перезапускает)."""
        active_ip = self._active_ip_iface(interface)
        config_ip = None
        if conf_path.exists():
            m = re.search(r"Address\s*=\s*(\d+\.\d+\.\d+\.\d+)", conf_path.read_text(encoding="utf-8"))
            if m:
                config_ip = m.group(1)

        if active_ip and config_ip and active_ip != config_ip:
            HOST.run(["systemctl", "restart", unit], capture_output=True)
            return self._is_up_iface(interface)

        if self._is_up_iface(interface):
            r = HOST.run(
                ["bash", "-c", f"awg syncconf {interface} <(awg-quick strip {interface})"],
                capture_output=True, text=True,
            )
            return r.returncode == 0
        r = HOST.run(["systemctl", "start", unit], capture_output=True, text=True)
        if r.returncode != 0:
            fallback = HOST.run(["awg-quick", "up", interface], capture_output=True, text=True)
            if fallback.returncode != 0:
                detail = (fallback.stderr or fallback.stdout or r.stderr or r.stdout or "unknown error").strip()
                raise RuntimeError(f"failed to start {interface}: {detail}")
            r = fallback
        return r.returncode == 0

    def _apply(self) -> bool:
        return self._apply_iface(AWG_INTERFACE, AWG_CONF, AWG_UNIT)

    def _active_ip_iface(self, interface: str) -> str | None:
        import platform
        if platform.system() != "Linux":
            return None
        try:
            r = HOST.run(
                ["ip", "-o", "-4", "addr", "show", interface],
                capture_output=True, text=True, timeout=5
            )
            if not isinstance(r.stdout, str):
                return None
            if r.returncode != 0:
                return None
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)
            return m.group(1) if m else None
        except Exception:
            return None

    def _active_ip(self) -> str | None:
        return self._active_ip_iface(AWG_INTERFACE)

    # ── разбор конфигов ──────────────────────────────────────────────────

    def _interface_block_for_conf(self, conf_path: Path, base: str, server_octet: str) -> str:
        text = conf_path.read_text(encoding="utf-8") if conf_path.exists() else ""
        out: list[str] = []
        for line in text.splitlines():
            if line.strip() == "[Peer]" or line.strip().startswith("### "):
                break
            out.append(line)
        block = "\n".join(out)
        address = f"Address = {base}.{server_octet}/24"
        if re.search(r"^Address\s*=", block, re.M):
            return re.sub(r"^Address\s*=.*$", address, block, flags=re.M)
        return f"{block.rstrip()}\n{address}" if block.strip() else address

    def _interface_block(self) -> str:
        if AWG_CONF.exists():
            text = AWG_CONF.read_text(encoding="utf-8")
        else:
            text = ""
        out: list[str] = []
        for line in text.splitlines():
            if line.strip() == "[Peer]" or line.strip().startswith("### "):
                break
            out.append(line)
        return "\n".join(out)

    def _interface_block_for_network(self, base: str, server_octet: str) -> str:
        block = self._interface_block()
        address = f"Address = {base}.{server_octet}/24"
        if re.search(r"^Address\s*=", block, re.M):
            return re.sub(r"^Address\s*=.*$", address, block, flags=re.M)
        return f"{block.rstrip()}\n{address}" if block.strip() else address

    def _existing_peer_ips_for_conf(self, conf_path: Path) -> dict[str, str]:
        if not conf_path.exists():
            return {}
        result: dict[str, str] = {}
        cur_pub = None
        for line in conf_path.read_text(encoding="utf-8").splitlines():
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

    def _existing_peer_ips(self) -> dict[str, str]:
        return self._existing_peer_ips_for_conf(AWG_CONF)

    def _network_for_profile(self, state: AppState, conf_path: Path, profile_name: str, default_network: str) -> tuple[str, str, str]:
        ps = state.protocols.get("amneziawg")
        network = None
        used = self._used_networks(state)

        # An existing interface is authoritative. Silently moving it to a
        # "free" subnet during a routine apply invalidates every previously
        # exported client profile. Conflict avoidance belongs to profile
        # creation, not reconciliation of an installed interface.
        if conf_path.exists():
            m = re.search(r"Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.", conf_path.read_text(encoding="utf-8"))
            if m:
                network = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.0/24"

        if not network and ps and "profiles" in ps.config and profile_name in ps.config["profiles"]:
            candidate = ps.config["profiles"][profile_name].get("network")
            if candidate and self._is_network_free(candidate, used):
                network = candidate
            
        if not network:
            network = default_network
            
        base = network.rsplit(".", 1)[0]
        server_octet = "1"
        if conf_path.exists():
            m = re.search(r"Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.(\d+)", conf_path.read_text(encoding="utf-8"))
            if m and f"{m.group(1)}.{m.group(2)}.{m.group(3)}" == base:
                server_octet = m.group(4)
        return base, server_octet, network

    def _network(self, state: AppState) -> tuple[str, str, str]:
        return self._network_for_profile(state, AWG_CONF, "desktop", "10.67.67.0/24")

    def _resolve_network(self, state: AppState) -> str:
        """Автовыбор свободной /24 подсети: из state → awg0.conf → сканирование."""
        ps = state.protocols.get("amneziawg")
        used = self._used_networks(state)
        if ps and ps.config.get("network") and self._is_network_free(ps.config["network"], used):
            return ps.config["network"]
        if AWG_CONF.exists():
            m = re.search(r"Address\s*=\s*(\d+)\.(\d+)\.(\d+)\.", AWG_CONF.read_text(encoding="utf-8"))
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
    def _is_network_free(network: object, used: list[str]) -> bool:
        """Return whether a valid CIDR does not overlap known valid networks."""
        try:
            candidate = ipaddress.ip_network(str(network), strict=False)
        except (TypeError, ValueError):
            return False
        for raw_network in used:
            try:
                occupied = ipaddress.ip_network(str(raw_network), strict=False)
            except (TypeError, ValueError):
                # Older plugins reuse the ``network`` key for transport modes
                # such as "tcp", "quic" and "both". They are not subnets.
                continue
            if candidate.overlaps(occupied):
                return False
        return True

    @staticmethod
    def _used_networks(state: AppState) -> list[str]:
        candidates: list[object] = list(_KNOWN_SUBNETS)
        for name, p in state.protocols.items():
            if name != "amneziawg" and p.config.get("network"):
                candidates.append(p.config["network"])
        used: list[str] = []
        for raw_network in candidates:
            try:
                network = ipaddress.ip_network(str(raw_network), strict=False)
            except (TypeError, ValueError):
                continue
            normalized = str(network)
            if normalized not in used:
                used.append(normalized)
        return used

    @staticmethod
    def _first_free(used: set[str]) -> str:
        for i in range(2, 255):
            if str(i) not in used:
                return str(i)
        return "254"

    def _obfuscation_for_conf(self, conf_path: Path) -> dict[str, str]:
        text = conf_path.read_text(encoding="utf-8") if conf_path.exists() else ""
        out_block: list[str] = []
        for line in text.splitlines():
            if line.strip() == "[Peer]" or line.strip().startswith("### "):
                break
            out_block.append(line)
        interface_block = "\n".join(out_block)
        
        out: dict[str, str] = {}
        for key in OBFUSCATION_KEYS_EXTENDED:
            m = re.search(rf"^{key}\s*=\s*(\S+)", interface_block, re.M)
            if m:
                out[key] = m.group(1)
        return out

    def _obfuscation(self) -> dict[str, str]:
        return self._obfuscation_for_conf(AWG_CONF)

    # ── генерация и получение ключей пира ────────────────────────────────

    def _get_or_create_keys(self, user: User, state: AppState, profile: str = None) -> dict:
        """Получает или создаёт ключи пользователя для AWG."""
        profile_name = profile if profile else "desktop"
        cred_key = f"amneziawg_{profile_name}" if profile_name != "desktop" else "amneziawg"
        creds = user.credentials.get(cred_key)
        if (creds 
            and "private_key" in creds 
            and "public_key" in creds 
            and "preshared_key" in creds):
            return creds
        
        priv_r = self._awg("genkey")
        if priv_r.returncode != 0:
            priv_r = HOST.run(
                ["wg", "genkey"], capture_output=True, text=True
            )
        private_key = priv_r.stdout.strip()
        
        pub_r = self._awg("pubkey", _input=private_key)
        if pub_r.returncode != 0:
            pub_r = HOST.run(
                ["wg", "pubkey"], input=private_key, 
                capture_output=True, text=True
            )
        public_key = pub_r.stdout.strip()
        
        psk_r = self._awg("genpsk")
        if psk_r.returncode != 0:
            psk_r = HOST.run(
                ["wg", "genpsk"], capture_output=True, text=True
            )
        preshared_key = psk_r.stdout.strip()
        
        user.credentials[cred_key] = {
            "private_key": private_key,
            "public_key": public_key,
            "preshared_key": preshared_key,
        }
        
        return user.credentials[cred_key]

    def _server_pubkey_for_conf(self, conf_path: Path) -> str:
        text = conf_path.read_text(encoding="utf-8") if conf_path.exists() else ""
        out: list[str] = []
        for line in text.splitlines():
            if line.strip() == "[Peer]" or line.strip().startswith("### "):
                break
            out.append(line)
        interface_block = "\n".join(out)
        
        m = re.search(r"PrivateKey\s*=\s*(\S+)", interface_block)
        if not m:
            return ""
        r = self._awg("pubkey", _input=m.group(1))
        if r.returncode != 0:
            r = HOST.run(
                ["wg", "pubkey"], input=m.group(1),
                capture_output=True, text=True
            )
            if r.returncode != 0:
                return ""
        return r.stdout.strip()

    def _server_pubkey(self) -> str:
        return self._server_pubkey_for_conf(AWG_CONF)

    # ═════════════════════════════════════════════════════════════════════
    #  Профили
    # ═════════════════════════════════════════════════════════════════════

    def get_profiles(self, state: AppState) -> list[dict]:
        """Возвращает список активных профилей."""
        ps = state.protocols.get("amneziawg")
        if ps and "profiles" in ps.config:
            res = []
            for name, prof in ps.config["profiles"].items():
                res.append({
                    "name": name,
                    "label": "Mobile" if name == "mobile" else "Desktop",
                    "interface": prof["interface"],
                    "unit": f"awg-quick@{prof['interface']}",
                    "port": prof["port"],
                    "preset": prof["preset"],
                    "network": prof["network"],
                    "obfuscation": prof["obfuscation"],
                })
            return res
        
        port = self._current_port()
        _, _, network = self._network(state)
        obf = self._obfuscation()
        return [{
            "name": "desktop",
            "label": "Desktop",
            "interface": AWG_INTERFACE,
            "unit": AWG_UNIT,
            "port": port,
            "preset": "default",
            "network": network,
            "obfuscation": obf,
        }]

    def add_profile(self, name: str, preset: str, state: AppState) -> bool:
        """Добавляет второй AWG-профиль (mobile)."""
        if name != "mobile":
            return False
        
        ps = state.protocols.get("amneziawg")
        if not ps:
            return False
        
        if "profiles" not in ps.config:
            current_profiles = {}
            port_0 = self._current_port()
            _, _, network_0 = self._network(state)
            obf_0 = self._obfuscation()
            privkey_0 = ""
            if AWG_CONF.exists():
                m = re.search(r"PrivateKey\s*=\s*(\S+)", AWG_CONF.read_text(encoding="utf-8"))
                if m:
                    privkey_0 = m.group(1)
            current_profiles["desktop"] = {
                "interface": AWG_INTERFACE,
                "port": port_0,
                "preset": "default",
                "network": network_0,
                "server_private_key": privkey_0,
                "obfuscation": obf_0,
            }
            ps.config["profiles"] = current_profiles

        if "mobile" in ps.config["profiles"]:
            return True
        
        port_1 = DEFAULT_PORT_1
        used_nets = self._used_networks(state)
        desktop_net = ps.config["profiles"]["desktop"]["network"]
        if desktop_net not in used_nets:
            used_nets.append(desktop_net)
        
        network_1 = "10.68.68.0/24"
        if not self._is_network_free(network_1, used_nets):
            for i in range(100, 256):
                for j in range(0, 256):
                    candidate = f"10.{i}.{j}.0/24"
                    if self._is_network_free(candidate, used_nets):
                        network_1 = candidate
                        break
                else:
                    continue
                break
        
        priv_r = self._awg("genkey")
        if priv_r.returncode != 0:
            priv_r = HOST.run(["wg", "genkey"], capture_output=True, text=True)
        server_private_key = priv_r.stdout.strip()
        
        from hydra.plugins.amneziawg.presets import generate_params, LEGACY_PRESET_MAP, STRATEGIES
        strategy = "mobile"
        carrier = None
        if ":" in preset:
            strategy, carrier = preset.split(":", 1)
            if carrier == "generic":
                carrier = None
        else:
            if preset in STRATEGIES:
                strategy = preset
            elif preset in LEGACY_PRESET_MAP:
                strategy, carrier = LEGACY_PRESET_MAP[preset]
            else:
                strategy = preset
        obf_1 = generate_params(strategy=strategy, carrier=carrier)
        
        base = network_1.rsplit(".", 1)[0]
        lines = [
            "[Interface]",
            f"PrivateKey = {server_private_key}",
            f"Address = {base}.1/24",
            f"ListenPort = {port_1}",
            "MTU = 1280",
            f"PostUp = iptables -I FORWARD -i {AWG_INTERFACE_1} -j ACCEPT; iptables -I FORWARD -o {AWG_INTERFACE_1} -j ACCEPT; iptables -t mangle -I FORWARD -i {AWG_INTERFACE_1} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
            f"PostDown = iptables -D FORWARD -i {AWG_INTERFACE_1} -j ACCEPT; iptables -D FORWARD -o {AWG_INTERFACE_1} -j ACCEPT; iptables -t mangle -D FORWARD -i {AWG_INTERFACE_1} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        ]
        for k, v in obf_1.items():
            if v != "":
                lines.append(f"{k} = {v}")
        lines.append("")
        
        for user in state.users:
            if user.blocked:
                continue
            
            keys_1 = self._get_or_create_keys(user, state, profile="mobile")
            pub_1 = keys_1["public_key"]
            psk_1 = keys_1["preshared_key"]
            
            desktop_ips = self._existing_peer_ips()
            keys_0 = user.credentials.get("amneziawg", {})
            pub_0 = keys_0.get("public_key")
            octet = None
            if pub_0 and pub_0 in desktop_ips:
                octet = desktop_ips[pub_0]
            if not octet:
                octet = "2"
            
            lines.extend([
                f"### {user.email}",
                "[Peer]",
                f"PublicKey = {pub_1}",
                f"PresharedKey = {psk_1}",
                f"AllowedIPs = {base}.{octet}/32",
                "",
            ])
            
        AWG_CONF_1.parent.mkdir(parents=True, exist_ok=True)
        AWG_CONF_1.write_text("\n".join(lines) + "\n", encoding="utf-8")
        AWG_CONF_1.chmod(0o600)
        
        ps.config["profiles"]["mobile"] = {
            "interface": AWG_INTERFACE_1,
            "port": port_1,
            "preset": preset,
            "network": network_1,
            "server_private_key": server_private_key,
            "obfuscation": obf_1,
        }
        from hydra.core.state import save_state
        save_state(state)
        
        HOST.run(["systemctl", "enable", "--now", AWG_UNIT_1], capture_output=True)
        
        from hydra.core.orchestrator import apply_config
        apply_config(state)
        return True

    def remove_profile(self, name: str, state: AppState) -> bool:
        """Удаляет профиль (останавливает интерфейс, удаляет конфиг)."""
        if name != "mobile":
            return False
        
        ps = state.protocols.get("amneziawg")
        if not ps or "profiles" not in ps.config or "mobile" not in ps.config["profiles"]:
            return False
        
        HOST.run(["systemctl", "stop", AWG_UNIT_1], capture_output=True)
        HOST.run(["systemctl", "disable", AWG_UNIT_1], capture_output=True)
        
        if AWG_CONF_1.exists():
            AWG_CONF_1.unlink()
            
        del ps.config["profiles"]["mobile"]
        
        for user in state.users:
            if "amneziawg_mobile" in user.credentials:
                del user.credentials["amneziawg_mobile"]
                
        from hydra.core.state import save_state
        save_state(state)
        
        from hydra.core.orchestrator import apply_config
        apply_config(state)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Ротация обфускации
    # ═════════════════════════════════════════════════════════════════════

    def rotate_obfuscation(self, state: AppState, 
                            profile: str = None, 
                            preset: str = None) -> bool:
        """Ротация параметров обфускации без downtime."""
        profile_name = profile if profile else "desktop"
        
        if profile_name == "mobile":
            conf_path = AWG_CONF_1
            interface = AWG_INTERFACE_1
            unit = AWG_UNIT_1
        else:
            conf_path = AWG_CONF
            interface = AWG_INTERFACE
            unit = AWG_UNIT
            
        if not conf_path.exists():
            return False
            
        ps = state.protocols.get("amneziawg")
        if not preset:
            if ps and "profiles" in ps.config and profile_name in ps.config["profiles"]:
                preset = ps.config["profiles"][profile_name].get("preset", "default")
            else:
                preset = "default"
                
        from hydra.plugins.amneziawg.presets import generate_params, LEGACY_PRESET_MAP, STRATEGIES
        strategy = "wired"
        carrier = None
        if ":" in preset:
            strategy, carrier = preset.split(":", 1)
            if carrier == "generic":
                carrier = None
        else:
            if preset in STRATEGIES:
                strategy = preset
            elif preset in LEGACY_PRESET_MAP:
                strategy, carrier = LEGACY_PRESET_MAP[preset]
            else:
                strategy = preset
        new_params = generate_params(strategy=strategy, carrier=carrier)
        
        text = conf_path.read_text(encoding="utf-8")
        
        keys_to_update = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]
        for key in keys_to_update:
            val = new_params.get(key)
            if val is not None:
                if re.search(rf"^{key}\s*=", text, re.M):
                    text = re.sub(rf"^{key}\s*=.*$", f"{key} = {val}", text, flags=re.M)
                else:
                    if "[Peer]" in text:
                        text = text.replace("[Peer]", f"{key} = {val}\n\n[Peer]", 1)
                    else:
                        text = text.rstrip() + f"\n{key} = {val}\n"
                        
        i1_val = new_params.get("I1", "")
        if i1_val:
            if re.search(r"^I1\s*=", text, re.M):
                text = re.sub(r"^I1\s*=.*$", f"I1 = {i1_val}", text, flags=re.M)
            else:
                if "[Peer]" in text:
                    text = text.replace("[Peer]", f"I1 = {i1_val}\n\n[Peer]", 1)
                else:
                    text = text.rstrip() + f"\nI1 = {i1_val}\n"
        else:
            text = re.sub(r"^I1\s*=.*\n?", "", text, flags=re.M)
            
        conf_path.write_text(text, encoding="utf-8")
        conf_path.chmod(0o600)
        
        r = HOST.run(
            ["bash", "-c", f"awg syncconf {interface} <(awg-quick strip {interface})"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            HOST.run(["systemctl", "restart", unit], capture_output=True)
            
        if ps:
            if "profiles" not in ps.config:
                ps.config["profiles"] = {}
            if profile_name not in ps.config["profiles"]:
                ps.config["profiles"][profile_name] = {
                    "interface": interface,
                    "port": 51820 if profile_name == "desktop" else 51821,
                    "network": "10.67.67.0/24" if profile_name == "desktop" else "10.68.68.0/24",
                }
            ps.config["profiles"][profile_name]["preset"] = preset
            ps.config["profiles"][profile_name]["obfuscation"] = new_params
            from hydra.core.state import save_state
            save_state(state)
            
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
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

    def generate_client_config(self, user: User, state: AppState, profile: str = None) -> str:
        """Валидный клиентский .conf. Гарантирует, что пир есть на сервере."""
        profile_name = profile if profile else "desktop"
        if profile_name == "mobile":
            conf_path = AWG_CONF_1
        else:
            conf_path = AWG_CONF

        if not conf_path.exists():
            return ""

        keys = self._get_or_create_keys(user, state, profile=profile_name)
        pub = keys["public_key"]
        ip = self._existing_peer_ips_for_conf(conf_path).get(pub)
        if not ip:
            self.configure(state)
            self.apply(state)
            ip = self._existing_peer_ips_for_conf(conf_path).get(pub)
        if not ip:
            return ""
        
        base, _, _ = self._network_for_profile(
            state, conf_path, profile_name,
            "10.67.67.0/24" if profile_name == "desktop" else "10.68.68.0/24"
        )

        server_pub = self._server_pubkey_for_conf(conf_path)
        
        if profile_name == "mobile":
            port = DEFAULT_PORT_1
            ps = state.protocols.get("amneziawg")
            if ps and "profiles" in ps.config and "mobile" in ps.config["profiles"]:
                port = ps.config["profiles"]["mobile"].get("port", DEFAULT_PORT_1)
        else:
            port = self._current_port()

        endpoint = state.network.server_ip or self._params().get("SERVER_PUB_IP") or self._public_ip()
        obf = self._obfuscation_for_conf(conf_path)

        mtu_m = re.search(r"^MTU\s*=\s*(\d+)", self._interface_block_for_conf(conf_path, base, "1"), re.M)
        mtu = mtu_m.group(1) if (mtu_m and mtu_m.group(1) != "1420") else "1376"

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
        for key in OBFUSCATION_KEYS_EXTENDED:
            if key in obf and obf[key] != "":
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

    def client_link(self, user: User, state: AppState, profile: str = None) -> str:
        """Ссылка wg:// для AmneziaWG-клиентов на базе клиентского конфига."""
        profile_name = profile if profile else "desktop"
        conf = self.generate_client_config(user, state, profile=profile_name)
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
        for key in OBFUSCATION_KEYS_EXTENDED:
            v = f(key)
            if v:
                params.append(f"{key.lower()}={v}")
        if f("PublicKey"):    params.append(f"public_key={f('PublicKey')}")
        if f("PresharedKey"): params.append(f"pre_shared_key={f('PresharedKey')}")
        params.append("persistent_keepalive_interval=25")
        
        label = "AWG Mobile" if profile_name == "mobile" else "AWG Desktop"
        return f"wg://{host}:{port}?{'&'.join(params)}#{user.email}%20{label}"

    def amnezia_link(self, user: User, state: AppState, profile: str = None) -> str:
        """Ссылка vpn:// для официального клиента AmneziaVPN (импорт одним тапом)."""
        import json
        import zlib
        
        profile_name = profile if profile else "desktop"
        conf = self.generate_client_config(user, state, profile=profile_name)
        if not conf:
            return ""

        if profile_name == "mobile":
            conf_path = AWG_CONF_1
        else:
            conf_path = AWG_CONF

        if not conf_path.exists():
            return ""

        keys = self._get_or_create_keys(user, state, profile=profile_name)
        pub = keys["public_key"]
        ip = self._existing_peer_ips_for_conf(conf_path).get(pub)
        if not ip:
            return ""

        base, _, _ = self._network_for_profile(
            state, conf_path, profile_name,
            "10.67.67.0/24" if profile_name == "desktop" else "10.68.68.0/24"
        )
        server_pub = self._server_pubkey_for_conf(conf_path)

        if profile_name == "mobile":
            port = DEFAULT_PORT_1
            ps = state.protocols.get("amneziawg")
            if ps and "profiles" in ps.config and "mobile" in ps.config["profiles"]:
                port = ps.config["profiles"]["mobile"].get("port", DEFAULT_PORT_1)
        else:
            port = self._current_port()

        endpoint = state.network.server_ip or self._params().get("SERVER_PUB_IP") or self._public_ip()
        obf = self._obfuscation_for_conf(conf_path)

        mtu_m = re.search(r"^MTU\s*=\s*(\d+)", self._interface_block_for_conf(conf_path, base, "1"), re.M)
        mtu = mtu_m.group(1) if (mtu_m and mtu_m.group(1) != "1420") else "1376"

        inner = {
            "H1": str(obf.get("H1", "1")),
            "H2": str(obf.get("H2", "2")),
            "H3": str(obf.get("H3", "3")),
            "H4": str(obf.get("H4", "4")),
            "Jc": str(obf.get("Jc", "4")),
            "Jmin": str(obf.get("Jmin", "40")),
            "Jmax": str(obf.get("Jmax", "70")),
            "S1": str(obf.get("S1", "0")),
            "S2": str(obf.get("S2", "0")),
            "S3": str(obf.get("S3", "0")),
            "S4": str(obf.get("S4", "0")),
        }
        for k in ("I1", "I2", "I3", "I4", "I5"):
            v = obf.get(k, "")
            if v:
                inner[k] = str(v)

        inner["allowed_ips"] = ["0.0.0.0/0"]
        inner["client_ip"] = f"{base}.{ip}"
        inner["client_ipv6"] = ""
        inner["client_priv_key"] = keys["private_key"]
        if keys.get("preshared_key"):
            inner["psk_key"] = keys["preshared_key"]
        inner["config"] = conf
        inner["hostName"] = endpoint
        inner["mtu"] = str(mtu)
        inner["persistent_keep_alive"] = "25"
        inner["port"] = port
        inner["server_pub_key"] = server_pub

        inner_json = json.dumps(inner, ensure_ascii=False)
        inner_b64 = base64.b64encode(inner_json.encode("utf-8")).decode("ascii")

        outer = {
            "containers": [{
                "awg": {
                    "isThirdPartyConfig": True,
                    "last_config": inner_json,
                    "port": str(port),
                    "protocol_version": "2",
                    "transport_proto": "udp",
                },
                "container": "amnezia-awg",
            }],
            "defaultContainer": "amnezia-awg",
        }
        outer_json = json.dumps(outer, ensure_ascii=False)
        outer_b64 = base64.b64encode(outer_json.encode("utf-8")).decode("ascii")

        return f"vpn://free/{outer_b64}/{inner_b64}"

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        from hydra.core.state import load_state

        runtime_installed = self._installed()
        installed = False
        enabled = False
        try:
            state = load_state()
            protocol = state.protocols.get("amneziawg")
            if protocol:
                installed = bool(protocol.installed and runtime_installed)
                enabled = bool(protocol.enabled and installed)
        except Exception:
            pass
        port = 0
        if installed:
            try:
                port = self._current_port()
            except Exception:
                pass
        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=enabled and (self._is_up() or self._is_up_iface(AWG_INTERFACE_1)),
            port=port,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        """{email: bytes}. Строит pubkey→email из state.users."""
        if not self._installed():
            return {}

        pub_to_email = {}
        for u in state.users:
            if not u.blocked:
                creds_d = u.credentials.get("amneziawg", {})
                pub_d = creds_d.get("public_key")
                if pub_d:
                    pub_to_email[pub_d] = u.email
                creds_m = u.credentials.get("amneziawg_mobile", {})
                pub_m = creds_m.get("public_key")
                if pub_m:
                    pub_to_email[pub_m] = u.email

        result: dict[str, int] = {}
        
        interfaces = [AWG_INTERFACE]
        if self._is_up_iface(AWG_INTERFACE_1):
            interfaces.append(AWG_INTERFACE_1)
            
        for iface in interfaces:
            r = self._awg("show", iface, "transfer")
            if r.returncode != 0:
                continue
            for line in r.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    pub, rx, tx = parts[0], parts[1], parts[2]
                    email = pub_to_email.get(pub)
                    if email:
                        result[email] = result.get(email, 0) + int(rx) + int(tx)
        return result

    def connected_clients(self, state: AppState | None = None) -> list[dict]:
        """Active peers, grouped by user across desktop/mobile profiles."""
        if not self._installed():
            return []

        if state:
            peer_map = {}
            for u in state.users:
                creds_d = u.credentials.get("amneziawg", {})
                pub_d = creds_d.get("public_key")
                if pub_d:
                    peer_map[pub_d] = u.email
                creds_m = u.credentials.get("amneziawg_mobile", {})
                pub_m = creds_m.get("public_key")
                if pub_m:
                    peer_map[pub_m] = u.email
            self._peer_map = peer_map

        interfaces = [AWG_INTERFACE]
        if self._is_up_iface(AWG_INTERFACE_1):
            interfaces.append(AWG_INTERFACE_1)

        now = int(time.time())
        active_window = 180
        grouped: dict[str, dict] = {}
        for iface in interfaces:
            r = self._awg("show", iface, "dump")
            if r.returncode != 0:
                continue
            for line in r.stdout.strip().splitlines()[1:]:
                p = line.split("\t")
                if len(p) < 8:
                    continue
                pub = p[0]
                handshake = int(p[4]) if p[4].isdigit() else 0
                
                email = self._peer_map.get(pub, "?")
                if isinstance(email, tuple):
                    email = email[0]
                if email == "?" or handshake <= 0 or now - handshake > active_window:
                    continue

                profile = "Mobile" if iface == AWG_INTERFACE_1 else "Desktop"
                item = grouped.setdefault(email, {
                    "email": email,
                    "profiles": [],
                    "endpoint": p[2],
                    "last_handshake": handshake,
                    "online": True,
                    "rx": 0,
                    "tx": 0,
                    "traffic_scope": "interface",
                })
                item["profiles"].append(profile)
                item["last_handshake"] = max(item["last_handshake"], handshake)
                item["rx"] += int(p[5]) if p[5].isdigit() else 0
                item["tx"] += int(p[6]) if p[6].isdigit() else 0
        return list(grouped.values())

    # ═════════════════════════════════════════════════════════════════════
    #  Управление интерфейсом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        ready, detail = self._ensure_kernel_module()
        if not ready:
            raise RuntimeError(detail)
        self._ensure_ip_forward()

        # Hardware tuning при первом включении
        ps = state.protocols.get("amneziawg")
        if ps and not ps.config.get("hw_tuned"):
            try:
                from hydra.plugins.amneziawg.tuning import hw_tune_all
                hw_tune_all()
                ps.config["hw_tuned"] = True
                from hydra.core.state import save_state
                save_state(state)
            except Exception:
                pass

        try:
            self._remove_nat(state)
        except Exception:
            pass

        profiles = self.get_profiles(state)
        for p in profiles:
            unit = p.get("unit", AWG_UNIT)
            if not self._is_up_iface(p["interface"]):
                HOST.run(["systemctl", "enable", "--now", unit], capture_output=True)

        self._ensure_forward()

    def on_disable(self, state: AppState) -> None:
        self._remove_forward()

        try:
            self._remove_nat(state)
        except Exception:
            pass

        HOST.run(["systemctl", "stop", AWG_UNIT], capture_output=True)
        HOST.run(["systemctl", "stop", AWG_UNIT_1], capture_output=True)

    @staticmethod
    def _ensure_ip_forward():
        """Включает ip_forward, если выключен."""
        r = HOST.run(["sysctl", "-n", "net.ipv4.ip_forward"], capture_output=True, text=True)
        if r.stdout.strip() != "1":
            HOST.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], capture_output=True)
            HOST.run(
                ["sed", "-i", "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g",
                 "/etc/sysctl.conf"], capture_output=True)
            HOST.run(
                ["sh", "-c", "grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || "
                 "echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf"], capture_output=True)

    def _ensure_nat(self, state: AppState):
        """Добавляет MASQUERADE для трафика AWG, если правила нет."""
        _, _, network = self._network(state)
        iface = self._wan_iface()
        r = HOST.run(
            ["iptables", "-t", "nat", "-C", "POSTROUTING",
             "-s", network, "-o", iface, "-j", "MASQUERADE"],
            capture_output=True,
        )
        if r.returncode != 0:
            HOST.run(
                ["iptables", "-t", "nat", "-A", "POSTROUTING",
                 "-s", network, "-o", iface, "-j", "MASQUERADE"],
                capture_output=True,
            )

    def _remove_nat(self, state: AppState):
        """Удаляет MASQUERADE для трафика AWG."""
        _, _, network = self._network(state)
        iface = self._wan_iface()
        HOST.run(
            ["iptables", "-t", "nat", "-D", "POSTROUTING",
             "-s", network, "-o", iface, "-j", "MASQUERADE"],
            capture_output=True,
        )

    def _ensure_forward(self):
        """Добавляет ACCEPT в FORWARD и MSS clamping для AWG (иначе policy drop и MTU)."""
        interfaces = [AWG_INTERFACE]
        if AWG_CONF_1.exists():
            interfaces.append(AWG_INTERFACE_1)

        for iface in interfaces:
            for rule in (["-i", iface], ["-o", iface]):
                r = HOST.run(
                    ["iptables", "-C", "FORWARD", *rule, "-j", "ACCEPT"],
                    capture_output=True,
                )
                if r.returncode != 0:
                    HOST.run(
                        ["iptables", "-I", "FORWARD", *rule, "-j", "ACCEPT"],
                        capture_output=True,
                    )

            rule = ["-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN"]
            r = HOST.run(
                ["iptables", "-t", "mangle", "-C", "FORWARD", *rule, "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                capture_output=True,
            )
            if r.returncode != 0:
                HOST.run(
                    ["iptables", "-t", "mangle", "-I", "FORWARD", *rule, "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                    capture_output=True,
                )

    def _remove_forward(self):
        """Удаляет ACCEPT-правила AWG из FORWARD и mangle."""
        interfaces = [AWG_INTERFACE]
        if AWG_CONF_1.exists():
            interfaces.append(AWG_INTERFACE_1)
            
        for iface in interfaces:
            for rule in (["-i", iface], ["-o", iface]):
                HOST.run(
                    ["iptables", "-D", "FORWARD", *rule, "-j", "ACCEPT"],
                    capture_output=True,
                )
            HOST.run(
                ["iptables", "-t", "mangle", "-D", "FORWARD", "-i", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
                capture_output=True,
            )

    @staticmethod
    def _wan_iface() -> str:
        """Определяет интерфейс с default route (eth0 / ens3 / etc)."""
        r = HOST.run(
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

    @staticmethod
    def _ensure_kernel_module() -> tuple[bool, str]:
        """Load the module for the running kernel and explain reboot mismatches."""
        loaded = HOST.run(["lsmod"], capture_output=True, text=True)
        if loaded.returncode == 0 and "amneziawg" in loaded.stdout:
            return True, ""

        result = HOST.run(["modprobe", "amneziawg"], capture_output=True, text=True)
        if result.returncode == 0:
            return True, ""

        import platform
        running_kernel = platform.release()
        dkms = (
            HOST.run(["dkms", "status"], capture_output=True, text=True)
            if HOST.which("dkms") else None
        )
        other_kernels = []
        if dkms is not None and dkms.returncode == 0:
            for line in dkms.stdout.splitlines():
                if "amneziawg" in line and ": installed" in line and running_kernel not in line:
                    parts = [part.strip() for part in line.split(",")]
                    if len(parts) >= 2:
                        other_kernels.append(parts[1])
        if other_kernels:
            built = ", ".join(sorted(set(other_kernels)))
            return False, (
                f"Модуль AmneziaWG собран для ядра {built}, но сейчас запущено {running_kernel}. "
                "Перезагрузите сервер и повторите включение."
            )

        error = (result.stderr or result.stdout or "module is unavailable").strip()
        return False, f"Модуль AmneziaWG недоступен для ядра {running_kernel}: {error}"

    def _is_up(self) -> bool:
        import platform
        if platform.system() != "Linux":
            return False
        return HOST.run(
            ["ip", "link", "show", AWG_INTERFACE], capture_output=True).returncode == 0

    def _is_up_iface(self, interface: str) -> bool:
        if interface == AWG_INTERFACE:
            return self._is_up()
        import platform
        if platform.system() != "Linux":
            return False
        return HOST.run(
            ["ip", "link", "show", interface], capture_output=True).returncode == 0

    def _current_port(self) -> int:
        try:
            r = self._awg("show", AWG_INTERFACE)
            m = re.search(r"listening port:\s*(\d+)", r.stdout)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        try:
            m = re.search(r"ListenPort\s*=\s*(\d+)", self._interface_block())
            return int(m.group(1)) if m else DEFAULT_PORT
        except Exception:
            return DEFAULT_PORT

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
        return HOST.run([bin_path, *args], **kw)

    @staticmethod
    def _public_ip() -> str:
        r = HOST.run(
            ["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
            capture_output=True, text=True,
        )
        return r.stdout.strip() if r.returncode == 0 else "127.0.0.1"
