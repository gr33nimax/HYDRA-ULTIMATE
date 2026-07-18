"""hydra/plugins/shadowtls/plugin.py — ShadowTLS v3 + Trojan plugin."""
from __future__ import annotations

import json
import ipaddress
import copy
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path

from hydra.plugins.base import (
    BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment,
)
from hydra.core.state import AppState, User
from hydra.utils.crypto import derive_hex_key
from hydra.utils.net import public_ip


SHADOWTLS_SNI_PRESETS = (
    ("www.microsoft.com", "Международный · Microsoft"),
    ("www.apple.com", "Международный · Apple"),
    ("www.cloudflare.com", "Международный · Cloudflare"),
    ("www.amazon.com", "Международный · Amazon"),
    ("www.samsung.com", "Международный · Samsung"),
    ("www.adobe.com", "Международный · Adobe"),
    ("ya.ru", "Россия · Яндекс"),
    ("vk.com", "Россия · ВКонтакте"),
    ("max.ru", "Россия · MAX"),
    ("dzen.ru", "Россия · Дзен"),
    ("rutube.ru", "Россия · Rutube"),
    ("www.ozon.ru", "Россия · Ozon"),
)


class ShadowTLSPlugin(BasePlugin):
    meta = PluginMeta(
        name="shadowtls",
        description="ShadowTLS v3 + Trojan: TLS-camouflaged tunnel (sing-box inbound)",
        category=PluginCategory.TRANSPORT,
        version="1.0.0",
        needs_domain=False,  # Does not require a personal domain
    )

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        from hydra.core.singbox import is_installed
        return is_installed()

    def uninstall(self) -> bool:
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — sing-box shadowtls & trojan detour inbounds
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        ps = state.protocols.get("shadowtls")
        handshake_sni = (ps.config.get("handshake_sni", "") if ps and ps.config else "")

        if not handshake_sni:
            return ConfigFragment()
        handshake_sni = self._validate_handshake_sni(handshake_sni, state)

        users_stls = []
        users_trojan = []
        for user in state.users:
            if user.blocked:
                continue
            username = self._derive_username(user)
            stls_password = self._derive_stls_password(user.uuid)
            trojan_password = self._derive_trojan_password(user.uuid)
            
            users_stls.append({
                "name": username,
                "password": stls_password,
            })
            users_trojan.append({
                "name": username,
                "password": trojan_password,
            })

        if not users_stls:
            return ConfigFragment()

        from hydra.core.sni_router import get_effective_port, needs_mux
        listen_port = get_effective_port("shadowtls", state)
        behind_mux = needs_mux(state)

        # ShadowTLS v3 Inbound (Front-end)
        shadowtls_inbound = {
            "type": "shadowtls",
            "tag": "shadowtls-in",
            "listen": "127.0.0.1" if behind_mux else "::",
            "listen_port": listen_port,
            "version": 3,
            "users": users_stls,
            "handshake": {
                "server": handshake_sni,
                "server_port": 443,
            },
            "strict_mode": True,
            "detour": "shadowtls-trojan-in",
        }

        # Trojan Inbound (Back-end detour)
        trojan_inbound = {
            "type": "trojan",
            "tag": "shadowtls-trojan-in",
            "listen": "127.0.0.1",
            "listen_port": 0,  # Listen port 0 = only via detour
            "users": users_trojan,
        }

        return ConfigFragment(inbounds=[shadowtls_inbound, trojan_inbound])

    def apply(self, state: AppState) -> bool:
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("shadowtls", {})
        user.credentials["shadowtls"]["username"] = self._derive_username(user)
        user.credentials["shadowtls"]["stls_password"] = self._derive_stls_password(user.uuid)
        user.credentials["shadowtls"]["trojan_password"] = self._derive_trojan_password(user.uuid)

    def on_user_remove(self, user: User, state: AppState) -> None:
        pass

    def on_user_block(self, user: User, state: AppState) -> None:
        pass

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентские конфиги
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        ps = state.protocols.get("shadowtls")
        handshake_sni = (ps.config.get("handshake_sni", "") if ps and ps.config else "")
        if not handshake_sni:
            return ""

        username = self._derive_username(user)
        stls_password = self._derive_stls_password(user.uuid)
        trojan_password = self._derive_trojan_password(user.uuid)
        server_ip = self._server_ip(state)

        outbound_trojan = {
            "type": "trojan",
            "tag": f"shadowtls-trojan-{username}",
            "server": server_ip,
            "server_port": 443,
            "password": trojan_password,
            "detour": f"shadowtls-{username}"
        }

        outbound_stls = {
            "type": "shadowtls",
            "tag": f"shadowtls-{username}",
            "server": server_ip,
            "server_port": 443,
            "version": 3,
            "password": stls_password,
            "tls": {
                "enabled": True,
                "server_name": handshake_sni,
                "utls": {
                    "enabled": True,
                    "fingerprint": "chrome"
                }
            }
        }

        full = {
            "log": {"level": "info"},
            "dns": {
                "servers": [
                    {"tag": "google", "address": "8.8.8.8"},
                    {"tag": "local", "address": "1.1.1.1", "detour": "direct"},
                ],
            },
            "outbounds": [outbound_trojan, outbound_stls, {"type": "direct", "tag": "direct"}],
            "route": {"final": outbound_trojan["tag"]},
        }
        return json.dumps(full, indent=2)

    def client_link(self, user: User, state: AppState) -> str:
        ps = state.protocols.get("shadowtls")
        handshake_sni = (ps.config.get("handshake_sni", "") if ps and ps.config else "")
        if not handshake_sni:
            return ""

        stls_password = self._derive_stls_password(user.uuid)
        trojan_password = self._derive_trojan_password(user.uuid)
        tag = urllib.parse.quote(self._derive_username(user), safe="")
        host = self._url_host(self._server_ip(state))
        
        # Format options for shadow-tls plugin
        opts = f"host={handshake_sni};password={stls_password};version=3"
        encoded_opts = urllib.parse.quote(opts, safe="")
        
        return f"trojan://{trojan_password}@{host}:443?plugin=shadow-tls&plugin-opts={encoded_opts}#{tag}"

    # ═════════════════════════════════════════════════════════════════════
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        ps = state.protocols.get("shadowtls")
        if not ps:
            from hydra.core.state import get_protocol
            ps = get_protocol(state, "shadowtls")

        handshake_sni = ps.config.get("handshake_sni", "") if ps and ps.config else ""
        if not handshake_sni:
            handshake_sni = self.choose_handshake_sni()
            if not handshake_sni:
                raise ValueError("SNI домен обязателен для маскировки ShadowTLS!")

        # Validate before touching firewall/accounting state. In particular, a
        # handshake back to this server would recursively enter ShadowTLS.
        handshake_sni = self._validate_handshake_sni(handshake_sni, state)
        ps.config["handshake_sni"] = handshake_sni

        # Firewall (порт 443)
        from hydra.utils.firewall import open_tcp
        open_tcp(443, "shadowtls")

        # iptables accounting
        self._remove_iptables_rules()
        self._add_iptables_rules()

        ps.enabled = True

    def choose_handshake_sni(self) -> str:
        """Show curated TLS 1.3 presets and a custom-domain option."""
        from hydra.ui.tui import menu, prompt

        options = [
            (str(index), domain, label)
            for index, (domain, label) in enumerate(SHADOWTLS_SNI_PRESETS, start=1)
        ]
        custom_key = str(len(options) + 1)
        options.extend([
            (custom_key, "Свой домен", "Введите произвольный TLS 1.3 SNI"),
            ("0", "Отмена", ""),
        ])
        choice = menu(options, "SNI ДЛЯ SHADOWTLS")
        if choice == "0":
            return ""
        if choice == custom_key:
            return prompt("Введите сторонний TLS 1.3 домен").strip()
        try:
            return SHADOWTLS_SNI_PRESETS[int(choice) - 1][0]
        except (ValueError, IndexError):
            return ""

    def set_handshake_sni(self, state: AppState, value: str) -> bool:
        """Validate and transactionally apply a new handshake SNI."""
        from hydra.core.state import get_protocol, save_state

        try:
            handshake_sni = self._validate_handshake_sni(value, state)
        except ValueError:
            return False

        ps = get_protocol(state, "shadowtls")
        old_config = copy.deepcopy(ps.config)
        ps.config["handshake_sni"] = handshake_sni
        if not ps.enabled:
            save_state(state)
            return True

        from hydra.core.orchestrator import apply_config
        try:
            if apply_config(state):
                save_state(state)
                return True
        except Exception:
            pass

        ps.config = old_config
        try:
            apply_config(state)
        except Exception:
            pass
        return False

    def on_disable(self, state: AppState) -> None:
        self._remove_iptables_rules()
        ps = state.protocols.get("shadowtls")
        if ps:
            ps.enabled = False

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / подключенные клиенты
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        from hydra.core.singbox import is_installed, is_running
        from hydra.core.state import load_state
        installed = is_installed()
        enabled = False
        try:
            state = load_state()
            ps = state.protocols.get("shadowtls")
            if ps:
                enabled = ps.enabled
        except Exception:
            pass

        info = {}
        if installed and enabled:
            try:
                total = self._get_total_traffic()
                size = float(total)
                for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
                    if size < 1024.0:
                        formatted = f"{size:.2f} {unit}" if unit != 'B' else f"{int(size)} B"
                        break
                    size /= 1024.0
                else:
                    formatted = f"{size:.2f} PB"
                info["Общий трафик"] = formatted
            except Exception:
                pass

        effective_port = 443
        if state:
            try:
                from hydra.core.sni_router import get_effective_port
                effective_port = get_effective_port("shadowtls", state)
            except Exception:
                pass

        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=installed and is_running() and enabled,
            port=effective_port,
            info=info,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        res = {}
        for u in state.users:
            t = u.credentials.get("shadowtls", {}).get("traffic_used_bytes", 0)
            if t > 0:
                res[u.email] = t
        return res

    def connected_clients(self, state: AppState | None = None) -> list[dict]:
        if not shutil.which("ss"):
            return []

        if state is None:
            from hydra.core.state import load_state
            try:
                state = load_state()
            except Exception:
                pass

        from hydra.core.sni_router import get_effective_port
        effective_port = get_effective_port("shadowtls", state) if state else 443

        r = subprocess.run(
            ["ss", "-t", "-H", "-n", "state", "established"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return []

        ip_counts = {}
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue

            local_addr = parts[2]
            local_port_str = local_addr.split(":")[-1]
            if not local_port_str.isdigit():
                continue
            local_port = int(local_port_str)

            if local_port == effective_port or local_port == 443:
                remote_addr = parts[3]
                remote_parts = remote_addr.split(":")
                remote_ip = ":".join(remote_parts[:-1]).strip("[]")
                ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1

        rx_bytes = 0
        tx_bytes = 0
        r_rx = subprocess.run(["iptables", "-t", "filter", "-L", "INPUT", "-n", "-v", "-x"], capture_output=True, text=True)
        if r_rx.returncode == 0:
            for line in r_rx.stdout.splitlines():
                if "shadowtls-rx" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rx_bytes += int(parts[1])
        r_tx = subprocess.run(["iptables", "-t", "filter", "-L", "OUTPUT", "-n", "-v", "-x"], capture_output=True, text=True)
        if r_tx.returncode == 0:
            for line in r_tx.stdout.splitlines():
                if "shadowtls-tx" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        tx_bytes += int(parts[1])

        clients = []
        now_ts = int(time.time())
        n_clients = len(ip_counts)

        for remote_ip, count in ip_counts.items():
            clients.append({
                "online": True,
                "email": f"{remote_ip} ({count} TCP)",
                "rx": rx_bytes // n_clients if n_clients > 0 else 0,
                "tx": tx_bytes // n_clients if n_clients > 0 else 0,
                "last_handshake": now_ts,
            })
        return clients

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _derive_username(user: User) -> str:
        return user.email

    @staticmethod
    def _derive_stls_password(uuid: str) -> str:
        return derive_hex_key("shadowtls-pass", uuid)

    @staticmethod
    def _derive_trojan_password(uuid: str) -> str:
        # Keep the inner credential compatible with already applied server
        # configs. ShadowTLS and Trojan authenticate different protocol layers,
        # so sharing this derived secret is valid and avoids silent rotations.
        return derive_hex_key("shadowtls-pass", uuid)

    @staticmethod
    def _normalized_host(value: str) -> str:
        return value.strip().rstrip(".").lower()

    def _validate_handshake_sni(self, value: str, state: AppState) -> str:
        handshake_sni = self._normalized_host(value)
        if not handshake_sni:
            raise ValueError("SNI домен обязателен для маскировки ShadowTLS!")

        own_hosts = {
            self._normalized_host(state.network.domain),
            self._normalized_host(state.network.sub_domain),
            self._normalized_host(state.network.server_ip),
        }
        for name, protocol in state.protocols.items():
            if name == "shadowtls" or not protocol.enabled:
                continue
            own_hosts.add(self._normalized_host(protocol.config.get("domain", "")))

        own_hosts.discard("")
        if handshake_sni in own_hosts:
            raise ValueError(
                f"SNI {handshake_sni} принадлежит этому серверу. "
                "Для ShadowTLS укажите сторонний TLS 1.3 домен, иначе возникает циклическое подключение."
            )
        return handshake_sni

    @staticmethod
    def _server_ip(state: AppState) -> str:
        value = (state.network.server_ip or public_ip()).strip()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(
                "Для ShadowTLS не удалось определить публичный IP сервера"
            ) from exc

    @staticmethod
    def _url_host(value: str) -> str:
        address = ipaddress.ip_address(value)
        return f"[{address}]" if address.version == 6 else str(address)

    def _remove_iptables_rules(self) -> None:
        for chain in ("INPUT", "OUTPUT"):
            r = subprocess.run(["iptables", "-S", chain], capture_output=True, text=True)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "shadowtls-" in line:
                    parts = line.split()
                    if parts[0] == "-A":
                        parts[0] = "-D"
                        subprocess.run(["iptables"] + parts, capture_output=True)

    def _add_iptables_rules(self) -> None:
        subprocess.run([
            "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "443",
            "-m", "comment", "--comment", "shadowtls-rx"
        ], capture_output=True)
        subprocess.run([
            "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--sport", "443",
            "-m", "comment", "--comment", "shadowtls-tx"
        ], capture_output=True)

    def _get_total_traffic(self) -> int:
        total_bytes = 0
        for chain in ("INPUT", "OUTPUT"):
            r = subprocess.run(
                ["iptables", "-t", "filter", "-L", chain, "-n", "-v", "-x"],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "shadowtls-" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        total_bytes += int(parts[1])
        return total_bytes
