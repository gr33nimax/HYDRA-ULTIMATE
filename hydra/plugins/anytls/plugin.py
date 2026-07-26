"""hydra/plugins/anytls/plugin.py — AnyTLS: TLS-shaped tunnel с padding scheme (sing-box inbound)."""
from __future__ import annotations

from hydra.core.host import HOST

import json
import shutil
import time
import urllib.parse

from hydra.plugins.context import PluginStateAccess
from hydra.plugins.base import (
    BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment,
    HealthResult,
)
from hydra.core.state_models import User
from hydra.utils.crypto import derive_key, derive_hex_key
from hydra.utils.net import public_ip
from hydra.utils.tls import resolve_tls_material
from hydra.plugins.anytls.presets import get_preset


DEFAULT_PADDING_SCHEME = [
    "stop=8",
    "0=30-30",
    "1=100-400",
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
    "3=9-9,500-1000",
    "4=500-1000",
    "5=500-1000",
    "6=500-1000",
    "7=500-1000",
]


class AnyTLSPlugin(BasePlugin):
    meta = PluginMeta(
        name="anytls",
        description="AnyTLS: TLS-shaped tunnel с padding scheme (sing-box inbound)",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=True,
        commands=("set_preset",),
        queries=("get_current_preset",),
        tls_domain_source="protocol",
        connection_source="tracked",
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
    #  configure — sing-box anytls inbound
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        ps = state.protocols.get("anytls")
        anytls_domain = (ps.config.get("domain", "") if ps and ps.config else "")
        
        # AnyTLS ОБЯЗАТЕЛЬНО использует свой домен (не network.domain)
        if not anytls_domain:
            return ConfigFragment()

        users = []
        for user in state.users:
            if user.blocked:
                continue
            username = self._derive_username(user)
            password = self._derive_password(user.uuid)
            users.append({
                "name": username,
                "password": password,
            })

        if not users:
            return ConfigFragment()

        # TLS-сертификаты
        cert_file, key_file = self._resolve_certs(anytls_domain, ps)
        if not cert_file or not key_file:
            return ConfigFragment()

        # Порт: через SNI-мультиплексор или напрямую
        from hydra.core.sni_router import get_effective_port, needs_mux
        listen_port = get_effective_port("anytls", state)
        behind_mux = needs_mux(state)

        inbound = {
            "type": "anytls",
            "tag": "anytls-in",
            "listen": "127.0.0.1" if behind_mux else "::",
            "listen_port": listen_port,
            "users": users,
            "padding_scheme": self._get_padding_scheme(state),
        }
        if not behind_mux:
            inbound["tls"] = {
                "enabled": True,
                "server_name": anytls_domain,
                "certificate_path": cert_file,
                "key_path": key_file,
            }
        return ConfigFragment(inbounds=[inbound])

    def apply(self, state: PluginStateAccess) -> bool:
        return True

    def healthcheck_for_state(self, state: PluginStateAccess) -> HealthResult:
        """Validate the candidate AnyTLS inbound without reloading state."""
        from hydra.core import singbox

        service_active = singbox.is_running()
        inbound_configured = singbox.has_configured_inbound("anytls-in")
        healthy = service_active and inbound_configured
        detail = ""
        if not service_active:
            detail = "sing-box service is not active"
        elif not inbound_configured:
            detail = "AnyTLS inbound is missing from the applied Sing-Box config"
        return HealthResult(
            healthy,
            detail,
            "ok" if healthy else "error",
            {"sing_box": service_active, "anytls_inbound": inbound_configured},
        )

    def _get_padding_scheme(self, state: PluginStateAccess) -> list[str]:
        ps = state.protocols.get("anytls")
        preset_name = "web_browsing"
        if ps and ps.config and "padding_preset" in ps.config:
            preset_name = ps.config["padding_preset"]
        preset = get_preset(preset_name)
        return preset["padding_scheme"]

    def get_current_preset(self, state: PluginStateAccess) -> str:
        """Возвращает имя текущего пресета обфускации."""
        ps = state.protocols.get("anytls")
        if ps and ps.config and "padding_preset" in ps.config:
            return ps.config["padding_preset"]
        return "web_browsing"

    def set_preset(
        self,
        state: PluginStateAccess,
        preset_name: str,
    ) -> bool:
        """Validate and update the desired padding preset."""
        from hydra.plugins.anytls.presets import PRESETS
        if preset_name not in PRESETS:
            return False
        ps = state.protocols.get("anytls")
        if ps is None:
            return False
        ps.config["padding_preset"] = preset_name
        return True


    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: PluginStateAccess) -> None:
        user.credentials.setdefault("anytls", {})
        user.credentials["anytls"]["username"] = self._derive_username(user)
        user.credentials["anytls"]["password"] = self._derive_password(user.uuid)

    def on_user_remove(self, user: User, state: PluginStateAccess) -> None:
        pass

    def on_user_block(self, user: User, state: PluginStateAccess) -> None:
        pass

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентские конфиги
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: PluginStateAccess) -> str:
        ps = state.protocols.get("anytls")
        anytls_domain = (ps.config.get("domain", "") if ps and ps.config else "")
        if not anytls_domain:
            return ""

        username = self._derive_username(user)
        password = self._derive_password(user.uuid)
        server_ip = state.network.server_ip or public_ip()

        outbound = {
            "type": "anytls",
            "tag": f"anytls-{username}",
            "server": server_ip,
            "server_port": 443,          # ← клиент всегда подключается на 443
            "password": password,
            "idle_session_check_interval": "30s",
            "idle_session_timeout": "30s",
            "min_idle_session": 5,
            "tls": {
                "enabled": True,
                "server_name": anytls_domain,  # ← собственный домен anytls
            },
        }

        full = {
            "log": {"level": "info"},
            "dns": {
                "servers": [
                    {"tag": "google", "address": "8.8.8.8"},
                    {"tag": "local", "address": "1.1.1.1", "detour": "direct"},
                ],
            },
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": outbound["tag"]},
        }
        return json.dumps(full, indent=2)

    def client_link(self, user: User, state: PluginStateAccess) -> str:
        ps = state.protocols.get("anytls")
        anytls_domain = (ps.config.get("domain", "") if ps and ps.config else "")
        if not anytls_domain:
            return ""

        password = self._derive_password(user.uuid)
        tag = urllib.parse.quote(self._derive_username(user), safe="")
        return f"anytls://{password}@{anytls_domain}:443?sni={anytls_domain}#{tag}"

    # ═════════════════════════════════════════════════════════════════════
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: PluginStateAccess) -> None:
        ps = state.protocols.get("anytls")
        if not ps:
            raise ValueError("AnyTLS configuration is missing")

        # Input belongs to adapters. Lifecycle hooks only validate the desired
        # state and reconcile host resources, so CLI/Telegram calls never block.
        anytls_domain = str(ps.config.get("domain", "")).strip()
        if not anytls_domain:
            raise ValueError(
                "Домен AnyTLS не настроен; задайте protocols.anytls.config.domain "
                "перед включением",
            )

        # Проверка: не совпадает ли с доменом naive
        if anytls_domain == state.network.domain:
            naive_ps = state.protocols.get("naive")
            if naive_ps and naive_ps.enabled:
                raise ValueError(
                    f"Домен {anytls_domain} уже используется NaiveProxy! "
                    "AnyTLS требует отдельный домен."
                )
        
        # 2. Получить TLS-сертификат (автоматически или найти существующий)
        cert_file, key_file = self._resolve_certs(anytls_domain, ps)
        if not cert_file or not key_file:
            raise ValueError(
                f"TLS material for {anytls_domain} must be prepared by the application service"
            )
        
        # 3. Firewall (порт 443 — если ещё не открыт naive)
        from hydra.utils.firewall import open_tcp
        open_tcp(443, "anytls")
        
        # 4. iptables accounting
        self._remove_iptables_rules()
        self._add_iptables_rules()
        
    def on_disable(self, state: PluginStateAccess) -> None:
        self._remove_iptables_rules()
        
    # ═════════════════════════════════════════════════════════════════════
    #  Статус / подключенные клиенты
    # ═════════════════════════════════════════════════════════════════════

    def status(
        self,
        state: PluginStateAccess | None = None,
    ) -> PluginStatus:
        from hydra.core.singbox import is_installed, is_running
        runtime_installed = is_installed()
        installed = False
        enabled = False
        if state is not None:
            ps = state.protocols.get("anytls")
            if ps:
                installed = bool(ps.installed and runtime_installed)
                enabled = bool(ps.enabled and installed)

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
                effective_port = get_effective_port("anytls", state)
            except Exception:
                pass

        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=installed and is_running() and enabled,
            port=effective_port,
            info=info,
        )

    def traffic(self, state: PluginStateAccess) -> dict[str, int]:
        res = {}
        for u in state.users:
            t = u.credentials.get("anytls", {}).get("traffic_used_bytes", 0)
            if t > 0:
                res[u.email] = t
        return res

    def connected_clients(self, state: PluginStateAccess | None = None) -> list[dict]:
        if not shutil.which("ss"):
            return []
        
        from hydra.core.sni_router import get_effective_port
        effective_port = get_effective_port("anytls", state) if state else 443
        
        r = HOST.run(
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
            
            # Фильтруем по внутреннему эффективному порту или по 443
            if local_port == effective_port or local_port == 443:
                remote_addr = parts[3]
                remote_parts = remote_addr.split(":")
                remote_ip = ":".join(remote_parts[:-1]).strip("[]")
                ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1
                
        # rx/tx из iptables accounting
        rx_bytes = 0
        tx_bytes = 0
        r_rx = HOST.run(["iptables", "-t", "filter", "-L", "INPUT", "-n", "-v", "-x"], capture_output=True, text=True)
        if r_rx.returncode == 0:
            for line in r_rx.stdout.splitlines():
                if "anytls-rx" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rx_bytes += int(parts[1])
        r_tx = HOST.run(["iptables", "-t", "filter", "-L", "OUTPUT", "-n", "-v", "-x"], capture_output=True, text=True)
        if r_tx.returncode == 0:
            for line in r_tx.stdout.splitlines():
                if "anytls-tx" in line:
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
    def _derive_password(uuid: str) -> str:
        return derive_hex_key("anytls-pass", uuid)

    def _resolve_certs(self, domain: str, ps) -> tuple[str, str]:
        """Ищет существующий TLS-сертификат для домена.
        
        Порядок поиска:
        1. Из ps.config["cert_file"] / ps.config["key_file"] (ручной ввод)
        2. /etc/letsencrypt/live/{domain}/ (certbot)
        """
        config = ps.config if ps and ps.config else {}
        return resolve_tls_material(domain, config)

    def _remove_iptables_rules(self) -> None:
        """Удаляет правила anytls-rx / anytls-tx."""
        for chain in ("INPUT", "OUTPUT"):
            r = HOST.run(["iptables", "-S", chain], capture_output=True, text=True)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "anytls-" in line:
                    parts = line.split()
                    if parts[0] == "-A":
                        parts[0] = "-D"
                        HOST.run(["iptables"] + parts, capture_output=True)

    def _add_iptables_rules(self) -> None:
        """Добавляет iptables accounting для порта 443."""
        HOST.run([
            "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "443",
            "-m", "comment", "--comment", "anytls-rx"
        ], capture_output=True)
        HOST.run([
            "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--sport", "443",
            "-m", "comment", "--comment", "anytls-tx"
        ], capture_output=True)

    def _get_total_traffic(self) -> int:
        """Суммарный трафик через iptables accounting."""
        total_bytes = 0
        for chain in ("INPUT", "OUTPUT"):
            r = HOST.run(
                ["iptables", "-t", "filter", "-L", chain, "-n", "-v", "-x"],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "anytls-" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        total_bytes += int(parts[1])
        return total_bytes
