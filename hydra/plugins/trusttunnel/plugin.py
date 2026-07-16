"""hydra/plugins/trusttunnel/plugin.py — TrustTunnel: HTTP/2-based obfuscated tunnel (sing-box inbound)."""
from __future__ import annotations

import json
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
from hydra.plugins.trusttunnel.presets import get_preset, list_presets, validate_preset, PRESETS


class TrustTunnelPlugin(BasePlugin):
    meta = PluginMeta(
        name="trusttunnel",
        description="TrustTunnel: HTTP/2 obfuscated tunnel (sing-box inbound)",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=True,
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
    #  configure — sing-box trusttunnel inbound
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        ps = state.protocols.get("trusttunnel")
        domain = (ps.config.get("domain", "") if ps and ps.config else "")
        
        if not domain:
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

        cert_file, key_file = self._resolve_certs(domain, ps)
        if not cert_file or not key_file:
            return ConfigFragment()

        # Пресет и транспорт
        preset_name = ps.config.get("preset", "default") if ps and ps.config else "default"
        preset = get_preset(preset_name)
        # Пользователь может override транспорт отдельно от пресета
        transport = ps.config.get("transport", preset.transport) if ps and ps.config else preset.transport

        # Порт: через SNI-мультиплексор или напрямую
        from hydra.core.sni_router import get_effective_port, needs_mux
        listen_port = get_effective_port("trusttunnel", state)
        behind_mux = needs_mux(state)

        inbounds = []

        # TCP inbound (HTTP/2)
        if transport in ("tcp", "both"):
            tcp_inbound = {
                "type": "trusttunnel",
                "tag": "trusttunnel-in",
                "listen": "127.0.0.1" if behind_mux else "::",
                "listen_port": listen_port,
                "users": users,
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "certificate_path": cert_file,
                    "key_path": key_file,
                    "alpn": ["h2"],
                },
            }
            inbounds.append(tcp_inbound)

        # QUIC inbound (HTTP/3)
        if transport in ("quic", "both"):
            # QUIC: определяем порт
            # Если ТОЛЬКО quic (не both) и нет mux — слушаем на 443
            # Если both или mux — используем отдельный внутренний порт
            if transport == "quic" and not behind_mux:
                quic_port = 443
                quic_listen = "::"
            else:
                quic_port = listen_port  # будет проксироваться через quic_mux в SNI router
                quic_listen = "127.0.0.1" if behind_mux else "::"

            quic_inbound = {
                "type": "trusttunnel",
                "tag": "trusttunnel-quic-in",
                "listen": quic_listen,
                "listen_port": quic_port,
                "users": users,
                "network": "udp",
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "certificate_path": cert_file,
                    "key_path": key_file,
                    "alpn": ["h3"],
                },
            }
            inbounds.append(quic_inbound)

        return ConfigFragment(inbounds=inbounds)

    def apply(self, state: AppState) -> bool:
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("trusttunnel", {})
        user.credentials["trusttunnel"]["username"] = self._derive_username(user)
        user.credentials["trusttunnel"]["password"] = self._derive_password(user.uuid)

    def on_user_remove(self, user: User, state: AppState) -> None:
        pass

    def on_user_block(self, user: User, state: AppState) -> None:
        pass

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентские конфиги
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        ps = state.protocols.get("trusttunnel")
        domain = (ps.config.get("domain", "") if ps and ps.config else "")
        if not domain:
            return ""

        username = self._derive_username(user)
        password = self._derive_password(user.uuid)
        server_ip = state.network.server_ip or public_ip()

        preset_name = ps.config.get("preset", "default") if ps and ps.config else "default"
        preset = get_preset(preset_name)
        transport = ps.config.get("transport", preset.transport) if ps and ps.config else preset.transport

        outbounds = []

        # TCP outbound
        if transport in ("tcp", "both"):
            tcp_out = {
                "type": "trusttunnel",
                "tag": f"trusttunnel-{username}",
                "server": server_ip,
                "server_port": 443,
                "username": username,
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                },
            }
            # uTLS fingerprint (client-side only)
            if preset.utls_fingerprint:
                tcp_out["tls"]["utls"] = {
                    "enabled": True,
                    "fingerprint": preset.utls_fingerprint,
                }
            # Multiplex
            if preset.multiplex:
                mux = {"enabled": True, "protocol": preset.multiplex["protocol"]}
                if "max_connections" in preset.multiplex:
                    mux["max_connections"] = preset.multiplex["max_connections"]
                if "min_streams" in preset.multiplex:
                    mux["min_streams"] = preset.multiplex["min_streams"]
                if "max_streams" in preset.multiplex:
                    mux["max_streams"] = preset.multiplex["max_streams"]
                mux["padding"] = preset.padding
                if "brutal" in preset.multiplex:
                    mux["brutal"] = preset.multiplex["brutal"]
                tcp_out["multiplex"] = mux
            outbounds.append(tcp_out)

        # QUIC outbound
        if transport in ("quic", "both"):
            quic_out = {
                "type": "trusttunnel",
                "tag": f"trusttunnel-quic-{username}",
                "server": server_ip,
                "server_port": 443,
                "username": username,
                "password": password,
                "network": "udp",
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                    "alpn": ["h3"],
                },
            }
            if preset.utls_fingerprint:
                quic_out["tls"]["utls"] = {
                    "enabled": True,
                    "fingerprint": preset.utls_fingerprint,
                }
            # QUIC с multiplex (если задан в пресете и протокол поддерживает)
            if preset.multiplex:
                mux = {"enabled": True, "protocol": preset.multiplex["protocol"]}
                if "max_connections" in preset.multiplex:
                    mux["max_connections"] = preset.multiplex["max_connections"]
                if "min_streams" in preset.multiplex:
                    mux["min_streams"] = preset.multiplex["min_streams"]
                if "max_streams" in preset.multiplex:
                    mux["max_streams"] = preset.multiplex["max_streams"]
                mux["padding"] = preset.padding
                if "brutal" in preset.multiplex:
                    mux["brutal"] = preset.multiplex["brutal"]
                quic_out["multiplex"] = mux
            outbounds.append(quic_out)

        direct_out = {"type": "direct", "tag": "direct"}

        # Финальный outbound (первый в списке = маршрут по умолчанию)
        final_tag = outbounds[0]["tag"] if outbounds else "direct"

        full = {
            "log": {"level": "info"},
            "dns": {
                "servers": [
                    {"tag": "google", "address": "8.8.8.8"},
                    {"tag": "local", "address": "1.1.1.1", "detour": "direct"},
                ],
            },
            "outbounds": outbounds + [direct_out],
            "route": {"final": final_tag},
        }
        return json.dumps(full, indent=2)

    def client_link(self, user: User, state: AppState) -> str:
        """Основная ссылка (для совместимости). При both — возвращает TCP."""
        ps = state.protocols.get("trusttunnel")
        domain = (ps.config.get("domain", "") if ps and ps.config else "")
        if not domain:
            return ""

        username = urllib.parse.quote(self._derive_username(user), safe="")
        password = urllib.parse.quote(self._derive_password(user.uuid), safe="")
        tag = urllib.parse.quote(self._derive_username(user), safe="")

        preset_name = ps.config.get("preset", "default") if ps and ps.config else "default"
        preset = get_preset(preset_name)
        transport = ps.config.get("transport", preset.transport) if ps and ps.config else preset.transport

        if transport == "quic":
            tag_q = urllib.parse.quote(f"{self._derive_username(user)} TrustTunnel QUIC", safe="")
            return f"tt+quic://{username}:{password}@{domain}:443?security=tls&sni={domain}&alpn=h3#{tag_q}"

        fp_param = f"&fp={preset.utls_fingerprint}" if preset.utls_fingerprint else ""
        return f"tt://{username}:{password}@{domain}:443?security=tls&sni={domain}&alpn=h2{fp_param}#{tag}"

    def client_links(self, user: User, state: AppState) -> list[str]:
        """Возвращает список ссылок (может быть >1 при transport=both)."""
        ps = state.protocols.get("trusttunnel")
        domain = (ps.config.get("domain", "") if ps and ps.config else "")
        if not domain:
            return []

        username = urllib.parse.quote(self._derive_username(user), safe="")
        password = urllib.parse.quote(self._derive_password(user.uuid), safe="")

        preset_name = ps.config.get("preset", "default") if ps and ps.config else "default"
        preset = get_preset(preset_name)
        transport = ps.config.get("transport", preset.transport) if ps and ps.config else preset.transport

        fp_param = f"&fp={preset.utls_fingerprint}" if preset.utls_fingerprint else ""
        links = []

        if transport in ("tcp", "both"):
            tag = urllib.parse.quote(f"{self._derive_username(user)} TrustTunnel", safe="")
            links.append(f"tt://{username}:{password}@{domain}:443?security=tls&sni={domain}&alpn=h2{fp_param}#{tag}")

        if transport in ("quic", "both"):
            tag = urllib.parse.quote(f"{self._derive_username(user)} TrustTunnel QUIC", safe="")
            links.append(f"tt+quic://{username}:{password}@{domain}:443?security=tls&sni={domain}&alpn=h3{fp_param}#{tag}")

        return links

    # ═════════════════════════════════════════════════════════════════════
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        ps = state.protocols.get("trusttunnel")
        if not ps:
            from hydra.core.state import get_protocol
            ps = get_protocol(state, "trusttunnel")

        domain = ps.config.get("domain", "") if ps and ps.config else ""
        if not domain:
            from hydra.ui.tui import prompt
            domain = prompt(
                "Введите домен для TrustTunnel (ДОЛЖЕН ОТЛИЧАТЬСЯ от домена NaiveProxy/AnyTLS!)"
            )
            if not domain:
                raise ValueError("Домен обязателен для TrustTunnel!")
            
            # Проверка: не совпадает ли с доменом naive
            if domain == state.network.domain:
                naive_ps = state.protocols.get("naive")
                if naive_ps and naive_ps.enabled:
                    raise ValueError(
                        f"Домен {domain} уже используется NaiveProxy! TrustTunnel требует отдельный домен."
                    )
            
            # Проверка: не совпадает ли с другими доменами
            for other_name in ("anytls",):
                other_ps = state.protocols.get(other_name)
                if other_ps and other_ps.enabled and other_ps.config.get("domain") == domain:
                    raise ValueError(
                        f"Домен {domain} уже используется {other_name}! TrustTunnel требует отдельный домен."
                    )
            
            ps.config["domain"] = domain
        
        cert_file, key_file = self._resolve_certs(domain, ps)
        if not cert_file or not key_file:
            print(f"  Получаю TLS-сертификат для {domain}...")
            ok = self._obtain_cert_certbot(domain)
            if ok:
                cert_file, key_file = self._find_existing_cert(domain)
        
        if not cert_file or not key_file:
            from hydra.ui.tui import prompt
            cert_file = prompt("Путь к сертификату (fullchain.pem)", default="")
            key_file = prompt("Путь к приватному ключу (privkey.pem)", default="")
        
        if not cert_file or not key_file:
            raise ValueError(
                f"TLS-сертификат для домена {domain} не получен! Проверьте DNS-записи и доступность порта 80."
            )
        
        ps.config["cert_file"] = cert_file
        ps.config["key_file"] = key_file
        
        # Firewall (порт 443)
        from hydra.utils.firewall import open_tcp
        open_tcp(443, "trusttunnel")
        
        # QUIC firewall (UDP)
        preset_name = ps.config.setdefault("preset", "default")
        preset = get_preset(preset_name)
        transport = ps.config.setdefault("transport", preset.transport)
        if transport in ("quic", "both"):
            from hydra.utils.firewall import open_udp
            open_udp(443, "trusttunnel-quic")
        
        # iptables accounting
        self._remove_iptables_rules()
        self._add_iptables_rules(state)
        
        ps.enabled = True
        
        from hydra.core.sni_router import rebuild
        rebuild(state)

    def on_disable(self, state: AppState) -> None:
        self._remove_iptables_rules()
        
        # Закрыть UDP порт
        try:
            from hydra.utils.firewall import close_udp
            close_udp(443)
        except Exception:
            pass

        ps = state.protocols.get("trusttunnel")
        if ps:
            ps.enabled = False
        
        from hydra.core.sni_router import rebuild
        rebuild(state)

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
            ps = state.protocols.get("trusttunnel")
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
        try:
            state = load_state()
            from hydra.core.sni_router import get_effective_port
            effective_port = get_effective_port("trusttunnel", state)
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
            t = u.credentials.get("trusttunnel", {}).get("traffic_used_bytes", 0)
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
        effective_port = get_effective_port("trusttunnel", state) if state else 443
        
        # Check TCP
        r = subprocess.run(
            ["ss", "-t", "-H", "-n", "state", "established"],
            capture_output=True, text=True,
        )
        
        ip_counts = {}
        if r.returncode == 0:
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

        # Check UDP (QUIC)
        r_udp = subprocess.run(
            ["ss", "-u", "-H", "-n", "state", "established"],
            capture_output=True, text=True,
        )
        if r_udp.returncode == 0:
            for line in r_udp.stdout.splitlines():
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
                if "trusttunnel-rx" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rx_bytes += int(parts[1])
        r_tx = subprocess.run(["iptables", "-t", "filter", "-L", "OUTPUT", "-n", "-v", "-x"], capture_output=True, text=True)
        if r_tx.returncode == 0:
            for line in r_tx.stdout.splitlines():
                if "trusttunnel-tx" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        tx_bytes += int(parts[1])
                        
        clients = []
        now_ts = int(time.time())
        n_clients = len(ip_counts)
        
        for remote_ip, count in ip_counts.items():
            clients.append({
                "online": True,
                "email": f"{remote_ip} ({count} Conns)",
                "rx": rx_bytes // n_clients if n_clients > 0 else 0,
                "tx": tx_bytes // n_clients if n_clients > 0 else 0,
                "last_handshake": now_ts,
            })
        return clients

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    # ═════════════════════════════════════════════════════════════════════
    #  Управление пресетами
    # ═════════════════════════════════════════════════════════════════════

    def get_current_preset(self, state: AppState) -> str:
        """Возвращает имя текущего пресета."""
        ps = state.protocols.get("trusttunnel")
        if ps and ps.config and "preset" in ps.config:
            return ps.config["preset"]
        return "default"

    def get_current_transport(self, state: AppState) -> str:
        """Возвращает текущий транспорт (может отличаться от пресетного)."""
        ps = state.protocols.get("trusttunnel")
        if ps and ps.config and "transport" in ps.config:
            return ps.config["transport"]
        preset = get_preset(self.get_current_preset(state))
        return preset.transport

    def set_preset(self, state: AppState, preset_name: str) -> bool:
        """Устанавливает пресет и применяет конфиг."""
        if not validate_preset(preset_name):
            return False
        from hydra.core.state import get_protocol, save_state
        ps = get_protocol(state, "trusttunnel")
        ps.config["preset"] = preset_name
        # Сбрасываем override транспорта — пресет задаёт свой
        preset = get_preset(preset_name)
        ps.config["transport"] = preset.transport
        save_state(state)
        from hydra.core import orchestrator
        return orchestrator.apply_config(state)

    def set_transport(self, state: AppState, transport: str) -> bool:
        """Устанавливает транспорт (override поверх пресета)."""
        if transport not in ("tcp", "quic", "both"):
            return False
        from hydra.core.state import get_protocol, save_state
        ps = get_protocol(state, "trusttunnel")
        ps.config["transport"] = transport
        save_state(state)

        # Обновить firewall для QUIC
        self._remove_iptables_rules()
        self._add_iptables_rules(state)
        if transport in ("quic", "both"):
            from hydra.utils.firewall import open_udp
            open_udp(443, "trusttunnel-quic")
        else:
            from hydra.utils.firewall import close_udp
            try:
                close_udp(443)
            except Exception:
                pass

        from hydra.core.sni_router import rebuild
        rebuild(state)
        from hydra.core import orchestrator
        return orchestrator.apply_config(state)

    @staticmethod
    def _derive_username(user: User) -> str:
        return user.email

    @staticmethod
    def _derive_password(uuid: str) -> str:
        return derive_hex_key("trusttunnel-pass", uuid)

    def _resolve_certs(self, domain: str, ps) -> tuple[str, str]:
        cert = (ps.config.get("cert_file", "") if ps and ps.config else "")
        key = (ps.config.get("key_file", "") if ps and ps.config else "")
        if cert and key:
            return cert, key
        return self._find_existing_cert(domain)

    def _find_existing_cert(self, domain: str) -> tuple[str, str]:
        paths = [
            (f"/etc/letsencrypt/live/{domain}/fullchain.pem", f"/etc/letsencrypt/live/{domain}/privkey.pem"),
            (f"/etc/xray/{domain}.crt", f"/etc/xray/{domain}.key"),
            ("/etc/xray/xray.crt", "/etc/xray/xray.key"),
        ]
        for cert, key in paths:
            cert_p, key_p = Path(cert), Path(key)
            if cert_p.exists() and key_p.exists():
                return cert, key
        return "", ""

    def _obtain_cert_certbot(self, domain: str) -> bool:
        # Проверяем, есть ли уже валидный сертификат
        from pathlib import Path
        cert_path = Path(f"/etc/letsencrypt/live/{domain}/fullchain.pem")
        key_path = Path(f"/etc/letsencrypt/live/{domain}/privkey.pem")
        if cert_path.exists() and key_path.exists():
            try:
                r = subprocess.run(
                    ["openssl", "x509", "-checkend", "2592000", "-noout", "-in", str(cert_path)],
                    capture_output=True
                )
                if r.returncode == 0:
                    print(f"  Сертификат для {domain} уже существует и действителен.")
                    return True
            except Exception:
                pass

        import shutil
        from hydra.utils.firewall import is_ufw_active

        if not shutil.which("certbot"):
            print("  Устанавливаю certbot...")
            subprocess.run(["apt-get", "update"], capture_output=True)
            subprocess.run(["apt-get", "install", "-y", "certbot"], capture_output=True)

        services_to_stop = ["caddy-l4", "caddy-naive", "nginx", "apache2"]
        was_running = []
        for s in services_to_stop:
            r = subprocess.run(["systemctl", "is-active", s], capture_output=True, text=True)
            if r.stdout.strip() == "active":
                print(f"  Временно останавливаю {s}...")
                subprocess.run(["systemctl", "stop", s], capture_output=True)
                was_running.append(s)

        ufw_opened = False
        ipt_opened = False
        if is_ufw_active():
            subprocess.run(["ufw", "allow", "80/tcp", "comment", "temp-certbot"], capture_output=True)
            ufw_opened = True
        else:
            r_chk = subprocess.run([
                "iptables", "-C", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"
            ], capture_output=True)
            if r_chk.returncode != 0:
                subprocess.run([
                    "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"
                ], capture_output=True)
                ipt_opened = True

        r = subprocess.run([
            "certbot", "certonly", "--standalone",
            "-d", domain,
            "--non-interactive", "--agree-tos",
            "--register-unsafely-without-email",
            "--keep-until-expiring",
        ], capture_output=True, text=True)

        success = r.returncode == 0

        if not success:
            print(f"  [Ошибка certbot] Вывод:\n{r.stderr or r.stdout or ''}")

        if ufw_opened:
            subprocess.run(["ufw", "delete", "allow", "80/tcp"], capture_output=True)
        if ipt_opened:
            subprocess.run([
                "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"
            ], capture_output=True)

        for s in was_running:
            print(f"  Восстанавливаю {s}...")
            subprocess.run(["systemctl", "start", s], capture_output=True)

        return success

    def _remove_iptables_rules(self) -> None:
        for chain in ("INPUT", "OUTPUT"):
            r = subprocess.run(["iptables", "-S", chain], capture_output=True, text=True)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "trusttunnel-" in line:
                    parts = line.split()
                    if parts[0] == "-A":
                        parts[0] = "-D"
                        subprocess.run(["iptables"] + parts, capture_output=True)

    def _add_iptables_rules(self, state: AppState) -> None:
        from hydra.core.sni_router import get_effective_port
        port = get_effective_port("trusttunnel", state)
        subprocess.run([
            "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(port),
            "-m", "comment", "--comment", "trusttunnel-rx"
        ], capture_output=True)
        subprocess.run([
            "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--sport", str(port),
            "-m", "comment", "--comment", "trusttunnel-tx"
        ], capture_output=True)

        # UDP accounting для QUIC
        ps = state.protocols.get("trusttunnel")
        preset_name = ps.config.get("preset", "default") if ps and ps.config else "default"
        preset = get_preset(preset_name)
        transport = ps.config.get("transport", preset.transport) if ps and ps.config else preset.transport
        if transport in ("quic", "both"):
            subprocess.run([
                "iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", str(port),
                "-m", "comment", "--comment", "trusttunnel-rx-udp"
            ], capture_output=True)
            subprocess.run([
                "iptables", "-I", "OUTPUT", "1", "-p", "udp", "--sport", str(port),
                "-m", "comment", "--comment", "trusttunnel-tx-udp"
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
                if "trusttunnel-" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        total_bytes += int(parts[1])
        return total_bytes
