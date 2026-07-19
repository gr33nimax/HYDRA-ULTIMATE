"""TrustTunnel transport: HTTP/2 TCP and experimental QUIC via sing-box."""
from __future__ import annotations

from hydra.core.host import HOST
from hydra.core.errors import HostOperationError

import copy
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


_VALID_TRANSPORTS = {"tcp", "quic", "both"}
_DEFAULT_TRANSPORT = "tcp"


class TrustTunnelPlugin(BasePlugin):
    meta = PluginMeta(
        name="trusttunnel",
        description="TrustTunnel: HTTP/2 and QUIC obfuscated tunnel (sing-box inbound)",
        category=PluginCategory.TRANSPORT,
        version="2.1.0",
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

        transport = self._transport(ps)
        if transport in ("quic", "both"):
            from hydra.core.sni_router import get_quic_owner
            get_quic_owner(state)

        # TrustTunnel всегда находится за Caddy L4: TCP проходит через HTTP
        # reverse-proxy, UDP/QUIC — через raw UDP proxy.
        from hydra.core.sni_router import get_effective_port, needs_mux
        listen_port = get_effective_port("trusttunnel", state)
        behind_mux = needs_mux(state)

        inbounds = []

        if transport in ("tcp", "both"):
            inbounds.append(self._build_tcp_inbound(
                domain, cert_file, key_file, users, listen_port, behind_mux,
            ))

        if transport in ("quic", "both"):
            inbounds.append(self._build_quic_inbound(
                domain, cert_file, key_file, users, listen_port, behind_mux,
            ))

        return ConfigFragment(inbounds=inbounds)

    @staticmethod
    def _build_tcp_inbound(domain: str, cert_file: str, key_file: str,
                           users: list[dict], listen_port: int,
                           behind_mux: bool) -> dict:
        return {
            "type": "trusttunnel",
            "tag": "trusttunnel-in",
            "listen": "127.0.0.1" if behind_mux else "::",
            "listen_port": listen_port,
            "network": "tcp",
            "users": users,
            "tls": {
                "enabled": True,
                "server_name": domain,
                "certificate_path": cert_file,
                "key_path": key_file,
                "alpn": ["h2"],
            },
        }

    @staticmethod
    def _build_quic_inbound(domain: str, cert_file: str, key_file: str,
                            users: list[dict], listen_port: int,
                            behind_mux: bool) -> dict:
        # Проверено для sing-box extended 1.13.14: server-side QUIC выбирается
        # network=udp; поле quic на inbound не поддерживается.
        return {
            "type": "trusttunnel",
            "tag": "trusttunnel-quic-in",
            "listen": "127.0.0.1" if behind_mux else "::",
            "listen_port": listen_port,
            "network": "udp",
            "users": users,
            "tls": {
                "enabled": True,
                "server_name": domain,
                "certificate_path": cert_file,
                "key_path": key_file,
                "alpn": ["h3"],
            },
        }

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

        transport = self._transport(ps)
        # Domain is required above; never emit an empty QUIC remote endpoint.
        server = domain
        outbounds = []

        if transport in ("tcp", "both"):
            outbounds.append(self._build_client_outbound(
                server, domain, username, password, quic=False,
            ))

        if transport in ("quic", "both"):
            outbounds.append(self._build_client_outbound(
                server, domain, username, password, quic=True,
            ))

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

    @staticmethod
    def _build_client_outbound(server: str, domain: str, username: str,
                               password: str, quic: bool) -> dict:
        outbound = {
            "type": "trusttunnel",
            "tag": f"trusttunnel{'-quic' if quic else ''}-{username}",
            "server": server,
            "server_port": 443,
            "username": username,
            "password": password,
            "tls": {
                "enabled": True,
                "server_name": domain,
            },
        }
        if quic:
            # В client outbound используем отдельный флаг core, а не
            # network=udp (последнее означает тип проксируемого трафика).
            outbound["quic"] = True
            outbound["tls"]["alpn"] = ["h3"]
        return outbound

    def client_link(self, user: User, state: AppState) -> str:
        """Основная ссылка (для совместимости). При both — возвращает TCP."""
        ps = state.protocols.get("trusttunnel")
        domain = (ps.config.get("domain", "") if ps and ps.config else "")
        if not domain:
            return ""

        username = urllib.parse.quote(self._derive_username(user), safe="")
        password = urllib.parse.quote(self._derive_password(user.uuid), safe="")
        transport = self._transport(ps)
        alpn = "h3" if transport == "quic" else "h2"
        suffix = " TrustTunnel QUIC" if transport == "quic" else ""
        tag = urllib.parse.quote(f"{self._derive_username(user)}{suffix}", safe="")

        return f"tt://{username}:{password}@{domain}:443?security=tls&sni={domain}&alpn={alpn}#{tag}"

    def client_links(self, user: User, state: AppState) -> list[str]:
        """Возвращает TCP/QUIC ссылки, сохраняя существующий URI-формат."""
        ps = state.protocols.get("trusttunnel")
        domain = (ps.config.get("domain", "") if ps and ps.config else "")
        if not domain:
            return []

        username = urllib.parse.quote(self._derive_username(user), safe="")
        password = urllib.parse.quote(self._derive_password(user.uuid), safe="")
        transport = self._transport(ps)
        links = []
        if transport in ("tcp", "both"):
            tag = urllib.parse.quote(self._derive_username(user), safe="")
            links.append(
                f"tt://{username}:{password}@{domain}:443?security=tls&sni={domain}&alpn=h2#{tag}"
            )
        if transport in ("quic", "both"):
            tag = urllib.parse.quote(
                f"{self._derive_username(user)} TrustTunnel QUIC", safe="",
            )
            links.append(
                f"tt://{username}:{password}@{domain}:443?security=tls&sni={domain}&alpn=h3#{tag}"
            )
        return links

    # ═════════════════════════════════════════════════════════════════════
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        ps = state.protocols.get("trusttunnel")
        if not ps:
            from hydra.core.state import get_protocol
            ps = get_protocol(state, "trusttunnel")

        ps.config.setdefault("transport", _DEFAULT_TRANSPORT)
        transport = self._transport(ps)
        domain = ps.config.get("domain", "") if ps and ps.config else ""
        if not domain:
            from hydra.ui.tui import prompt
            domain = prompt(
                "Введите домен для TrustTunnel (ДОЛЖЕН ОТЛИЧАТЬСЯ от домена NaiveProxy/AnyTLS!)"
            )
            if not domain:
                raise ValueError("Домен обязателен для TrustTunnel!")
            
            ps.config["domain"] = domain

        validation_errors = self.validate_config(state, require_cert=False,
                                                 prospective_enable=True)
        if validation_errors:
            raise ValueError("; ".join(validation_errors))
        
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
        
        # Firewall: Caddy L4 является внешним владельцем TCP/UDP 443.
        from hydra.utils.firewall import open_tcp
        open_tcp(443, "trusttunnel")
        if transport in ("quic", "both"):
            from hydra.utils.firewall import open_udp
            open_udp(443, "udp-quic-mux")

        # Удаляем legacy accounting rules: per-user статистика уже ведётся
        # traffic_daemon, а общие портовые счётчики нельзя честно разнести
        # по подключённым пользователям.
        self._remove_iptables_rules()

    def on_disable(self, state: AppState) -> None:
        """Удаляет только legacy-ресурсы; общий config применяет orchestrator."""
        self._remove_iptables_rules()
        ps = state.protocols.get("trusttunnel")
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
            ps = state.protocols.get("trusttunnel")
            if ps:
                enabled = ps.enabled
        except Exception:
            pass

        info = {}
        health_report: dict[str, object] | None = None
        if installed and enabled:
            try:
                total = self._get_total_traffic(state)
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
            try:
                health_report = self.health(state)
                errors = health_report.get("errors", [])
                if errors:
                    info["Проверка"] = str(errors[0])
            except Exception:
                health_report = None

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
            running=(
                installed and enabled
                and bool(health_report and health_report.get("ok"))
            ),
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
        transport = self._transport(
            state.protocols.get("trusttunnel") if state else None
        )
        
        ip_counts: dict[tuple[str, str], int] = {}
        if transport in ("tcp", "both"):
            self._collect_ss_clients(
                ["ss", "-t", "-H", "-n", "state", "established"],
                effective_port, "TCP", ip_counts,
            )
        if transport in ("quic", "both"):
            self._collect_ss_clients(
                ["ss", "-u", "-H", "-n"],
                effective_port, "QUIC", ip_counts,
            )

        clients = []
        now_ts = int(time.time())
        for (kind, remote_ip), count in ip_counts.items():
            clients.append({
                "online": True,
                "email": f"{remote_ip} ({kind}, {count} Conns)",
                "rx": 0,
                "tx": 0,
                "last_handshake": now_ts,
            })
        return clients

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _transport(ps) -> str:
        value = ps.config.get("transport", _DEFAULT_TRANSPORT) if ps and ps.config else _DEFAULT_TRANSPORT
        return value if value in _VALID_TRANSPORTS else _DEFAULT_TRANSPORT

    def validate_config(self, state: AppState, require_cert: bool = True,
                        prospective_enable: bool = False) -> list[str]:
        """Возвращает ошибки до изменения runtime-конфигурации."""
        ps = state.protocols.get("trusttunnel")
        if not ps:
            return ["состояние TrustTunnel отсутствует"]

        errors = []
        transport = ps.config.get("transport", _DEFAULT_TRANSPORT)
        if transport not in _VALID_TRANSPORTS:
            errors.append(f"неизвестный транспорт: {transport}")

        domain = ps.config.get("domain", "").strip()
        if not domain:
            errors.append("домен TrustTunnel не задан")
        else:
            naive = state.protocols.get("naive")
            if naive and naive.enabled and state.network.domain == domain:
                errors.append(f"домен {domain} уже используется NaiveProxy")
            for other_name in ("anytls",):
                other = state.protocols.get(other_name)
                if other and other.enabled and other.config.get("domain") == domain:
                    errors.append(f"домен {domain} уже используется {other_name}")

        if require_cert and domain:
            cert_file, key_file = self._resolve_certs(domain, ps)
            if not cert_file or not key_file:
                errors.append(f"TLS-сертификат для {domain} не найден")

        if self._transport(ps) in ("quic", "both"):
            try:
                from hydra.core.sni_router import get_quic_owner
                get_quic_owner(
                    state,
                    prospective="trusttunnel" if prospective_enable else None,
                )
            except ValueError as exc:
                errors.append(str(exc))
        return errors

    def health(self, state: AppState) -> dict[str, object]:
        """Лёгкий health report без сетевого подключения к внешнему сайту."""
        ps = state.protocols.get("trusttunnel")
        transport = self._transport(ps)
        errors = self.validate_config(state)
        report: dict[str, object] = {
            "ok": not errors,
            "transport": transport,
            "errors": errors,
            "singbox": False,
            "caddy_l4": False,
        }
        try:
            from hydra.core.singbox import is_running
            report["singbox"] = is_running()
        except Exception:
            pass
        try:
            r = HOST.run(
                ["systemctl", "is-active", "--quiet", "caddy-l4"],
                capture_output=True,
            )
            report["caddy_l4"] = r.returncode == 0
        except OSError:
            pass
        report["ok"] = bool(report["ok"] and report["singbox"] and report["caddy_l4"])
        return report

    def set_transport(self, state: AppState, transport: str) -> bool:
        """Транзакционно переключает transport и откатывает runtime при сбое."""
        if transport not in _VALID_TRANSPORTS:
            return False
        from hydra.core.state import get_protocol, save_state

        ps = get_protocol(state, "trusttunnel")
        old_config = copy.deepcopy(ps.config)
        ps.config["transport"] = transport
        errors = self.validate_config(
            state, require_cert=ps.enabled, prospective_enable=not ps.enabled,
        )
        if errors:
            ps.config = old_config
            return False

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
        save_state(state)
        try:
            apply_config(state)
        except Exception:
            pass
        return False

    @staticmethod
    def _split_endpoint(endpoint: str) -> tuple[str, int | None]:
        endpoint = endpoint.strip()
        if endpoint.startswith("[") and "]:" in endpoint:
            host, _, port = endpoint[1:].partition("]:")
        else:
            host, sep, port = endpoint.rpartition(":")
            if not sep:
                return endpoint.strip("[]"), None
        return host.strip("[]"), int(port) if port.isdigit() else None

    def _collect_ss_clients(self, cmd: list[str], port: int, kind: str,
                            counts: dict[tuple[str, str], int]) -> None:
        try:
            result = HOST.run(cmd, capture_output=True, text=True)
        except OSError:
            return
        if result.returncode != 0:
            return
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            _, local_port = self._split_endpoint(parts[-2])
            remote_host, _ = self._split_endpoint(parts[-1])
            if local_port != port or not remote_host or remote_host == "*":
                continue
            key = (kind, remote_host)
            counts[key] = counts.get(key, 0) + 1



    @staticmethod
    def _derive_username(user: User) -> str:
        return user.email

    @staticmethod
    def _derive_password(uuid: str) -> str:
        return derive_hex_key("trusttunnel-pass", uuid)

    def _resolve_certs(self, domain: str, ps) -> tuple[str, str]:
        cert = (ps.config.get("cert_file", "") if ps and ps.config else "")
        key = (ps.config.get("key_file", "") if ps and ps.config else "")
        if cert and key and Path(cert).exists() and Path(key).exists():
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
                r = HOST.run(
                    ["openssl", "x509", "-checkend", "2592000", "-noout", "-in", str(cert_path)],
                    capture_output=True
                )
                if r.returncode == 0:
                    print(f"  Сертификат для {domain} уже существует и действителен.")
                    return True
            except Exception:
                pass

        import shutil
        from hydra.utils.firewall import temporary_open_port

        if not shutil.which("certbot"):
            print("  Устанавливаю certbot...")
            HOST.run(["apt-get", "update"], capture_output=True)
            HOST.run(["apt-get", "install", "-y", "certbot"], capture_output=True)

        services_to_stop = ["caddy-l4", "caddy-naive", "nginx", "apache2"]
        was_running: list[str] = []
        try:
            for service in services_to_stop:
                status = HOST.run(
                    ["systemctl", "is-active", service],
                    capture_output=True, text=True,
                )
                if status.stdout.strip() == "active":
                    print(f"  Временно останавливаю {service}...")
                    stopped = HOST.run(
                        ["systemctl", "stop", service], capture_output=True,
                    )
                    if stopped.returncode == 0:
                        was_running.append(service)

            with temporary_open_port("tcp", 80, "temp-certbot"):
                result = HOST.run([
                    "certbot", "certonly", "--standalone",
                    "-d", domain,
                    "--non-interactive", "--agree-tos",
                    "--register-unsafely-without-email",
                    "--keep-until-expiring",
                ], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"  [Ошибка certbot] Вывод:\n{result.stderr or result.stdout or ''}")
            return result.returncode == 0
        except (OSError, HostOperationError) as exc:
            print(f"  [Ошибка certbot] {exc}")
            return False
        finally:
            for service in was_running:
                print(f"  Восстанавливаю {service}...")
                HOST.run(
                    ["systemctl", "start", service], capture_output=True,
                )

    def _remove_iptables_rules(self) -> None:
        for chain in ("INPUT", "OUTPUT"):
            r = HOST.run(["iptables", "-S", chain], capture_output=True, text=True)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "trusttunnel-" in line:
                    parts = line.split()
                    if parts[0] == "-A":
                        parts[0] = "-D"
                        HOST.run(["iptables"] + parts, capture_output=True)

    @staticmethod
    def _get_total_traffic(state: AppState) -> int:
        return sum(
            int(user.credentials.get("trusttunnel", {}).get("traffic_used_bytes", 0))
            for user in state.users
        )
