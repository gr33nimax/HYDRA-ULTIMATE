"""hydra/plugins/anytls/plugin.py — AnyTLS: TLS-shaped tunnel с padding scheme (sing-box inbound)."""
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
from hydra.utils.crypto import derive_key
from hydra.utils.net import public_ip

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

    def configure(self, state: AppState) -> ConfigFragment:
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
        from hydra.core.sni_router import get_effective_port
        listen_port = get_effective_port("anytls", state)

        inbound = {
            "type": "anytls",
            "tag": "anytls-in",
            "listen": "::",
            "listen_port": listen_port,
            "users": users,
            "padding_scheme": DEFAULT_PADDING_SCHEME,
            "tls": {
                "enabled": True,
                "server_name": anytls_domain,
                "certificate_path": cert_file,
                "key_path": key_file,
            },
        }
        return ConfigFragment(inbounds=[inbound])

    def apply(self, state: AppState) -> bool:
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("anytls", {})
        user.credentials["anytls"]["username"] = self._derive_username(user)
        user.credentials["anytls"]["password"] = self._derive_password(user.uuid)

    def on_user_remove(self, user: User, state: AppState) -> None:
        pass

    def on_user_block(self, user: User, state: AppState) -> None:
        pass

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентские конфиги
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
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

    def client_link(self, user: User, state: AppState) -> str:
        ps = state.protocols.get("anytls")
        anytls_domain = (ps.config.get("domain", "") if ps and ps.config else "")
        if not anytls_domain:
            return ""

        password = self._derive_password(user.uuid)
        server_ip = state.network.server_ip or public_ip()
        tag = urllib.parse.quote(self._derive_username(user), safe="")

        return f"anytls://{password}@{server_ip}:443?sni={anytls_domain}#{tag}"

    # ═════════════════════════════════════════════════════════════════════
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        ps = state.protocols.get("anytls")
        if not ps:
            from hydra.core.state import get_protocol
            ps = get_protocol(state, "anytls")

        # 1. Визард: запросить ОТДЕЛЬНЫЙ домен для AnyTLS
        anytls_domain = ps.config.get("domain", "") if ps and ps.config else ""
        if not anytls_domain:
            from hydra.ui.tui import prompt
            anytls_domain = prompt(
                "Введите домен для AnyTLS (ДОЛЖЕН ОТЛИЧАТЬСЯ от домена NaiveProxy!)"
            )
            if not anytls_domain:
                raise ValueError("Домен обязателен для AnyTLS!")
            
            # Проверка: не совпадает ли с доменом naive
            if anytls_domain == state.network.domain:
                naive_ps = state.protocols.get("naive")
                if naive_ps and naive_ps.enabled:
                    raise ValueError(
                        f"Домен {anytls_domain} уже используется NaiveProxy! "
                        "AnyTLS требует отдельный домен."
                    )
            
            ps.config["domain"] = anytls_domain
        
        # 2. Получить TLS-сертификат (автоматически или найти существующий)
        cert_file, key_file = self._resolve_certs(anytls_domain, ps)
        if not cert_file or not key_file:
            # Автоматическое получение через certbot (HTTP-01 challenge, порт 80)
            print(f"  Получаю TLS-сертификат для {anytls_domain}...")
            ok = self._obtain_cert_certbot(anytls_domain)
            if ok:
                cert_file, key_file = self._find_existing_cert(anytls_domain)
        
        if not cert_file or not key_file:
            # Fallback: ручной ввод
            from hydra.ui.tui import prompt
            cert_file = prompt("Путь к сертификату (fullchain.pem)", default="")
            key_file = prompt("Путь к приватному ключу (privkey.pem)", default="")
        
        if not cert_file or not key_file:
            raise ValueError(
                f"TLS-сертификат для домена {anytls_domain} не получен! "
                "Проверьте DNS-записи и доступность порта 80."
            )
        
        ps.config["cert_file"] = cert_file
        ps.config["key_file"] = key_file
        
        # 3. Firewall (порт 443 — если ещё не открыт naive)
        from hydra.utils.firewall import open_tcp
        open_tcp(443, "anytls")
        
        # 4. iptables accounting
        self._remove_iptables_rules()
        self._add_iptables_rules()
        
        # Выставляем enabled = True, чтобы rebuild знал, что AnyTLS включен
        ps.enabled = True
        
        # 5. Пересобрать SNI-мультиплексор (если нужен)
        from hydra.core.sni_router import rebuild
        rebuild(state)

    def on_disable(self, state: AppState) -> None:
        self._remove_iptables_rules()
        
        ps = state.protocols.get("anytls")
        if ps:
            ps.enabled = False
        
        # Пересобрать SNI-мультиплексор (возможно отключить)
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
            ps = state.protocols.get("anytls")
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

        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=installed and is_running() and enabled,
            port=443,
            info=info,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

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
        effective_port = get_effective_port("anytls", state) if state else 443
        
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
            
            # Фильтруем по внутреннему эффективному порту или по 443
            if local_port == effective_port or local_port == 443:
                remote_addr = parts[3]
                remote_parts = remote_addr.split(":")
                remote_ip = ":".join(remote_parts[:-1]).strip("[]")
                ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1
                
        # rx/tx из iptables accounting
        rx_bytes = 0
        tx_bytes = 0
        r_rx = subprocess.run(["iptables", "-t", "filter", "-L", "INPUT", "-n", "-v", "-x"], capture_output=True, text=True)
        if r_rx.returncode == 0:
            for line in r_rx.stdout.splitlines():
                if "anytls-rx" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rx_bytes += int(parts[1])
        r_tx = subprocess.run(["iptables", "-t", "filter", "-L", "OUTPUT", "-n", "-v", "-x"], capture_output=True, text=True)
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
        return derive_key("anytls-pass", uuid)

    def _resolve_certs(self, domain: str, ps) -> tuple[str, str]:
        """Ищет существующий TLS-сертификат для домена.
        
        Порядок поиска:
        1. Из ps.config["cert_file"] / ps.config["key_file"] (ручной ввод)
        2. /etc/letsencrypt/live/{domain}/ (certbot)
        3. /etc/xray/{domain}.crt/.key
        """
        cert = (ps.config.get("cert_file", "") if ps and ps.config else "")
        key = (ps.config.get("key_file", "") if ps and ps.config else "")
        if cert and key:
            return cert, key
        return self._find_existing_cert(domain)

    def _find_existing_cert(self, domain: str) -> tuple[str, str]:
        """Поиск сертификата в стандартных путях (аналогично naive)."""
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
        """Автоматическое получение сертификата через certbot.

        Использует HTTP-01 challenge (порт 80).
        Временно открывает порт 80 в UFW/iptables.
        """
        import shutil
        from hydra.utils.firewall import is_ufw_active

        # 1. Проверяем/устанавливаем certbot
        if not shutil.which("certbot"):
            print("  Устанавливаю certbot...")
            subprocess.run(["apt-get", "update"], capture_output=True)
            subprocess.run(["apt-get", "install", "-y", "certbot"], capture_output=True)

        # 2. Временно открываем порт 80 в фаерволе
        ufw_opened = False
        ipt_opened = False
        if is_ufw_active():
            subprocess.run(["ufw", "allow", "80/tcp", "comment", "temp-certbot"], capture_output=True)
            ufw_opened = True
        else:
            # Проверяем, нет ли уже правила в iptables
            r_chk = subprocess.run([
                "iptables", "-C", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"
            ], capture_output=True)
            if r_chk.returncode != 0:
                subprocess.run([
                    "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"
                ], capture_output=True)
                ipt_opened = True

        # 3. Запускаем certbot
        r = subprocess.run([
            "certbot", "certonly", "--standalone",
            "-d", domain,
            "--non-interactive", "--agree-tos",
            "--register-unsafely-without-email",
        ], capture_output=True, text=True)

        success = r.returncode == 0

        if not success:
            print(f"  [Ошибка certbot] Вывод:\n{r.stderr or r.stdout or ''}")

        # 4. Закрываем порт 80 в фаерволе
        if ufw_opened:
            subprocess.run(["ufw", "delete", "allow", "80/tcp"], capture_output=True)
        if ipt_opened:
            subprocess.run([
                "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"
            ], capture_output=True)

        return success

    def _remove_iptables_rules(self) -> None:
        """Удаляет правила anytls-rx / anytls-tx."""
        for chain in ("INPUT", "OUTPUT"):
            r = subprocess.run(["iptables", "-S", chain], capture_output=True, text=True)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "anytls-" in line:
                    parts = line.split()
                    if parts[0] == "-A":
                        parts[0] = "-D"
                        subprocess.run(["iptables"] + parts, capture_output=True)

    def _add_iptables_rules(self) -> None:
        """Добавляет iptables accounting для порта 443."""
        subprocess.run([
            "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "443",
            "-m", "comment", "--comment", "anytls-rx"
        ], capture_output=True)
        subprocess.run([
            "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--sport", "443",
            "-m", "comment", "--comment", "anytls-tx"
        ], capture_output=True)

    def _get_total_traffic(self) -> int:
        """Суммарный трафик через iptables accounting."""
        total_bytes = 0
        for chain in ("INPUT", "OUTPUT"):
            r = subprocess.run(
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
