"""hydra/plugins/naive/plugin.py — NaiveProxy: Caddy + forwardproxy, Chromium HTTP/2 fingerprint.

Контракт v2 — TRANSPORT-плагин с needs_domain=True:
  • configure() — генерит Caddyfile в памяти.
  • apply() — пишет Caddyfile, caddy validate + systemctl reload.
  • per-user: детерминированные username/password из uuid через derive_key.
  • traffic — iptables accounting (как mieru).
  • nft_tproxy_ports=[443] — трафик заворачивается в sing-box через TPROXY.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.state import AppState, User
from hydra.utils.crypto import derive_key
from hydra.utils.downloader import download_github_asset, verify_elf

BIN_PATH = Path("/usr/local/bin/caddy-naive")
CFG_DIR = Path("/etc/caddy-naive")
CADDYFILE = CFG_DIR / "Caddyfile"
LOG_DIR = Path("/var/log/caddy-naive")
SERVICE_FILE = Path("/etc/systemd/system/caddy-naive.service")
SERVICE_NAME = "caddy-naive"

DEFAULT_PORT = 443

GITHUB_REPO = "Michaol/caddy-naive"


class NaivePlugin(BasePlugin):
    meta = PluginMeta(
        name="naive",
        description="NaiveProxy: Caddy + forwardproxy, Chromium HTTP/2 fingerprint",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=True,
    )

    def __init__(self):
        self._pending_cfg: str | None = None

    # ═════════════════════════════════════════════════════════════════════
    #  Установка / удаление
    # ═════════════════════════════════════════════════════════════════════

    def install(self) -> bool:
        if self._installed():
            return True

        print("  Скачиваю caddy-naive...")
        if not self._download_binary():
            print("  Не удалось установить caddy-naive.")
            return False

        self._install_service()
        return self._installed()

    def uninstall(self) -> bool:
        subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
        subprocess.run(["systemctl", "disable", SERVICE_NAME], capture_output=True)
        if SERVICE_FILE.exists():
            SERVICE_FILE.unlink()
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "reset-failed"], capture_output=True)

        if BIN_PATH.exists():
            BIN_PATH.unlink()
        for d in (CFG_DIR, LOG_DIR):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: генерит Caddyfile в памяти
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        domain = state.network.domain
        port = DEFAULT_PORT

        if not domain:
            self._pending_cfg = None
            return ConfigFragment()

        users = []
        for user in state.users:
            if user.blocked:
                continue
            username = self._derive_username(user.uuid)
            password = self._derive_password(user.uuid)
            users.append({"username": username, "password": password})

        ps = state.protocols.get("naive")
        probe_secret = (ps.config.get("probe_secret", "") if ps and ps.config else "")
        decoy_url = (ps.config.get("decoy_url", "https://www.bing.com") if ps and ps.config else "https://www.bing.com")

        cert_file = (ps.config.get("cert_file", "") if ps and ps.config else "")
        key_file = (ps.config.get("key_file", "") if ps and ps.config else "")
        if not cert_file or not key_file:
            cert_file, key_file = self._find_existing_cert(domain)

        caddyfile = self._build_caddyfile(
            domain=domain,
            port=port,
            users=users,
            probe_secret=probe_secret,
            decoy_url=decoy_url,
            cert_file=cert_file,
            key_file=key_file,
        )

        self._pending_cfg = caddyfile
        return ConfigFragment(
            nft_tproxy_ports=[port],
        )

    def apply(self, state: AppState) -> bool:
        if not self._pending_cfg:
            return False

        CFG_DIR.mkdir(parents=True, exist_ok=True)
        CADDYFILE.write_text(self._pending_cfg)
        CADDYFILE.chmod(0o640)

        err = self._validate_caddy()
        if err:
            print(f"  Caddyfile validation error: {err}")
            return False

        subprocess.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
        time.sleep(2)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("naive", {})
        user.credentials["naive"]["username"] = self._derive_username(user.uuid)
        user.credentials["naive"]["password"] = self._derive_password(user.uuid)
        self.configure(state)
        self.apply(state)

    def on_user_remove(self, user: User, state: AppState) -> None:
        self.configure(state)
        self.apply(state)

    def on_user_block(self, user: User, state: AppState) -> None:
        self.configure(state)
        self.apply(state)

    # ═════════════════════════════════════════════════════════════════════
    #  Клиентский конфиг
    # ═════════════════════════════════════════════════════════════════════

    def generate_client_config(self, user: User, state: AppState) -> str:
        domain = state.network.domain
        if not domain:
            return ""
        username = self._derive_username(user.uuid)
        password = self._derive_password(user.uuid)
        port = DEFAULT_PORT

        outbound = {
            "type": "naive",
            "tag": f"naive-{username}",
            "server": domain,
            "server_port": port,
            "username": username,
            "password": password,
            "tls": {
                "enabled": True,
                "server_name": domain,
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
        domain = state.network.domain
        if not domain:
            return ""
        username = self._derive_username(user.uuid)
        password = self._derive_password(user.uuid)
        port = DEFAULT_PORT

        user_q = urllib.parse.quote(username, safe="")
        pass_q = urllib.parse.quote(password, safe="")
        tag = urllib.parse.quote(username, safe="")
        return f"naive+https://{user_q}:{pass_q}@{domain}:{port}/#{tag}"

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        enabled = CADDYFILE.exists()
        if installed:
            r = subprocess.run(
                ["systemctl", "is-active", SERVICE_NAME],
                capture_output=True, text=True,
            )
            running = r.stdout.strip() == "active"

        info = {}
        if installed and running:
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
            running=running,
            port=DEFAULT_PORT,
            info=info,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        """iptables accounting по username → email (как в mieru)."""
        if not self._installed():
            return {}

        username_to_email: dict[str, str] = {}
        for u in state.users:
            if u.blocked:
                continue
            uname = self._derive_username(u.uuid)
            username_to_email[uname] = u.email

        result: dict[str, int] = {}
        for username, email in username_to_email.items():
            for chain in ("INPUT", "OUTPUT"):
                r = subprocess.run(
                    ["iptables", "-t", "filter", "-L", chain, "-n", "-v", "-x"],
                    capture_output=True, text=True,
                )
                if r.returncode != 0:
                    continue
                for line in r.stdout.splitlines():
                    if username in line:
                        parts = line.split()
                        if len(parts) >= 2 and parts[0].isdigit():
                            result[email] = result.get(email, 0) + int(parts[0])
        return result

    def connected_clients(self, state: AppState | None = None) -> list[dict]:
        """Получает список подключённых клиентов через ss с группировкой по IP."""
        import shutil
        import time
        if not shutil.which("ss"):
            return []

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

            if local_port == DEFAULT_PORT:
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
                if "naive-rx" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rx_bytes += int(parts[1])
        r_tx = subprocess.run(["iptables", "-t", "filter", "-L", "OUTPUT", "-n", "-v", "-x"], capture_output=True, text=True)
        if r_tx.returncode == 0:
            for line in r_tx.stdout.splitlines():
                if "naive-tx" in line:
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
    #  Управление сервисом
    # ═════════════════════════════════════════════════════════════════════

    def on_enable(self, state: AppState) -> None:
        # Интерактивный визард
        modified = False
        from hydra.ui.tui import prompt
        
        domain = state.network.domain
        new_domain = prompt("Введите домен для NaiveProxy (например, proxy.example.com)", default=domain)
        if not new_domain:
            raise ValueError("Домен обязателен для работы NaiveProxy!")
        if new_domain != domain:
            state.network.domain = new_domain
            modified = True

        ps = state.protocols.get("naive")
        if ps:
            if not ps.config:
                ps.config = {}
            current_decoy = ps.config.get("decoy_url", "https://www.bing.com")
            new_decoy = prompt("Введите decoy URL (для маскировки)", default=current_decoy)
            if new_decoy != ps.config.get("decoy_url"):
                ps.config["decoy_url"] = new_decoy
                modified = True
                
            current_secret = ps.config.get("probe_secret", "")
            if not current_secret:
                import secrets
                current_secret = secrets.token_hex(16)
            new_secret = prompt("Введите секрет для защиты от зондирования (probe_resistance)", default=current_secret)
            if new_secret != ps.config.get("probe_secret"):
                ps.config["probe_secret"] = new_secret
                modified = True

            from hydra.ui.tui import confirm
            use_custom = confirm("Использовать собственный SSL-сертификат (указать пути вручную)?", default=False)
            if use_custom:
                custom_cert = prompt("Путь к файлу сертификата (fullchain.pem)", default=ps.config.get("cert_file", ""))
                custom_key = prompt("Путь к приватному ключу (privkey.pem)", default=ps.config.get("key_file", ""))
                if custom_cert and custom_key:
                    ps.config["cert_file"] = custom_cert
                    ps.config["key_file"] = custom_key
                    modified = True
            else:
                if "cert_file" in ps.config:
                    del ps.config["cert_file"]
                    modified = True
                if "key_file" in ps.config:
                    del ps.config["key_file"]
                    modified = True

        if modified:
            from hydra.core.state import save_state
            save_state(state)

        from hydra.utils.firewall import open_tcp
        open_tcp(DEFAULT_PORT, "naive")

        # iptables accounting для подсчёта трафика
        import subprocess
        
        # Проверка доступности порта 443 (чтобы не сломать Let's Encrypt и Caddy)
        # Если мы не running (т.е. включаем первый раз), и порт занят — это конфликт
        r_status = subprocess.run(["systemctl", "is-active", SERVICE_NAME], capture_output=True, text=True)
        if r_status.stdout.strip() != "active":
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', DEFAULT_PORT)) == 0:
                    print(f"  [Предупреждение] Порт {DEFAULT_PORT} уже занят другим процессом. NaiveProxy может не запуститься.")

        self._remove_iptables_rules()
        subprocess.run([
            "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(DEFAULT_PORT),
            "-m", "comment", "--comment", "naive-rx"
        ], capture_output=True)
        subprocess.run([
            "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--sport", str(DEFAULT_PORT),
            "-m", "comment", "--comment", "naive-tx"
        ], capture_output=True)

        self.configure(state)
        self.apply(state)
        r = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True, text=True,
        )
        if r.stdout.strip() != "active":
            subprocess.run(["systemctl", "enable", "--now", SERVICE_NAME], capture_output=True)

    def on_disable(self, state: AppState) -> None:
        from hydra.utils.firewall import close_tcp
        subprocess.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
        close_tcp(DEFAULT_PORT)
        self._remove_iptables_rules()

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _derive_username(uuid: str) -> str:
        import hashlib
        h = hashlib.sha256(f"naive-user|{uuid}".encode()).hexdigest()
        return "u" + h[:8]

    @staticmethod
    def _derive_password(uuid: str) -> str:
        import hashlib
        return hashlib.sha256(f"naive-pass|{uuid}".encode()).hexdigest()[:24]

    def _remove_iptables_rules(self) -> None:
        """Удаляет iptables accounting правила naive-rx/naive-tx."""
        import subprocess
        for chain in ("INPUT", "OUTPUT"):
            r = subprocess.run(["iptables", "-S", chain], capture_output=True, text=True)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "naive-" in line:
                    parts = line.split()
                    if parts[0] == "-A":
                        parts[0] = "-D"
                        subprocess.run(["iptables"] + parts, capture_output=True)

    def _get_total_traffic(self) -> int:
        """Считает суммарный трафик на порту NaiveProxy через iptables accounting."""
        import subprocess
        total_bytes = 0
        for chain in ("INPUT", "OUTPUT"):
            r = subprocess.run(
                ["iptables", "-t", "filter", "-L", chain, "-n", "-v", "-x"],
                capture_output=True, text=True,
            )
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "naive-" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        total_bytes += int(parts[1])
        return total_bytes

    def _find_existing_cert(self, domain: str) -> tuple[str, str]:
        """Ищет существующий сертификат для домена в стандартных путях."""
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

    @staticmethod
    def _installed() -> bool:
        return BIN_PATH.exists() or shutil.which("caddy-naive") is not None

    def _download_binary(self) -> bool:
        from hydra.utils.net import detect_arch
        arch = detect_arch()

        dest = Path("/tmp/caddy-naive-install")
        dest.mkdir(parents=True, exist_ok=True)
        binary = dest / f"caddy-linux-{arch}"

        if not download_github_asset(GITHUB_REPO, f"caddy-linux-{arch}", binary):
            return False

        if not verify_elf(binary):
            return False

        shutil.copy2(str(binary), str(BIN_PATH))
        BIN_PATH.chmod(0o755)
        return True

    @staticmethod
    def _install_service() -> None:
        SERVICE_FILE.write_text(
            "[Unit]\n"
            "Description=NaiveProxy (caddy-forwardproxy-naive)\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=notify\n"
            f"ExecStart={BIN_PATH} run "
            f"--config {CADDYFILE} --adapter caddyfile\n"
            "ExecReload=/bin/kill -USR1 $MAINPID\n"
            "Restart=on-failure\n"
            "RestartSec=5\n"
            "TimeoutStopSec=5\n"
            "LimitNOFILE=1048576\n"
            f"ReadWritePaths={CFG_DIR} {LOG_DIR}\n"
            "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
            "NoNewPrivileges=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        subprocess.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)

    def _build_caddyfile(
        self,
        domain: str,
        port: int,
        users: list[dict],
        probe_secret: str,
        decoy_url: str = "https://www.bing.com",
        cert_file: str = "",
        key_file: str = "",
    ) -> str:
        import subprocess
        auth_lines = ""
        for u in users:
            password_hash = u['password']
            try:
                r = subprocess.run(
                    [str(BIN_PATH), "hash-password", "--plaintext", u['password']],
                    capture_output=True, text=True, check=True
                )
                hashed = r.stdout.strip()
                if hashed.startswith("$2"):
                    password_hash = hashed
            except Exception:
                pass
            auth_lines += f"            basic_auth {u['username']} {password_hash}\n"

        probe_line = ""
        if probe_secret:
            probe_line = f"            probe_resistance {probe_secret}\n"

        if cert_file and key_file:
            tls_line = f"    tls {cert_file} {key_file}\n"
        else:
            tls_line = ""

        return f"""\
{{
    http_port 0
    order forward_proxy before reverse_proxy
}}

{domain}:{port} {{
{tls_line}    forward_proxy {{
{auth_lines}            hide_ip
            hide_via
{probe_line}    }}
    reverse_proxy {decoy_url} {{
        header_up Host {{upstream_hostport}}
    }}
    log {{
        output file {LOG_DIR}/access.log {{
            roll_size 10mb
            roll_keep 3
        }}
    }}
}}
"""

    def _validate_caddy(self) -> str | None:
        r = subprocess.run(
            [str(BIN_PATH), "validate",
             "--config", str(CADDYFILE), "--adapter", "caddyfile"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return (r.stderr or r.stdout or "")[:300]
        return None
