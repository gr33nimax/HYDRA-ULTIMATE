"""hydra/plugins/naive/plugin.py — NaiveProxy: Caddy + forwardproxy, Chromium HTTP/2 fingerprint.

Контракт v2 — TRANSPORT-плагин с needs_domain=True:
  • configure() — генерит Caddyfile в памяти.
  • apply() — создает фейковый сайт, пишет Caddyfile, caddy validate + systemctl reload.
  • per-user: детерминированные username/password из uuid через derive_key.
  • traffic — iptables accounting (как mieru).
  • TLS & HAProxy: использует certbot / существующий SSL-сертификат для корректной работы за HAProxy.
  • sing-box integration: исходящий трафик проксируется в sing-box через `upstream socks5://127.0.0.1:1080`.
  • probe resistance: незнакомые клиенты получают отклик от фейкового HTML-файла.
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
from hydra.utils.crypto import derive_hex_key
from hydra.utils.downloader import download_github_asset, verify_elf

BIN_PATH = Path("/usr/local/bin/caddy-naive")
CFG_DIR = Path("/etc/caddy-naive")
CADDYFILE = CFG_DIR / "Caddyfile"
LOG_DIR = Path("/var/log/caddy-naive")
FAKE_SITE_DIR = Path("/var/www/naive-fake")
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
        for d in (CFG_DIR, LOG_DIR, Path("/var/lib/caddy-naive")):
            if d.exists():
                shutil.rmtree(d, ignore_errors=True)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  configure — чистая: генерит Caddyfile в памяти
    # ═════════════════════════════════════════════════════════════════════

    def configure(self, state: AppState) -> ConfigFragment:
        domain = state.network.domain
        from hydra.core.sni_router import get_effective_port
        port = get_effective_port("naive", state)

        if not domain:
            self._pending_cfg = None
            return ConfigFragment()

        users = []
        for user in state.users:
            if user.blocked:
                continue
            username = self._derive_username(user)
            password = self._derive_password(user.uuid)
            users.append({"username": username, "password": password})

        ps = state.protocols.get("naive")
        decoy_url = (ps.config.get("decoy_url", "") if ps and ps.config else "")

        cert_file, key_file = self._resolve_certs(domain, ps)
        if not cert_file or not key_file:
            if self._obtain_cert_certbot(domain):
                cert_file, key_file = self._find_existing_cert(domain)
                if ps and ps.config is not None:
                    ps.config["cert_file"] = cert_file
                    ps.config["key_file"] = key_file

        caddyfile = self._build_caddyfile(
            domain=domain,
            port=port,
            users=users,
            fake_site_dir=str(FAKE_SITE_DIR),
            cert_file=cert_file,
            key_file=key_file,
            decoy_url=decoy_url,
        )

        self._pending_cfg = caddyfile
        return ConfigFragment()

    def apply(self, state: AppState) -> bool:
        if not self._pending_cfg:
            return False

        CFG_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        Path("/var/lib/caddy-naive").mkdir(parents=True, exist_ok=True)
        self._create_fake_site()

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
        user.credentials["naive"]["username"] = self._derive_username(user)
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
        username = self._derive_username(user)
        password = self._derive_password(user.uuid)
        port = DEFAULT_PORT

        outbound = {
            "type": "naive",
            "tag": f"naive-{username}",
            "server": domain,
            "server_port": port,
            "username": username,
            "password": password,
            "network": "udp",
            "quic": True,
            "tls": {
                "enabled": True,
                "server_name": domain,
                "alpn": ["h3", "h2"],
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
        username = self._derive_username(user)
        password = self._derive_password(user.uuid)
        port = DEFAULT_PORT

        user_q = urllib.parse.quote(username, safe="")
        pass_q = urllib.parse.quote(password, safe="")
        tag = urllib.parse.quote(username, safe="")
        sni_q = urllib.parse.quote(domain, safe="")
        return f"naive+quic://{user_q}:{pass_q}@{domain}:{port}?congestion_control=bbr&security=tls&sni={sni_q}&alpn#{tag}"

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

        effective_port = DEFAULT_PORT
        try:
            from hydra.core.state import load_state
            from hydra.core.sni_router import get_effective_port
            state = load_state()
            effective_port = get_effective_port("naive", state)
        except Exception:
            pass

        return PluginStatus(
            installed=installed,
            enabled=enabled,
            running=running,
            port=effective_port,
            info=info,
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        import json
        log_file = LOG_DIR / "access.log"
        if not self._installed() or not log_file.exists():
            return {}

        uname_to_email = {}
        for u in state.users:
            uname = self._derive_username(u)
            uname_to_email[uname] = u.email

        result: dict[str, int] = {}
        try:
            with log_file.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        user_id = data.get("user_id")
                        if not user_id:
                            user_id = data.get("user")
                        if user_id:
                            size = data.get("size", 0)
                            email = uname_to_email.get(user_id)
                            if email:
                                result[email] = result.get(email, 0) + size
                    except Exception:
                        continue
        except Exception:
            pass
        return result

    def connected_clients(self, state: AppState | None = None) -> list[dict]:
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

            from hydra.core.sni_router import get_effective_port
            effective = get_effective_port("naive", state) if state else DEFAULT_PORT
            if local_port == effective or local_port == DEFAULT_PORT:
                remote_addr = parts[3]
                remote_parts = remote_addr.split(":")
                remote_ip = ":".join(remote_parts[:-1]).strip("[]")
                ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1

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
        ps = state.protocols.get("naive")
        if not ps:
            return

        domain = state.network.domain
        has_config = bool(domain and ps.config and "decoy_url" in ps.config)

        if not has_config:
            from hydra.ui.tui import prompt
            new_domain = prompt("Введите домен для NaiveProxy (например, proxy.example.com)", default=domain)
            if not new_domain:
                raise ValueError("Домен обязателен для работы NaiveProxy!")
            if new_domain != domain:
                state.network.domain = new_domain
                domain = new_domain

            if not ps.config:
                ps.config = {}

            decoy_url = prompt(
                "URL или домен для сайта-декоя (например, https://bing.com или опустите для HTML-заглушки)",
                default=ps.config.get("decoy_url", "")
            )
            ps.config["decoy_url"] = decoy_url

            from hydra.ui.tui import confirm
            use_custom = confirm("Использовать собственный SSL-сертификат (указать пути вручную)?", default=False)
            if use_custom:
                custom_cert = prompt("Путь к файлу сертификата (fullchain.pem)", default=ps.config.get("cert_file", ""))
                custom_key = prompt("Путь к приватному ключу (privkey.pem)", default=ps.config.get("key_file", ""))
                if custom_cert and custom_key:
                    ps.config["cert_file"] = custom_cert
                    ps.config["key_file"] = custom_key

            from hydra.core.state import save_state
            save_state(state)

        # Разрешение / получение TLS-сертификата (certbot)
        cert_file, key_file = self._resolve_certs(domain, ps)
        if not cert_file or not key_file:
            print(f"  Получаю TLS-сертификат для {domain} через certbot...")
            if self._obtain_cert_certbot(domain):
                cert_file, key_file = self._find_existing_cert(domain)

        if cert_file and key_file:
            ps.config["cert_file"] = cert_file
            ps.config["key_file"] = key_file

        from hydra.utils.firewall import open_tcp
        open_tcp(DEFAULT_PORT, "naive")

        self._remove_iptables_rules()
        subprocess.run([
            "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(DEFAULT_PORT),
            "-m", "comment", "--comment", "naive-rx"
        ], capture_output=True)
        subprocess.run([
            "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--sport", str(DEFAULT_PORT),
            "-m", "comment", "--comment", "naive-tx"
        ], capture_output=True)

        ps.enabled = True

        from hydra.core.sni_router import rebuild
        rebuild(state)

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

        ps = state.protocols.get("naive")
        if ps:
            ps.enabled = False

        from hydra.core.sni_router import rebuild
        rebuild(state)

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _create_fake_site() -> None:
        FAKE_SITE_DIR.mkdir(parents=True, exist_ok=True)
        index_file = FAKE_SITE_DIR / "index.html"
        if not index_file.exists():
            index_file.write_text(
                "<!DOCTYPE html><html><head><title>Welcome</title></head>"
                "<body><h1>Welcome</h1><p>This site is under maintenance.</p></body></html>\n"
            )

    @staticmethod
    def _derive_username(user: User) -> str:
        clean = user.email.split("@")[0]
        sanitized = "".join(c for c in clean if c.isalnum() or c in ("_", "-"))
        return sanitized or user.email

    @staticmethod
    def _derive_password(uuid: str) -> str:
        return derive_hex_key("naive-pass", uuid)[:24]

    def _remove_iptables_rules(self) -> None:
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
        """Автоматическое получение сертификата через certbot (HTTP-01 challenge, порт 80)."""
        from hydra.utils.firewall import is_ufw_active

        if not shutil.which("apt-get") and not shutil.which("certbot"):
            return False

        if not shutil.which("certbot"):
            print("  Устанавливаю certbot...")
            subprocess.run(["apt-get", "update"], capture_output=True)
            subprocess.run(["apt-get", "install", "-y", "certbot"], capture_output=True)

        services_to_stop = ["caddy-naive", "nginx", "apache2"]
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
            r_chk = subprocess.run(["iptables", "-C", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"], capture_output=True)
            if r_chk.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"], capture_output=True)
                ipt_opened = True

        r = subprocess.run([
            "certbot", "certonly", "--standalone",
            "-d", domain,
            "--non-interactive", "--agree-tos",
            "--register-unsafely-without-email",
        ], capture_output=True, text=True)

        success = r.returncode == 0
        if not success:
            print(f"  [Ошибка certbot] Вывод:\n{r.stderr or r.stdout or ''}")

        if ufw_opened:
            subprocess.run(["ufw", "delete", "allow", "80/tcp"], capture_output=True)
        if ipt_opened:
            subprocess.run(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"], capture_output=True)

        for s in was_running:
            if s != "caddy-naive":
                print(f"  Восстанавливаю {s}...")
                subprocess.run(["systemctl", "start", s], capture_output=True)

        return success

    @staticmethod
    def _installed() -> bool:
        return BIN_PATH.exists() or shutil.which("caddy-naive") is not None

    def _download_binary(self) -> bool:
        from hydra.utils.net import detect_arch
        arch = detect_arch()

        dest = Path("/tmp/caddy-naive-install")
        dest.mkdir(parents=True, exist_ok=True)
        binary = dest / f"caddy-linux-{arch}"

        download_ok = download_github_asset(GITHUB_REPO, f"caddy-linux-{arch}", binary)

        if not download_ok:
            from hydra.utils.downloader import download
            direct_url = f"https://github.com/{GITHUB_REPO}/releases/latest/download/caddy-linux-{arch}"
            download_ok = download(direct_url, binary)

        if not download_ok:
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
            "RestartSec=1\n"
            "TimeoutStopSec=5\n"
            "Environment=\"XDG_DATA_HOME=/var/lib/caddy-naive\"\n"
            "Environment=\"XDG_CONFIG_HOME=/var/lib/caddy-naive\"\n"
            "LimitNOFILE=1048576\n"
            f"ReadWritePaths={CFG_DIR} {LOG_DIR} {FAKE_SITE_DIR} /var/lib/caddy-naive\n"
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
        probe_secret: str = "",
        fake_site_dir: str = "/var/www/naive-fake",
        cert_file: str = "",
        key_file: str = "",
        decoy_url: str = "",
    ) -> str:
        auth_lines = ""
        for u in users:
            auth_lines += f"            basic_auth {u['username']} {u['password']}\n"

        if cert_file and key_file:
            tls_line = f"    tls {cert_file} {key_file}\n"
        else:
            tls_line = ""

        if decoy_url:
            target_decoy = decoy_url.strip()
            if not target_decoy.startswith("http://") and not target_decoy.startswith("https://"):
                target_decoy = f"https://{target_decoy}"
            decoy_block = f"    reverse_proxy {target_decoy} {{\n        header_up Host {{upstream_hostport}}\n    }}\n"
            order_line = "    order forward_proxy before reverse_proxy\n"
        else:
            decoy_block = f"    file_server {{\n        root {fake_site_dir}\n    }}\n"
            order_line = "    order forward_proxy before file_server\n"

        site_header = f":{port}, {domain}:{port}"
        probe_line = "            probe_resistance\n" if auth_lines else ""

        return f"""\
{{
    http_port 0
{order_line}}}

{site_header} {{
{tls_line}    forward_proxy {{
{auth_lines}            hide_ip
            hide_via
{probe_line}    }}
{decoy_block}    log {{
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
            return (r.stderr or r.stdout or "")[:4000]
        return None
