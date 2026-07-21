"""hydra/plugins/naive/plugin.py — NaiveProxy: Caddy + forwardproxy, Chromium HTTP/2 fingerprint.

Контракт v2 — TRANSPORT-плагин с needs_domain=True:
  • configure() — генерит Caddyfile в памяти.
  • apply() — создает фейковый сайт, пишет Caddyfile, caddy validate + systemctl reload.
  • per-user: детерминированные username/password из uuid через derive_key.
  • traffic — per-user Caddy access-log accounting (Rx + Tx).
  • TLS & HAProxy: использует certbot / существующий SSL-сертификат для корректной работы за HAProxy.
  • sing-box integration: исходящий трафик проксируется в sing-box через `upstream socks5://127.0.0.1:1080`.
  • probe resistance: незнакомые клиенты получают отклик от фейкового HTML-файла.
"""
from __future__ import annotations

from hydra.core.host import HOST

import copy
import json
import shutil
import subprocess
import time
import urllib.parse
from pathlib import Path

from hydra.plugins.base import BasePlugin, PluginMeta, PluginStatus, PluginCategory, ConfigFragment
from hydra.core.errors import HostOperationError
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
        required_commands=("systemctl",),
    )

    def __init__(self):
        self._pending_cfg: str | None = None

    def snapshot(self, state: AppState):
        return {
            "config": CADDYFILE.read_bytes() if CADDYFILE.exists() else None,
            "service": SERVICE_FILE.read_bytes() if SERVICE_FILE.exists() else None,
            "running": self.status().running,
        }

    def rollback(self, state: AppState, snapshot) -> bool:
        previous = snapshot or {}
        for key, path in (("config", CADDYFILE), ("service", SERVICE_FILE)):
            content = previous.get(key)
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(path.suffix + ".rollback")
                tmp.write_bytes(content)
                tmp.replace(path)
        HOST.run(["systemctl", "daemon-reload"], capture_output=True)
        command = ["systemctl", "restart", SERVICE_NAME] if previous.get("running") else ["systemctl", "stop", SERVICE_NAME]
        return HOST.run(command, capture_output=True).returncode == 0

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
        HOST.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
        HOST.run(["systemctl", "disable", SERVICE_NAME], capture_output=True)
        if SERVICE_FILE.exists():
            SERVICE_FILE.unlink()
        HOST.run(["systemctl", "daemon-reload"], capture_output=True)
        HOST.run(["systemctl", "reset-failed"], capture_output=True)

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
        from hydra.core.sni_router import get_effective_port, _INTERNAL_PORTS
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
            # Не запрашиваем сертификат в configure() — это делается в on_enable()
            self._pending_cfg = None
            return ConfigFragment()

        caddyfile = self._build_caddyfile(
            domain=domain,
            port=port,
            users=users,
            fake_site_dir=str(FAKE_SITE_DIR),
            cert_file=cert_file,
            key_file=key_file,
            decoy_url=decoy_url,
            accept_proxy_protocol=port == _INTERNAL_PORTS["naive"],
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

        pending = CADDYFILE.with_suffix(".pending")
        pending.write_text(self._pending_cfg)
        pending.chmod(0o640)

        err = self._validate_caddy(pending)
        if err:
            pending.unlink(missing_ok=True)
            print(f"  Caddyfile validation error: {err}")
            return False
        pending.replace(CADDYFILE)

        enabled = HOST.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)
        restarted = HOST.run(["systemctl", "reload-or-restart", SERVICE_NAME], capture_output=True)
        if enabled.returncode != 0 or restarted.returncode != 0:
            return False
        time.sleep(2)
        return True

    # ═════════════════════════════════════════════════════════════════════
    #  Per-user TRANSPORT-методы
    # ═════════════════════════════════════════════════════════════════════

    def on_user_add(self, user: User, state: AppState) -> None:
        user.credentials.setdefault("naive", {})
        user.credentials["naive"]["username"] = self._derive_username(user)
        user.credentials["naive"]["password"] = self._derive_password(user.uuid)

    def on_user_remove(self, user: User, state: AppState) -> None:
        pass

    def on_user_block(self, user: User, state: AppState) -> None:
        pass

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

        ps = state.protocols.get("naive")
        network_mode = ps.config.get("network", "tcp") if ps and ps.config else "tcp"

        outbounds = []

        if network_mode in ("tcp", "both"):
            outbounds.append({
                "type": "naive",
                "tag": f"naive-tcp-{username}",
                "server": domain,
                "server_port": port,
                "username": username,
                "password": password,
                "quic": False,
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                },
            })

        if network_mode in ("quic", "both"):
            outbounds.append({
                "type": "naive",
                "tag": f"naive-quic-{username}",
                "server": domain,
                "server_port": port,
                "username": username,
                "password": password,
                "quic": True,
                "tls": {
                    "enabled": True,
                    "server_name": domain,
                },
            })

        full = {
            "log": {"level": "info"},
            "dns": {
                "servers": [
                    {"tag": "google", "address": "8.8.8.8"},
                    {"tag": "local", "address": "1.1.1.1", "detour": "direct"},
                ],
            },
            "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
            "route": {"final": outbounds[0]["tag"] if outbounds else "direct"},
        }
        return json.dumps(full, indent=2)

    def client_link(self, user: User, state: AppState) -> str:
        domain = state.network.domain
        if not domain:
            return ""
        username = self._derive_username(user)
        password = self._derive_password(user.uuid)
        port = DEFAULT_PORT

        ps = state.protocols.get("naive")
        network_mode = ps.config.get("network", "tcp") if ps and ps.config else "tcp"

        user_q = urllib.parse.quote(username, safe="")
        pass_q = urllib.parse.quote(password, safe="")
        sni_q = urllib.parse.quote(domain, safe="")

        if network_mode == "quic":
            tag_raw = f"{username} NaiveProxy QUIC"
            tag_q = urllib.parse.quote(tag_raw, safe="")
            return f"naive+quic://{user_q}:{pass_q}@{domain}:{port}?security=tls&sni={sni_q}#{tag_q}"
        else:
            tag_raw = f"{username} NaiveProxy"
            tag_q = urllib.parse.quote(tag_raw, safe="")
            return f"naive+https://{user_q}:{pass_q}@{domain}:{port}?security=tls&sni={sni_q}#{tag_q}"

    def client_links(self, user: User, state: AppState) -> list[str]:
        """Возвращает список клиентских ссылок (может быть >1 при network=both)."""
        domain = state.network.domain
        if not domain:
            return []

        ps = state.protocols.get("naive")
        network_mode = ps.config.get("network", "tcp") if ps and ps.config else "tcp"

        username = self._derive_username(user)
        password = self._derive_password(user.uuid)
        port = DEFAULT_PORT

        user_q = urllib.parse.quote(username, safe="")
        pass_q = urllib.parse.quote(password, safe="")
        sni_q = urllib.parse.quote(domain, safe="")

        links = []

        if network_mode in ("tcp", "both"):
            tag_q = urllib.parse.quote(f"{username} NaiveProxy", safe="")
            links.append(f"naive+https://{user_q}:{pass_q}@{domain}:{port}?security=tls&sni={sni_q}#{tag_q}")

        if network_mode in ("quic", "both"):
            tag_q = urllib.parse.quote(f"{username} NaiveProxy QUIC", safe="")
            links.append(f"naive+quic://{user_q}:{pass_q}@{domain}:{port}?security=tls&sni={sni_q}#{tag_q}")

        return links

    def set_transport(self, state: AppState, network: str) -> bool:
        """Транзакционно переключает TCP/QUIC и откатывает state/runtime при сбое."""
        if network not in ("tcp", "quic", "both"):
            return False

        from hydra.core.state import get_protocol, save_state

        ps = get_protocol(state, "naive")
        old_config = copy.deepcopy(ps.config)
        old_network = old_config.get("network", "tcp")
        if network == old_network:
            return True

        ps.config["network"] = network
        if network in ("quic", "both"):
            try:
                from hydra.core.sni_router import get_quic_owner
                get_quic_owner(state, prospective="naive")
            except ValueError:
                ps.config = old_config
                return False

        if not ps.enabled:
            save_state(state)
            return True

        from hydra.core.orchestrator import apply_config
        try:
            applied = apply_config(state)
        except Exception:
            applied = False

        if applied:
            save_state(state)
            self._sync_transport_firewall(old_network, network)
            return True

        # apply_config() может сохранить state для внутренних миграций, поэтому
        # прежнее значение обязательно записываем обратно и восстанавливаем runtime.
        ps.config = old_config
        save_state(state)
        try:
            apply_config(state)
        except Exception:
            pass
        return False

    def _sync_transport_firewall(self, old_network: str, network: str) -> None:
        """Обновляет внешнее правило UDP и legacy accounting после успешного apply."""
        from hydra.utils.firewall import open_udp, close_udp

        if network in ("quic", "both"):
            open_udp(DEFAULT_PORT, "naive-quic")
        elif old_network in ("quic", "both"):
            close_udp(DEFAULT_PORT, "naive-quic")

        self._remove_iptables_rules()
        HOST.run([
            "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(DEFAULT_PORT),
            "-m", "comment", "--comment", "naive-rx",
        ], capture_output=True)
        HOST.run([
            "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--sport", str(DEFAULT_PORT),
            "-m", "comment", "--comment", "naive-tx",
        ], capture_output=True)
        if network in ("quic", "both"):
            HOST.run([
                "iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", str(DEFAULT_PORT),
                "-m", "comment", "--comment", "naive-rx-udp",
            ], capture_output=True)
            HOST.run([
                "iptables", "-I", "OUTPUT", "1", "-p", "udp", "--sport", str(DEFAULT_PORT),
                "-m", "comment", "--comment", "naive-tx-udp",
            ], capture_output=True)

    # ═════════════════════════════════════════════════════════════════════
    #  Статус / трафик
    # ═════════════════════════════════════════════════════════════════════

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        enabled = CADDYFILE.exists()
        if installed:
            r = HOST.run(
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

            ps = state.protocols.get("naive")
            if ps and ps.config:
                mode = ps.config.get("network", "tcp")
                mode_labels = {"tcp": "HTTP/2 (TCP)", "quic": "QUIC (UDP)", "both": "HTTP/2 + QUIC"}
                info["Транспорт"] = mode_labels.get(mode, mode)
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
                            size = self._access_log_bytes(data)
                            email = uname_to_email.get(user_id)
                            if email:
                                result[email] = result.get(email, 0) + size
                    except Exception:
                        continue
        except Exception:
            pass
        return result

    @staticmethod
    def _access_log_directions(data: dict) -> tuple[int, int]:
        """Return client Rx/Tx from a structured Caddy access-log record."""
        try:
            rx = max(0, int(data.get("size", 0)))
        except (TypeError, ValueError):
            rx = 0
        try:
            tx = max(0, int(data.get("bytes_read", 0)))
        except (TypeError, ValueError):
            tx = 0
        return rx, tx

    @classmethod
    def _access_log_bytes(cls, data: dict) -> int:
        rx, tx = cls._access_log_directions(data)
        return rx + tx

    def update_traffic(self, state: AppState) -> None:
        """Increment persisted totals from unread access-log records.

        Cursors are keyed by the file inode, so Caddy may rename a live log
        during rotation without making already processed records reappear.
        """
        import gzip
        import json

        uname_to_user = {self._derive_username(user): user for user in state.users}
        cursor_root = state.install.setdefault("traffic_log_cursors", {})
        cursors = cursor_root.setdefault("naive", {})

        try:
            paths = sorted(LOG_DIR.glob("access.log*"), key=lambda p: p.stat().st_mtime_ns)
        except OSError:
            return

        for path in paths:
            try:
                stat = path.stat()
                if path.suffix == ".gz":
                    key = f"gz:{path.name}:{stat.st_mtime_ns}:{stat.st_size}"
                    if cursors.get(key) == "done":
                        continue
                    handle = gzip.open(path, "rt", encoding="utf-8", errors="replace")
                    start = 0
                else:
                    key = f"inode:{stat.st_dev}:{stat.st_ino}"
                    start = max(0, int(cursors.get(key, 0)))
                    if start > stat.st_size:
                        start = 0
                    handle = path.open("r", encoding="utf-8", errors="replace")

                with handle:
                    if start:
                        handle.seek(start)
                    while True:
                        line = handle.readline()
                        if not line:
                            break
                        try:
                            data = json.loads(line)
                            username = data.get("user_id") or data.get("user")
                            user = uname_to_user.get(username)
                            rx, tx = self._access_log_directions(data)
                            size = rx + tx
                        except (json.JSONDecodeError, TypeError, ValueError):
                            continue
                        if user is not None and size:
                            stats = user.credentials.setdefault("naive", {})
                            stats["traffic_used_bytes"] = (
                                max(0, int(stats.get("traffic_used_bytes", 0))) + size
                            )
                            stats["traffic_rx_bytes"] = (
                                max(0, int(stats.get("traffic_rx_bytes", 0))) + rx
                            )
                            stats["traffic_tx_bytes"] = (
                                max(0, int(stats.get("traffic_tx_bytes", 0))) + tx
                            )
                    cursors[key] = "done" if path.suffix == ".gz" else handle.tell()
            except OSError:
                continue

        # Bound metadata while retaining enough tombstones to recognize old
        # compressed rotations that may still be present.
        if len(cursors) > 128:
            for key in list(cursors)[:-128]:
                cursors.pop(key, None)

    def recent_connections(self, state: AppState, window_seconds: int = 300) -> list[dict]:
        """Return recently completed authenticated Caddy requests.

        Caddy emits an access record after the request/CONNECT handler returns,
        so these rows are deliberately marked as recent rather than online.
        """
        import gzip
        import json

        now = time.time()
        cutoff = now - max(1, window_seconds)
        uname_to_email = {self._derive_username(user): user.email for user in state.users}
        grouped: dict[str, dict] = {}
        try:
            paths = sorted(LOG_DIR.glob("access.log*"), key=lambda p: p.stat().st_mtime_ns)
        except OSError:
            return []

        for path in paths:
            try:
                opener = gzip.open if path.suffix == ".gz" else open
                with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        try:
                            data = json.loads(line)
                            ts = float(data.get("ts", 0))
                        except (json.JSONDecodeError, TypeError, ValueError):
                            continue
                        if ts < cutoff:
                            continue
                        username = data.get("user_id") or data.get("user")
                        email = uname_to_email.get(username)
                        if not email:
                            continue
                        request = data.get("request", {})
                        method = request.get("method", "") if isinstance(request, dict) else ""
                        if method and method != "CONNECT":
                            continue
                        rx, tx = self._access_log_directions(data)
                        row = grouped.setdefault(email, {
                            "email": email,
                            "online": False,
                            "rx": 0,
                            "tx": 0,
                            "connections": 0,
                            "last_handshake": int(ts),
                            "activity_kind": "recent",
                        })
                        row["rx"] += rx
                        row["tx"] += tx
                        row["connections"] += 1
                        row["last_handshake"] = max(row["last_handshake"], int(ts))
            except OSError:
                continue
        return list(grouped.values())

    def connected_clients(self, state: AppState | None = None) -> list[dict]:
        if not shutil.which("ss"):
            return []

        ip_counts = {}

        r = HOST.run(
            ["ss", "-t", "-H", "-n", "state", "established"],
            capture_output=True, text=True,
        )
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

                from hydra.core.sni_router import get_effective_port
                effective = get_effective_port("naive", state) if state else DEFAULT_PORT
                if local_port == effective or local_port == DEFAULT_PORT:
                    remote_addr = parts[3]
                    remote_parts = remote_addr.split(":")
                    remote_ip = ":".join(remote_parts[:-1]).strip("[]")
                    ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1

        # Также проверяем UDP (QUIC)
        r_udp = HOST.run(
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

                from hydra.core.sni_router import get_effective_port
                effective = get_effective_port("naive", state) if state else DEFAULT_PORT
                if local_port == effective or local_port == DEFAULT_PORT:
                    remote_addr = parts[3]
                    remote_parts = remote_addr.split(":")
                    remote_ip = ":".join(remote_parts[:-1]).strip("[]")
                    ip_counts[remote_ip] = ip_counts.get(remote_ip, 0) + 1

        rx_bytes = 0
        tx_bytes = 0
        r_rx = HOST.run(["iptables", "-t", "filter", "-L", "INPUT", "-n", "-v", "-x"], capture_output=True, text=True)
        if r_rx.returncode == 0:
            for line in r_rx.stdout.splitlines():
                if "naive-rx" in line:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rx_bytes += int(parts[1])
        r_tx = HOST.run(["iptables", "-t", "filter", "-L", "OUTPUT", "-n", "-v", "-x"], capture_output=True, text=True)
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
                "email": f"{remote_ip} ({count} Conn)",
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
        has_config = bool(domain and ps.config)

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

            from hydra.ui.tui import confirm
            use_custom = confirm("Использовать собственный SSL-сертификат (указать пути вручную)?", default=False)
            if use_custom:
                custom_cert = prompt("Путь к файлу сертификата (fullchain.pem)", default=ps.config.get("cert_file", ""))
                custom_key = prompt("Путь к приватному ключу (privkey.pem)", default=ps.config.get("key_file", ""))
                if custom_cert and custom_key:
                    ps.config["cert_file"] = custom_cert
                    ps.config["key_file"] = custom_key

            from hydra.ui.tui import menu as tui_menu
            current_mode = ps.config.get("network", "tcp")
            print()
            print("  Выберите режим транспорта NaiveProxy:")
            mode_choice = tui_menu([
                ("1", "HTTP/2 (TCP)", "Стандартный режим, максимальная совместимость"),
                ("2", "QUIC (UDP)", "HTTP/3 через UDP, может быть быстрее"),
                ("3", "HTTP/2 + QUIC", "Оба транспорта одновременно (2 ссылки на клиента)"),
            ], header="Транспорт NaiveProxy")
            mode_map = {"1": "tcp", "2": "quic", "3": "both"}
            ps.config["network"] = mode_map.get(mode_choice, current_mode)

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

        network_mode = ps.config.get("network", "tcp")
        if network_mode in ("quic", "both"):
            from hydra.core.sni_router import get_quic_owner
            # Caddy L4 raw UDP proxy не умеет делить UDP/443 между двумя
            # QUIC backend без QUIC-aware SNI matcher.
            get_quic_owner(state, prospective="naive")
            from hydra.utils.firewall import open_udp
            open_udp(DEFAULT_PORT, "naive-quic")

        self._remove_iptables_rules()
        HOST.run([
            "iptables", "-I", "INPUT", "1", "-p", "tcp", "--dport", str(DEFAULT_PORT),
            "-m", "comment", "--comment", "naive-rx"
        ], capture_output=True)
        HOST.run([
            "iptables", "-I", "OUTPUT", "1", "-p", "tcp", "--sport", str(DEFAULT_PORT),
            "-m", "comment", "--comment", "naive-tx"
        ], capture_output=True)

        if network_mode in ("quic", "both"):
            HOST.run([
                "iptables", "-I", "INPUT", "1", "-p", "udp", "--dport", str(DEFAULT_PORT),
                "-m", "comment", "--comment", "naive-rx-udp"
            ], capture_output=True)
            HOST.run([
                "iptables", "-I", "OUTPUT", "1", "-p", "udp", "--sport", str(DEFAULT_PORT),
                "-m", "comment", "--comment", "naive-tx-udp"
            ], capture_output=True)

        ps.enabled = True

    def on_disable(self, state: AppState) -> None:
        from hydra.utils.firewall import close_tcp
        HOST.run(["systemctl", "stop", SERVICE_NAME], capture_output=True)
        close_tcp(DEFAULT_PORT, "naive")

        from hydra.utils.firewall import close_udp
        close_udp(DEFAULT_PORT, "naive-quic")

        self._remove_iptables_rules()

        ps = state.protocols.get("naive")
        if ps:
            ps.enabled = False

    # ═════════════════════════════════════════════════════════════════════
    #  Внутренние помощники
    # ═════════════════════════════════════════════════════════════════════

    @staticmethod
    def _create_fake_site() -> None:
        from hydra.core.decoy import ensure_decoy_site
        ensure_decoy_site("naive")

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
            r = HOST.run(["iptables", "-S", chain], capture_output=True, text=True)
            if r.returncode != 0:
                continue
            for line in r.stdout.splitlines():
                if "naive-" in line:
                    parts = line.split()
                    if parts[0] == "-A":
                        parts[0] = "-D"
                        HOST.run(["iptables"] + parts, capture_output=True)

    def _get_total_traffic(self) -> int:
        total_bytes = 0
        for chain in ("INPUT", "OUTPUT"):
            r = HOST.run(
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

        from hydra.utils.firewall import temporary_open_port

        if not shutil.which("apt-get") and not shutil.which("certbot"):
            return False

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
                if status.stdout.strip() != "active":
                    continue
                print(f"  Временно останавливаю {service}...")
                stopped = HOST.run(
                    ["systemctl", "stop", service], capture_output=True, text=True,
                )
                if stopped.returncode != 0:
                    detail = stopped.stderr or stopped.stdout or "unknown error"
                    print(f"  [Ошибка certbot] Не удалось освободить порт 80: {service}: {detail}")
                    return False
                was_running.append(service)

            with temporary_open_port("tcp", 80, "temp-certbot"):
                r = HOST.run([
                    "certbot", "certonly", "--standalone",
                    "-d", domain,
                    "--non-interactive", "--agree-tos",
                    "--register-unsafely-without-email",
                    "--keep-until-expiring",
                ], capture_output=True, text=True)
            if r.returncode != 0:
                print(f"  [Ошибка certbot] Вывод:\n{r.stderr or r.stdout or ''}")
            return r.returncode == 0
        except (OSError, HostOperationError) as exc:
            print(f"  [Ошибка certbot] {exc}")
            return False
        finally:
            for service in was_running:
                print(f"  Восстанавливаю {service}...")
                HOST.run(["systemctl", "start", service], capture_output=True)

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
            return False

        if not verify_elf(binary):
            return False

        if BIN_PATH.exists():
            try:
                BIN_PATH.unlink()
            except Exception:
                pass

        shutil.copy2(str(binary), str(BIN_PATH))
        BIN_PATH.chmod(0o755)
        return True

    @staticmethod
    def _install_service() -> None:
        from hydra.core.decoy import DECOY_DIRS
        decoy_dir = DECOY_DIRS.get("naive", FAKE_SITE_DIR)
        decoy_dir.mkdir(parents=True, exist_ok=True)

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
            f"ReadWritePaths={CFG_DIR} {LOG_DIR} {decoy_dir} /var/lib/caddy-naive\n"
            "AmbientCapabilities=CAP_NET_BIND_SERVICE\n"
            "NoNewPrivileges=true\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )
        HOST.run(["systemctl", "daemon-reload"], capture_output=True)
        HOST.run(["systemctl", "enable", SERVICE_NAME], capture_output=True)

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
        accept_proxy_protocol: bool = False,
    ) -> str:
        auth_lines = ""
        for u in users:
            auth_lines += f"            basic_auth {u['username']} {u['password']}\n"

        if cert_file and key_file:
            tls_line = f"    tls {cert_file} {key_file}\n"
        else:
            tls_line = ""

        from hydra.core.decoy import DECOY_DIRS
        decoy_dir = DECOY_DIRS.get("naive", Path(fake_site_dir)).as_posix()
        decoy_block = f"    file_server {{\n        root {decoy_dir}\n    }}\n"
        order_line = "    order forward_proxy before file_server\n"

        site_header = f":{port}, {domain}:{port}"
        probe_line = "            probe_resistance\n" if auth_lines else ""
        listener_wrappers = ""
        if accept_proxy_protocol:
            listener_wrappers = """\
    servers {
        listener_wrappers {
            proxy_protocol {
                timeout 1s
                allow 127.0.0.0/8 ::1/128
                fallback_policy require
            }
            tls
        }
    }
"""

        return f"""\
{{
    http_port 0
    auto_https disable_redirects
{listener_wrappers}{order_line}}}

{site_header} {{
{tls_line}    forward_proxy {{
{auth_lines}            hide_ip
            hide_via
{probe_line}            upstream socks5://127.0.0.1:1080
    }}
{decoy_block}    log {{
        output file {LOG_DIR}/access.log {{
            roll_size 10mb
            roll_keep 3
        }}
    }}
}}
"""

    def _validate_caddy(self, config_path: Path = CADDYFILE) -> str | None:
        r = HOST.run(
            [str(BIN_PATH), "validate",
             "--config", str(config_path), "--adapter", "caddyfile"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return (r.stderr or r.stdout or "")[:4000]
        return None
