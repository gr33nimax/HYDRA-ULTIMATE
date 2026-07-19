"""TCP honeypot with verified firewall bans and persistent audit state."""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import textwrap
import time
from pathlib import Path

from hydra.core.state import AppState
from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory, PluginMeta, PluginStatus


HONEYPOT_SCRIPT = Path("/usr/local/bin/hydra-honeypot.py")
HONEYPOT_SERVICE = Path("/etc/systemd/system/hydra-honeypot.service")
HONEYPOT_STATE = Path("/var/lib/hydra/honeypot.json")
HONEYPOT_LOG = Path("/var/log/hydra-honeypot.log")
HONEYPOT_LOGROTATE = Path("/etc/logrotate.d/hydra-honeypot")
HONEYPOT_PORT = 9999
_FW_COMMENT = "hydra-honeypot-ban"
_PORT_COMMENT = "hydra-honeypot-port"


def _run(command: list[str], *, text: bool = False, timeout: int = 20) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(command, capture_output=True, text=text, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(command, 1, stdout="" if text else b"", stderr=str(exc))


class HoneypotPlugin(BasePlugin):
    last_error = ""
    meta = PluginMeta(
        name="honeypot",
        description="Honeypot: TCP-ловушка с проверяемым IPv4/IPv6 firewall-баном",
        category=PluginCategory.SECURITY,
        version="2.1.0",
    )

    def install(self) -> bool:
        return shutil.which("python3") is not None and shutil.which("systemctl") is not None

    def uninstall(self) -> bool:
        config = self._load_state()
        self._remove_service(close_port=True)
        ok = True
        for ip in list(config.get("banned", {})):
            ok = self._unban_ip(ip) and ok
        if ok:
            HONEYPOT_STATE.unlink(missing_ok=True)
        HONEYPOT_LOGROTATE.unlink(missing_ok=True)
        return ok

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def snapshot(self, state: AppState):
        def read(path: Path):
            return path.read_bytes() if path.exists() else None
        return {
            "script": read(HONEYPOT_SCRIPT),
            "service": read(HONEYPOT_SERVICE),
            "state": read(HONEYPOT_STATE),
            "running": self.status().running,
        }

    def rollback(self, state: AppState, snapshot) -> bool:
        previous = snapshot or {}
        for key, path in (("script", HONEYPOT_SCRIPT), ("service", HONEYPOT_SERVICE), ("state", HONEYPOT_STATE)):
            content = previous.get(key)
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                tmp = path.with_suffix(path.suffix + ".rollback")
                tmp.write_bytes(content)
                tmp.replace(path)
        if previous.get("running"):
            result = _run(["systemctl", "restart", "hydra-honeypot"])
        else:
            result = _run(["systemctl", "stop", "hydra-honeypot"])
        return result.returncode == 0

    def apply(self, state: AppState) -> bool:
        config = self._load_state()
        if not self.status().running:
            return self._install_service(config["port"], config["whitelist"])
        self._write_script(config["port"], config["whitelist"])
        restarted = _run(["systemctl", "restart", "hydra-honeypot"])
        return restarted.returncode == 0 and self._wait_until_stably_running()

    def _service_diagnostics(self) -> str:
        result = _run(
            ["journalctl", "-u", "hydra-honeypot", "-n", "8", "--no-pager", "-o", "cat"],
            text=True,
        )
        lines = [line.strip() for line in str(result.stdout or result.stderr or "").splitlines() if line.strip()]
        return " | ".join(lines[-3:])[:600] or "служба не перешла в active"

    def _wait_until_stably_running(self) -> bool:
        # systemctl start may return while Python is still importing and before
        # bind(). Recheck after the process has had time to fail on a busy port
        # or an invalid sandbox/runtime setting.
        for _ in range(10):
            if self.status().running:
                time.sleep(1)
                if self.status().running:
                    return True
            time.sleep(0.2)
        return False

    def status(self) -> PluginStatus:
        result = _run(["systemctl", "is-active", "hydra-honeypot"], text=True)
        active = result.returncode == 0 and result.stdout.strip() == "active"
        state = self._load_state()
        return PluginStatus(
            installed=HONEYPOT_SCRIPT.exists(),
            enabled=active,
            running=active,
            port=state.get("port", HONEYPOT_PORT),
            info={"banned_ips": len(state.get("banned", {}))},
        )

    @staticmethod
    def _normalize_whitelist(values: list[object]) -> list[str]:
        result = ["127.0.0.0/8", "::1/128"]
        for value in values:
            try:
                network = ipaddress.ip_network(str(value), strict=False)
            except ValueError:
                try:
                    address = ipaddress.ip_address(str(value))
                    network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
                except ValueError:
                    continue
            normalized = str(network)
            if normalized not in result:
                result.append(normalized)
        return result

    def _write_script(self, port: int, whitelist: list[str]) -> None:
        normalized = self._normalize_whitelist(whitelist)
        script = textwrap.dedent(f"""\
            #!/usr/bin/env python3
            import ipaddress
            import json
            import os
            import socket
            import subprocess
            import time
            from datetime import datetime, timezone
            from pathlib import Path

            PORT = {port}
            WHITELIST = [ipaddress.ip_network(item, strict=False) for item in {normalized!r}]
            LOG = Path({str(HONEYPOT_LOG)!r})
            STATE = Path({str(HONEYPOT_STATE)!r})
            COMMENT = {_FW_COMMENT!r}
            LOG.parent.mkdir(parents=True, exist_ok=True)
            STATE.parent.mkdir(parents=True, exist_ok=True)

            def log(message):
                timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
                with LOG.open("a", encoding="utf-8") as handle:
                    handle.write(f"[{{timestamp}}] {{message}}\\n")

            def load_state():
                try:
                    return json.loads(STATE.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    return {{"port": PORT, "whitelist": {normalized!r}, "banned": {{}}}}

            def save_state(data):
                temporary = STATE.with_name(f".{{STATE.name}}.{{os.getpid()}}.tmp")
                with temporary.open("w", encoding="utf-8") as handle:
                    json.dump(data, handle, indent=2, ensure_ascii=False)
                    handle.flush()
                    os.fsync(handle.fileno())
                temporary.chmod(0o600)
                temporary.replace(STATE)

            def firewall_spec(ip):
                address = ipaddress.ip_address(ip)
                binary = "ip6tables" if address.version == 6 else "iptables"
                spec = ["-s", ip, "-m", "comment", "--comment", COMMENT, "-j", "DROP"]
                return binary, spec

            def ensure_firewall_ban(ip):
                binary, spec = firewall_spec(ip)
                try:
                    check = subprocess.run([binary, "-C", "INPUT", *spec], capture_output=True, timeout=10)
                    if check.returncode == 0:
                        return True, binary
                    result = subprocess.run([binary, "-I", "INPUT", "1", *spec], capture_output=True, timeout=10)
                    return result.returncode == 0, binary
                except (OSError, subprocess.TimeoutExpired):
                    return False, binary

            def ban(ip):
                data = load_state()
                if ip in data.setdefault("banned", {{}}):
                    ok, backend = ensure_firewall_ban(ip)
                    log(f"VERIFY {{ip}} backend={{backend}} result={{'OK' if ok else 'FAIL'}}")
                    return ok
                ok, backend = ensure_firewall_ban(ip)
                log(f"BAN {{ip}} backend={{backend}} result={{'OK' if ok else 'FAIL'}}")
                if not ok:
                    return False
                data["banned"][ip] = {{
                    "banned_at": datetime.now(timezone.utc).isoformat(),
                    "source": "honeypot",
                    "backend": backend,
                }}
                save_state(data)
                return True

            for existing_ip in list(load_state().get("banned", {{}})):
                ok, backend = ensure_firewall_ban(existing_ip)
                log(f"RESTORE {{existing_ip}} backend={{backend}} result={{'OK' if ok else 'FAIL'}}")

            family = socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET
            server = socket.socket(family, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                try:
                    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except OSError:
                    pass
            server.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", PORT))
            server.listen(64)
            server.settimeout(5)
            log(f"Honeypot listening on TCP/{{PORT}}")

            while True:
                try:
                    connection, peer = server.accept()
                    connection.close()
                    ip = peer[0].removeprefix("::ffff:")
                    address = ipaddress.ip_address(ip)
                    if any(address in network for network in WHITELIST):
                        log(f"SKIP {{ip}} (whitelist)")
                        continue
                    log(f"CONNECT {{ip}}:{{peer[1]}}")
                    ban(ip)
                except socket.timeout:
                    continue
                except Exception as exc:
                    log(f"ERROR {{type(exc).__name__}}: {{exc}}")
                    time.sleep(1)
        """)
        HONEYPOT_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
        HONEYPOT_SCRIPT.write_text(script, encoding="utf-8")
        HONEYPOT_SCRIPT.chmod(0o750)

    def _install_service(self, port: int, whitelist: list[str]) -> bool:
        from hydra.utils import firewall

        self.last_error = ""
        self._write_script(port, whitelist)
        # systemd validates ReadWritePaths before ExecStart, so both paths must
        # already exist even though the generated script also creates them.
        HONEYPOT_STATE.parent.mkdir(parents=True, exist_ok=True)
        HONEYPOT_LOG.parent.mkdir(parents=True, exist_ok=True)
        port_was_open = firewall.port_is_open("tcp", port)
        if not port_was_open:
            firewall.open_tcp(port, _PORT_COMMENT)
        python_binary = shutil.which("python3") or "/usr/bin/python3"
        service = textwrap.dedent(f"""\
            [Unit]
            Description=Hydra Honeypot Port {port}
            After=network-online.target
            Wants=network-online.target

            [Service]
            Type=simple
            ExecStart={python_binary} {HONEYPOT_SCRIPT}
            Restart=on-failure
            RestartSec=5
            User=root
            NoNewPrivileges=true
            PrivateTmp=true
            ProtectHome=true
            ProtectSystem=strict
            ReadWritePaths=/var/lib/hydra /var/log
            RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK
            CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
            AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
            StandardOutput=journal
            StandardError=journal

            [Install]
            WantedBy=multi-user.target
        """)
        HONEYPOT_SERVICE.parent.mkdir(parents=True, exist_ok=True)
        HONEYPOT_SERVICE.write_text(service, encoding="utf-8")
        HONEYPOT_LOGROTATE.write_text(
            f"{HONEYPOT_LOG} {{\n  weekly\n  rotate 8\n  compress\n  missingok\n  notifempty\n  copytruncate\n}}\n",
            encoding="utf-8",
        )
        daemon_reload = _run(["systemctl", "daemon-reload"])
        if daemon_reload.returncode != 0:
            self.last_error = str(daemon_reload.stderr or daemon_reload.stdout or "systemctl daemon-reload failed")
            if not port_was_open:
                firewall.close_tcp(port, _PORT_COMMENT)
            return False
        enabled = _run(["systemctl", "enable", "--now", "hydra-honeypot"])
        if enabled.returncode == 0 and self._wait_until_stably_running():
            return True
        self.last_error = self._service_diagnostics()
        _run(["systemctl", "disable", "--now", "hydra-honeypot"])
        if not port_was_open:
            firewall.close_tcp(port, _PORT_COMMENT)
        return False

    def _remove_service(self, *, close_port: bool = True) -> bool:
        from hydra.utils import firewall

        config = self._load_state()
        _run(["systemctl", "disable", "--now", "hydra-honeypot"])
        HONEYPOT_SERVICE.unlink(missing_ok=True)
        HONEYPOT_SCRIPT.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"])
        if close_port:
            firewall.close_tcp(int(config.get("port", HONEYPOT_PORT)), _PORT_COMMENT)
        return not self.status().running

    def _unban_ip(self, ip: str) -> bool:
        config = self._load_state()
        metadata = config.get("banned", {}).get(ip, {})
        backend = metadata.get("backend", "ufw")
        if backend == "ufw":
            result = _run(["ufw", "delete", "deny", "from", ip, "to", "any"])
        else:
            binary = "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"
            spec = ["-s", ip, "-m", "comment", "--comment", _FW_COMMENT, "-j", "DROP"]
            check = _run([binary, "-C", "INPUT", *spec])
            result = _run([binary, "-D", "INPUT", *spec]) if check.returncode == 0 else check
            if check.returncode != 0:
                result = subprocess.CompletedProcess([binary], 0)
        if result.returncode != 0:
            return False
        config.setdefault("banned", {}).pop(ip, None)
        self._save_state(config)
        return True

    def _load_state(self) -> dict:
        default = {
            "banned": {},
            "port": HONEYPOT_PORT,
            "whitelist": ["127.0.0.0/8", "::1/128"],
        }
        if HONEYPOT_STATE.exists():
            try:
                loaded = json.loads(HONEYPOT_STATE.read_text(encoding="utf-8"))
                loaded["whitelist"] = self._normalize_whitelist(loaded.get("whitelist", []))
                loaded.setdefault("banned", {})
                loaded.setdefault("port", HONEYPOT_PORT)
                return loaded
            except (OSError, json.JSONDecodeError, TypeError):
                pass
        return default

    def _save_state(self, data: dict) -> None:
        HONEYPOT_STATE.parent.mkdir(parents=True, exist_ok=True)
        data["whitelist"] = self._normalize_whitelist(data.get("whitelist", []))
        temporary = HONEYPOT_STATE.with_name(f".{HONEYPOT_STATE.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            temporary.chmod(0o600)
            temporary.replace(HONEYPOT_STATE)
        finally:
            temporary.unlink(missing_ok=True)

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        config = self._load_state()
        if not self._install_service(config["port"], config["whitelist"]):
            detail = f": {self.last_error}" if self.last_error else ""
            raise RuntimeError(f"Honeypot не удалось запустить{detail}")

    def on_disable(self, state: AppState) -> None:
        if not self._remove_service(close_port=True):
            raise RuntimeError("Honeypot не удалось остановить")
