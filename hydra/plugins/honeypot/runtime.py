"""Service, script and firewall runtime operations for Honeypot."""
from __future__ import annotations

# audit: allow-generated-runtime-subprocess
from hydra.plugins.context import PluginStateAccess


class HoneypotRuntimeMixin:
    def install(self) -> bool:
        return self._honeypot_env().shutil_module.which('python3') is not None and self._honeypot_env().shutil_module.which('systemctl') is not None

    def uninstall(self) -> bool:
        config = self._load_state()
        self._remove_service(close_port=True)
        ok = True
        for ip in list(config.get('banned', {})):
            ok = self._unban_ip(ip) and ok
        if ok:
            self._honeypot_env().honeypot_state.unlink(missing_ok=True)
        self._honeypot_env().honeypot_logrotate.unlink(missing_ok=True)
        return ok

    def apply(self, state: PluginStateAccess) -> bool:
        config = self._load_state()
        self._sync_host_whitelist(config, state)
        previous_script = None
        try:
            previous_script = self._honeypot_env().honeypot_script.read_bytes()
        except OSError:
            pass
        if not self.status().running:
            return self._install_service(config['port'], config['whitelist'])
        self._write_script(config['port'], config['whitelist'])
        try:
            if previous_script is not None and self._honeypot_env().honeypot_script.read_bytes() == previous_script:
                return True
        except OSError:
            pass
        restarted = self._honeypot_env().run(['systemctl', 'restart', 'hydra-honeypot'])
        if restarted.returncode != 0 or not self._wait_until_stably_running():
            self.last_error = self._service_diagnostics()
            return False
        self.last_error = ''
        return True

    def _service_diagnostics(self) -> str:
        result = self._honeypot_env().run(['journalctl', '-u', 'hydra-honeypot', '-n', '8', '--no-pager', '-o', 'cat'], text=True)
        lines = [line.strip() for line in str(result.stdout or result.stderr or '').splitlines() if line.strip()]
        return ' | '.join(lines[-3:])[:600] or 'служба не перешла в active'

    def _wait_until_stably_running(self) -> bool:
        for _ in range(10):
            if self.status().running:
                self._honeypot_env().time_module.sleep(1)
                if self.status().running:
                    return True
            self._honeypot_env().time_module.sleep(0.2)
        return False

    def _write_script(self, port: int, whitelist: list[str]) -> None:
        normalized = self._normalize_whitelist(whitelist)
        script = self._honeypot_env().textwrap_module.dedent(f"""            #!/usr/bin/env python3\n            import ipaddress\n            import json\n            import os\n            import socket\n            import subprocess\n            import time\n            from datetime import datetime, timezone\n            from pathlib import Path\n\n            PORT = {port}\n            WHITELIST = [ipaddress.ip_network(item, strict=False) for item in {normalized!r}]\n            LOG = Path({str(self._honeypot_env().honeypot_log)!r})\n            STATE = Path({str(self._honeypot_env().honeypot_state)!r})\n            COMMENT = {self._honeypot_env().fw_comment!r}\n            LOG.parent.mkdir(parents=True, exist_ok=True)\n            STATE.parent.mkdir(parents=True, exist_ok=True)\n\n            def log(message):\n                timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")\n                with LOG.open("a", encoding="utf-8") as handle:\n                    handle.write(f"[{{timestamp}}] {{message}}\\n")\n\n            def load_state():\n                try:\n                    return json.loads(STATE.read_text(encoding="utf-8"))\n                except (OSError, json.JSONDecodeError):\n                    return {{"port": PORT, "whitelist": {normalized!r}, "banned": {{}}}}\n\n            def save_state(data):\n                temporary = STATE.with_name(f".{{STATE.name}}.{{os.getpid()}}.tmp")\n                with temporary.open("w", encoding="utf-8") as handle:\n                    json.dump(data, handle, indent=2, ensure_ascii=False)\n                    handle.flush()\n                    os.fsync(handle.fileno())\n                temporary.chmod(0o600)\n                temporary.replace(STATE)\n\n            def firewall_spec(ip):\n                address = ipaddress.ip_address(ip)\n                binary = "ip6tables" if address.version == 6 else "iptables"\n                spec = ["-s", ip, "-m", "comment", "--comment", COMMENT, "-j", "DROP"]\n                return binary, spec\n\n            def ensure_firewall_ban(ip):\n                binary, spec = firewall_spec(ip)\n                try:\n                    check = subprocess.run(\n                        [binary, "-C", "INPUT", *spec], timeout=10,\n                        capture_output=True, check=False,\n                    )\n                    if check.returncode == 0:\n                        return True, binary\n                    result = subprocess.run(\n                        [binary, "-I", "INPUT", "1", *spec], timeout=10,\n                        capture_output=True, check=False,\n                    )\n                    return result.returncode == 0, binary\n                except (OSError, subprocess.TimeoutExpired):\n                    return False, binary\n\n            def ban(ip):\n                data = load_state()\n                if ip in data.setdefault("banned", {{}}):\n                    ok, backend = ensure_firewall_ban(ip)\n                    log(f"VERIFY {{ip}} backend={{backend}} result={{'OK' if ok else 'FAIL'}}")\n                    return ok\n                ok, backend = ensure_firewall_ban(ip)\n                log(f"BAN {{ip}} backend={{backend}} result={{'OK' if ok else 'FAIL'}}")\n                if not ok:\n                    return False\n                data["banned"][ip] = {{\n                    "banned_at": datetime.now(timezone.utc).isoformat(),\n                    "source": "honeypot",\n                    "backend": backend,\n                }}\n                save_state(data)\n                return True\n\n            for existing_ip in list(load_state().get("banned", {{}})):\n                ok, backend = ensure_firewall_ban(existing_ip)\n                log(f"RESTORE {{existing_ip}} backend={{backend}} result={{'OK' if ok else 'FAIL'}}")\n\n            family = socket.AF_INET6 if socket.has_ipv6 else socket.AF_INET\n            server = socket.socket(family, socket.SOCK_STREAM)\n            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n            if family == socket.AF_INET6:\n                try:\n                    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)\n                except OSError:\n                    pass\n            server.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", PORT))\n            server.listen(64)\n            server.settimeout(5)\n            log(f"Honeypot listening on TCP/{{PORT}}")\n\n            while True:\n                try:\n                    connection, peer = server.accept()\n                    connection.close()\n                    ip = peer[0].removeprefix("::ffff:")\n                    address = ipaddress.ip_address(ip)\n                    if any(address in network for network in WHITELIST):\n                        log(f"SKIP {{ip}} (whitelist)")\n                        continue\n                    log(f"CONNECT {{ip}}:{{peer[1]}}")\n                    ban(ip)\n                except socket.timeout:\n                    continue\n                except Exception as exc:\n                    log(f"ERROR {{type(exc).__name__}}: {{exc}}")\n                    time.sleep(1)\n        """)
        self._honeypot_env().honeypot_script.parent.mkdir(parents=True, exist_ok=True)
        self._honeypot_env().honeypot_script.write_text(script, encoding='utf-8')
        self._honeypot_env().honeypot_script.chmod(488)

    def _install_service(self, port: int, whitelist: list[str]) -> bool:
        from hydra.utils import firewall
        self.last_error = ''
        self._write_script(port, whitelist)
        self._honeypot_env().honeypot_state.parent.mkdir(parents=True, exist_ok=True)
        self._honeypot_env().honeypot_log.parent.mkdir(parents=True, exist_ok=True)
        port_was_open = firewall.port_is_open('tcp', port)
        if not port_was_open:
            firewall.open_tcp(port, self._honeypot_env().port_comment)
        python_binary = self._honeypot_env().shutil_module.which('python3') or '/usr/bin/python3'
        service = self._honeypot_env().textwrap_module.dedent(f'            [Unit]\n            Description=Hydra Honeypot Port {port}\n            After=network-online.target\n            Wants=network-online.target\n\n            [Service]\n            Type=simple\n            ExecStart={python_binary} {self._honeypot_env().honeypot_script}\n            Restart=on-failure\n            RestartSec=5\n            User=root\n            NoNewPrivileges=true\n            PrivateTmp=true\n            ProtectHome=true\n            ProtectSystem=strict\n            ReadWritePaths=/var/lib/hydra /var/log\n            RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK\n            CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n            AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n            StandardOutput=journal\n            StandardError=journal\n\n            [Install]\n            WantedBy=multi-user.target\n        ')
        self._honeypot_env().honeypot_service.parent.mkdir(parents=True, exist_ok=True)
        self._honeypot_env().honeypot_service.write_text(service, encoding='utf-8')
        self._honeypot_env().honeypot_logrotate.write_text(f'{self._honeypot_env().honeypot_log} {{\n  weekly\n  rotate 8\n  compress\n  missingok\n  notifempty\n  copytruncate\n}}\n', encoding='utf-8')
        daemon_reload = self._honeypot_env().run(['systemctl', 'daemon-reload'])
        if daemon_reload.returncode != 0:
            self.last_error = str(daemon_reload.stderr or daemon_reload.stdout or 'systemctl daemon-reload failed')
            if not port_was_open:
                firewall.close_tcp(port, self._honeypot_env().port_comment)
            return False
        enabled = self._honeypot_env().run(['systemctl', 'enable', '--now', 'hydra-honeypot'])
        if enabled.returncode == 0 and self._wait_until_stably_running():
            return True
        self.last_error = self._service_diagnostics()
        self._honeypot_env().run(['systemctl', 'disable', '--now', 'hydra-honeypot'])
        if not port_was_open:
            firewall.close_tcp(port, self._honeypot_env().port_comment)
        return False

    def _remove_service(self, *, close_port: bool=True) -> bool:
        from hydra.utils import firewall
        config = self._load_state()
        self._honeypot_env().run(['systemctl', 'disable', '--now', 'hydra-honeypot'])
        self._honeypot_env().honeypot_service.unlink(missing_ok=True)
        self._honeypot_env().honeypot_script.unlink(missing_ok=True)
        self._honeypot_env().run(['systemctl', 'daemon-reload'])
        if close_port:
            firewall.close_tcp(int(config.get('port', self._honeypot_env().honeypot_port)), self._honeypot_env().port_comment)
        return not self.status().running

    def unban(self, raw: str) -> bool:
        try:
            address = self._honeypot_env().ipaddress_module.ip_address(str(raw).strip().strip('[]')).compressed
        except ValueError:
            return False
        config = self._load_state()
        if address not in config.get('banned', {}):
            return False
        return self._unban_ip(address)

    def _unban_ip(self, ip: str) -> bool:
        config = self._load_state()
        metadata = config.get('banned', {}).get(ip, {})
        backend = metadata.get('backend', 'ufw')
        if backend == 'ufw':
            result = self._honeypot_env().run(['ufw', 'delete', 'deny', 'from', ip, 'to', 'any'])
        else:
            binary = 'ip6tables' if self._honeypot_env().ipaddress_module.ip_address(ip).version == 6 else 'iptables'
            spec = ['-s', ip, '-m', 'comment', '--comment', self._honeypot_env().fw_comment, '-j', 'DROP']
            check = self._honeypot_env().run([binary, '-C', 'INPUT', *spec])
            result = self._honeypot_env().run([binary, '-D', 'INPUT', *spec]) if check.returncode == 0 else check
            if check.returncode != 0:
                result = self._honeypot_env().subprocess_module.CompletedProcess([binary], 0)
        if result.returncode != 0:
            return False
        config.setdefault('banned', {}).pop(ip, None)
        self._save_state(config)
        return True

    def on_enable(self, state: PluginStateAccess) -> None:
        config = self._load_state()
        self._sync_host_whitelist(config, state)
        if not self._install_service(config['port'], config['whitelist']):
            detail = f': {self.last_error}' if self.last_error else ''
            raise RuntimeError(f'Honeypot не удалось запустить{detail}')

    def on_disable(self, state: PluginStateAccess) -> None:
        if not self._remove_service(close_port=True):
            raise RuntimeError('Honeypot не удалось остановить')
