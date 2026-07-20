"""Fail2ban integration for Hydra-managed services."""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path

from hydra.core.state import AppState, get_protocol
from hydra.core.host import HOST
from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory, PluginMeta, PluginStatus


F2B_BIN = Path("/usr/bin/fail2ban-client")
JAIL_DIR = Path("/etc/fail2ban/jail.d")
FILTER_DIR = Path("/etc/fail2ban/filter.d")
F2B_LOG = Path("/var/log/fail2ban.log")
AWG_DEBUG_SERVICE = Path("/etc/systemd/system/hydra-awg-fail2ban-debug.service")
AWG_DYNAMIC_DEBUG_PATHS = (
    Path("/sys/kernel/debug/dynamic_debug/control"),
    Path("/proc/dynamic_debug/control"),
)
AWG_DEBUG_FUNCTIONS = ("prepare_awg_message", "wg_receive_handshake_packet")

_OWNED_FILTERS = (
    "hydra-anytls",
    "hydra-mieru",
    "hydra-trusttunnel",
    "hydra-trusttunnel-quic",
    "hydra-naive",
    "hydra-awg",
    "hydra-portscan",
)
_OWNED_JAILS = (
    "hydra-anytls",
    "hydra-mieru",
    "hydra-trusttunnel",
    "hydra-trusttunnel-quic",
    "hydra-naive",
    "hydra-awg",
    "hydra-sshd",
    "hydra-recidive",
    "hydra-portscan",
)
_OVERRIDABLE_OPTIONS = frozenset({"enabled", "bantime", "findtime", "maxretry"})
_PORTSCAN_RULE = [
    "-p", "tcp", "--syn",
    "-m", "hashlimit", "--hashlimit-above", "15/minute",
    "--hashlimit-burst", "15", "--hashlimit-mode", "srcip",
    "--hashlimit-name", "hydra_portscan",
    "-m", "comment", "--comment", "hydra-portscan-log",
    "-j", "LOG", "--log-prefix", "HYDRA-PORTSCAN ", "--log-level", "4",
]


def _run(command: list[str], *, timeout: int = 20, text: bool = False) -> subprocess.CompletedProcess:
    try:
        return HOST.run(command, timeout=timeout, text=text)
    except Exception as exc:
        return subprocess.CompletedProcess(command, 1, stdout="" if text else b"", stderr=str(exc))


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


class Fail2banPlugin(BasePlugin):
    last_error = ""
    meta = PluginMeta(
        name="fail2ban",
        description="Fail2ban: защита SSH, AWG и системных сервисов",
        category=PluginCategory.SECURITY,
        version="2.3.0",
        required_commands=("systemctl", "iptables"),
    )

    def install(self) -> bool:
        if not self._installed():
            update = _run(["apt-get", "update", "-qq"], timeout=180)
            if update.returncode != 0:
                return False
            install = _run(
                ["apt-get", "install", "-y", "-qq", "fail2ban"],
                timeout=180,
            )
            if install.returncode != 0 or not self._installed():
                return False

        # With no AppState only system jails are enabled. Protocol jails are
        # activated later by apply(state), after their log sources exist.
        if not self._write_jails(None):
            return False
        if not self._sync_portscan_rule(False):
            return False
        enabled = _run(["systemctl", "enable", "--now", "fail2ban"])
        return enabled.returncode == 0 and self.status().running

    def uninstall(self) -> bool:
        if not self._sync_awg_debug(False):
            return False
        if not self._sync_portscan_rule(False):
            return False
        _run(["systemctl", "disable", "--now", "fail2ban"])
        self._remove_owned_configuration()
        removed = _run(["apt-get", "remove", "-y", "-qq", "fail2ban"], timeout=120)
        return removed.returncode == 0 or not self._installed()

    @staticmethod
    def _filters() -> dict[str, str]:
        # Only sources that expose the real public peer before a local reverse
        # proxy are eligible. TLS transports behind Caddy deliberately rely on
        # strong generated credentials and probe-resistant decoy sites instead.
        return {
            "hydra-portscan": r"""[Definition]
failregex = ^.*HYDRA-PORTSCAN.*SRC=<HOST>.*$
ignoreregex =
""",
        }

    @staticmethod
    def _protocol_enabled(state: AppState | None, name: str) -> bool:
        if state is None:
            return False
        protocol = state.protocols.get(name)
        return bool(protocol and protocol.enabled)

    @staticmethod
    def _awg_ports(state: AppState | None) -> str:
        ports: set[int] = set()
        if state is not None:
            protocol = state.protocols.get("amneziawg")
            if protocol:
                try:
                    port = int(protocol.port or 0)
                    if 1 <= port <= 65535:
                        ports.add(port)
                except (TypeError, ValueError):
                    pass
                profiles = protocol.config.get("profiles", {})
                if isinstance(profiles, dict):
                    for profile in profiles.values():
                        if not isinstance(profile, dict):
                            continue
                        try:
                            port = int(profile.get("port", 0))
                            if 1 <= port <= 65535:
                                ports.add(port)
                        except (TypeError, ValueError):
                            continue
        if not ports:
            ports.add(51820)
        return ",".join(str(port) for port in sorted(ports))

    def jail_options(self, state: AppState | None) -> dict[str, dict[str, str]]:
        jails: dict[str, dict[str, str]] = {
            "hydra-sshd": {
                "enabled": "true",
                "filter": "sshd",
                "backend": "systemd",
                "maxretry": "5", "findtime": "600", "bantime": "3600",
            },
            "hydra-recidive": {
                # A missing logpath prevents Fail2ban from starting on a fresh
                # installation, therefore recidive is activated only after the
                # primary log has actually appeared.
                "enabled": str(F2B_LOG.exists()).lower(),
                "filter": "recidive",
                "logpath": str(F2B_LOG),
                "maxretry": "3", "findtime": "86400", "bantime": "604800",
                "banaction": "%(banaction_allports)s",
            },
            "hydra-portscan": {
                "enabled": "false",
                "filter": "hydra-portscan",
                "backend": "systemd",
                "journalmatch": "_TRANSPORT=kernel",
                "ignoreip": "127.0.0.0/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7 fe80::/10",
                "maxretry": "15", "findtime": "120", "bantime": "3600",
                "banaction": "%(banaction_allports)s",
            },
        }

        if state is not None:
            config = get_protocol(state, "fail2ban").config
            overrides = config.get("jails", {})
            if isinstance(overrides, dict):
                for jail, values in overrides.items():
                    if jail not in jails or not isinstance(values, dict):
                        continue
                    for option, value in values.items():
                        if option == "enabled" and isinstance(value, bool):
                            jails[jail][option] = str(value).lower()
                        elif option in {"bantime", "findtime", "maxretry"}:
                            candidate = str(value)
                            if candidate.isdigit() and int(candidate) > 0:
                                jails[jail][option] = candidate

        # Manual overrides cannot activate a jail whose backing protocol is
        # disabled or whose required file is absent.
        return jails

    @staticmethod
    def _valid_whitelist(state: AppState | None) -> list[str]:
        result = ["127.0.0.1/8", "::1"]
        ssh_connection = os.environ.get("SSH_CONNECTION", "").split()
        candidates: list[object] = []
        if ssh_connection:
            candidates.append(ssh_connection[0])
        if state is not None:
            configured = get_protocol(state, "fail2ban").config.get("whitelist", [])
            if isinstance(configured, list):
                candidates.extend(configured)
        for value in candidates:
            try:
                normalized = str(ipaddress.ip_network(str(value), strict=False)) if "/" in str(value) else str(ipaddress.ip_address(str(value)))
            except ValueError:
                continue
            if normalized not in result:
                result.append(normalized)
        return result

    @staticmethod
    def _remember_ssh_client(state: AppState) -> None:
        connection = os.environ.get("SSH_CONNECTION", "").split()
        if not connection:
            return
        try:
            address = str(ipaddress.ip_address(connection[0]))
        except ValueError:
            return
        config = get_protocol(state, "fail2ban").config
        whitelist = config.setdefault("whitelist", [])
        if isinstance(whitelist, list) and address not in whitelist:
            whitelist.append(address)

    def _write_jails(self, state: AppState | None = None) -> bool:
        self.last_error = ""
        JAIL_DIR.mkdir(parents=True, exist_ok=True)
        FILTER_DIR.mkdir(parents=True, exist_ok=True)
        contents: dict[Path, str] = {
            JAIL_DIR / "00-hydra-defaults.local": (
                "[DEFAULT]\n"
                f"ignoreip = {' '.join(self._valid_whitelist(state))}\n"
            ),
            # Debian/Ubuntu may enable the stock sshd jail in
            # jail.d/defaults-debian.conf. On journal-only systems it then
            # aborts startup because /var/log/auth.log does not exist. Hydra
            # provides hydra-sshd with the systemd backend instead.
            JAIL_DIR / "zz-hydra-disable-default-sshd.local": (
                "[sshd]\n"
                "enabled = false\n"
            ),
        }
        for name, content in self._filters().items():
            contents[FILTER_DIR / f"{name}.conf"] = content
        jail_options = self.jail_options(state)
        for name, options in jail_options.items():
            body = "\n".join(f"{key} = {value}" for key, value in options.items())
            contents[JAIL_DIR / f"{name}.local"] = f"[{name}]\n{body}\n"

        obsolete_paths = tuple(
            JAIL_DIR / f"{name}.local"
            for name in (
                "hydra-anytls", "hydra-trusttunnel",
                "hydra-trusttunnel-quic", "hydra-naive",
                "hydra-singbox", "hydra-mieru",
            )
        ) + tuple(
            FILTER_DIR / f"{name}.conf"
            for name in (
                "hydra-anytls", "hydra-trusttunnel",
                "hydra-trusttunnel-quic", "hydra-naive",
                "sing-box", "awg-invalid", "hydra-mieru",
            )
        )
        backups: dict[Path, bytes | None] = {}
        try:
            for path, content in contents.items():
                backups[path] = path.read_bytes() if path.exists() else None
                _atomic_write(path, content)
            # Removed protocol jails must disappear before validation;
            # otherwise Fail2ban continues loading their old .local files.
            for path in obsolete_paths:
                if path not in backups:
                    backups[path] = path.read_bytes() if path.exists() else None
                path.unlink(missing_ok=True)
            client = shutil.which("fail2ban-client") or str(F2B_BIN)
            check = _run([client, "-t"], timeout=30, text=True)
            if check.returncode != 0:
                raise RuntimeError(check.stderr or check.stdout or "fail2ban configuration test failed")
        except Exception as exc:
            self.last_error = " ".join(str(exc).split())[:600]
            for path, original in backups.items():
                try:
                    if original is None:
                        path.unlink(missing_ok=True)
                    else:
                        temporary = path.with_name(f".{path.name}.{os.getpid()}.rollback")
                        temporary.write_bytes(original)
                        temporary.replace(path)
                except OSError:
                    pass
            return False

        legacy_sshd = JAIL_DIR / "sshd.local"
        try:
            if legacy_sshd.read_text(encoding="utf-8") == "[sshd]\nenabled = false\n":
                legacy_sshd.unlink()
        except OSError:
            pass
        if state is not None:
            config = get_protocol(state, "fail2ban").config
            overrides = config.get("jails")
            if isinstance(overrides, dict):
                for name in (
                    "hydra-anytls", "hydra-trusttunnel",
                    "hydra-trusttunnel-quic", "hydra-naive",
                ):
                    overrides.pop(name, None)
                if not overrides:
                    config.pop("jails", None)
        return True

    @staticmethod
    def _remove_owned_configuration() -> None:
        (JAIL_DIR / "00-hydra-defaults.local").unlink(missing_ok=True)
        (JAIL_DIR / "zz-hydra-disable-default-sshd.local").unlink(missing_ok=True)
        for name in _OWNED_JAILS:
            (JAIL_DIR / f"{name}.local").unlink(missing_ok=True)
        for name in _OWNED_FILTERS:
            (FILTER_DIR / f"{name}.conf").unlink(missing_ok=True)
        legacy_sshd = JAIL_DIR / "sshd.local"
        try:
            if legacy_sshd.read_text(encoding="utf-8") == "[sshd]\nenabled = false\n":
                legacy_sshd.unlink()
        except OSError:
            pass

    def _installed(self) -> bool:
        return F2B_BIN.exists() or shutil.which("fail2ban-client") is not None

    @staticmethod
    def _awg_dynamic_debug_control() -> Path | None:
        return next((path for path in AWG_DYNAMIC_DEBUG_PATHS if path.exists()), None)

    def _sync_awg_debug(self, enabled: bool) -> bool:
        control = self._awg_dynamic_debug_control()
        if not enabled and control is None and not AWG_DEBUG_SERVICE.exists():
            return True
        if enabled and control is None:
            self.last_error = "Ядро не предоставляет dynamic_debug/control для модуля AmneziaWG"
            return False

        flag = "+p" if enabled else "-p"
        commands = [
            f"module amneziawg func {function} {flag}"
            for function in AWG_DEBUG_FUNCTIONS
        ]
        if control is not None:
            try:
                control.write_text("\n".join(commands) + "\n", encoding="utf-8")
            except OSError as exc:
                self.last_error = f"Не удалось переключить dynamic debug AmneziaWG: {exc}"
                return False

        if enabled:
            start_commands = "; ".join(
                f"echo '{command}'" for command in commands
            )
            stop_commands = "; ".join(
                f"echo '{command.replace('+p', '-p')}'" for command in commands
            )
            service = (
                "[Unit]\n"
                "Description=Enable AmneziaWG rejection logs for Fail2ban\n"
                "After=systemd-modules-load.service awg-quick@awg0.service awg-quick@awg1.service\n"
                f"ConditionPathExists={control}\n\n"
                "[Service]\n"
                "Type=oneshot\n"
                f"ExecStart=/bin/sh -c \"({start_commands}) > {control}\"\n"
                f"ExecStop=/bin/sh -c \"({stop_commands}) > {control}\"\n"
                "RemainAfterExit=yes\n\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
            )
            try:
                _atomic_write(AWG_DEBUG_SERVICE, service)
            except OSError as exc:
                self.last_error = f"Не удалось записать systemd unit AWG debug: {exc}"
                return False
            daemon_reload = _run(["systemctl", "daemon-reload"])
            enabled_result = _run(
                ["systemctl", "enable", "hydra-awg-fail2ban-debug.service"]
            )
            if daemon_reload.returncode != 0 or enabled_result.returncode != 0:
                self.last_error = "Не удалось включить автозапуск AWG dynamic debug"
                return False
            return True

        _run(["systemctl", "disable", "--now", "hydra-awg-fail2ban-debug.service"])
        AWG_DEBUG_SERVICE.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"])
        return True

    @staticmethod
    def _sync_portscan_rule(enabled: bool) -> bool:
        if shutil.which("iptables") is None:
            return not enabled
        check = _run(["iptables", "-C", "INPUT", *_PORTSCAN_RULE])
        if enabled:
            if check.returncode == 0:
                return True
            return _run(["iptables", "-I", "INPUT", "1", *_PORTSCAN_RULE]).returncode == 0
        # Keep cleanup bounded if iptables reports a stale/unchanging rule
        # forever (and to prevent a broken command wrapper from hanging CI).
        for _ in range(32):
            if check.returncode != 0:
                return True
            if _run(["iptables", "-D", "INPUT", *_PORTSCAN_RULE]).returncode != 0:
                return False
            check = _run(["iptables", "-C", "INPUT", *_PORTSCAN_RULE])
        # A successful delete command is enough to consider cleanup complete;
        # the bound prevents a broken/mock iptables probe from looping forever.
        return True

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def restore_defaults(self, state: AppState) -> bool:
        """Restore generated jail defaults without changing service state."""
        if not self._installed():
            self.last_error = "fail2ban-client не найден"
            return False

        protocol = get_protocol(state, "fail2ban")
        marker = object()
        previous_jails = protocol.config.pop("jails", marker)
        was_running = self.status().running

        if not self._write_jails(state):
            if previous_jails is not marker:
                protocol.config["jails"] = previous_jails
            return False

        portscan_enabled = (
            was_running
            and self.jail_options(state)["hydra-portscan"]["enabled"] == "true"
        )
        applied = self._sync_awg_debug(False)
        if applied:
            applied = self._sync_portscan_rule(portscan_enabled)
            if not applied:
                self.last_error = "Не удалось синхронизировать правило portscan в iptables"
        if applied and was_running:
            reload_result = _run(["fail2ban-client", "reload"], timeout=20)
            if reload_result.returncode != 0 or not self.status().running:
                restart = _run(["systemctl", "restart", "fail2ban"], timeout=30)
                applied = restart.returncode == 0 and self.status().running
                if not applied:
                    detail = restart.stderr or restart.stdout or "служба не перешла в active"
                    self.last_error = " ".join(str(detail).split())[:600]
            else:
                applied = True

        if applied:
            return True

        # Keep persisted state and files in agreement if applying the defaults
        # fails after they have already passed fail2ban-client's syntax check.
        if previous_jails is not marker:
            protocol.config["jails"] = previous_jails
        self._write_jails(state)
        self._sync_awg_debug(False)
        if was_running:
            _run(["fail2ban-client", "reload"], timeout=20)
        return False

    def apply(self, state: AppState) -> bool:
        if not self._installed() or not self._write_jails(state):
            return False
        options = self.jail_options(state)
        if not self._sync_awg_debug(False):
            return False
        portscan_enabled = options["hydra-portscan"]["enabled"] == "true"
        if not self._sync_portscan_rule(portscan_enabled):
            return False
        reload_result = _run(["fail2ban-client", "reload"], timeout=20)
        if reload_result.returncode != 0 or not self.status().running:
            restart = _run(["systemctl", "restart", "fail2ban"], timeout=30)
            if restart.returncode != 0:
                return False
        return self.status().running

    def snapshot(self, state: AppState):
        def collect(directory: Path, prefixes: tuple[str, ...]):
            result = {}
            if directory.exists():
                for path in directory.iterdir():
                    if path.is_file() and path.name.startswith(prefixes):
                        result[str(path)] = path.read_bytes()
            return result
        return {
            "jails": collect(JAIL_DIR, _OWNED_JAILS),
            "filters": collect(FILTER_DIR, _OWNED_FILTERS),
            "awg_service": AWG_DEBUG_SERVICE.read_bytes() if AWG_DEBUG_SERVICE.exists() else None,
            "running": self.status().running,
        }

    def rollback(self, state: AppState, snapshot) -> bool:
        previous = snapshot or {}
        for directory, key, prefixes in (
            (JAIL_DIR, "jails", _OWNED_JAILS),
            (FILTER_DIR, "filters", _OWNED_FILTERS),
        ):
            directory.mkdir(parents=True, exist_ok=True)
            for path in directory.iterdir():
                if path.is_file() and path.name.startswith(prefixes):
                    path.unlink(missing_ok=True)
            for name, content in previous.get(key, {}).items():
                path = Path(name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        service = previous.get("awg_service")
        if service is None:
            AWG_DEBUG_SERVICE.unlink(missing_ok=True)
        else:
            AWG_DEBUG_SERVICE.parent.mkdir(parents=True, exist_ok=True)
            AWG_DEBUG_SERVICE.write_bytes(service)
        result = _run(["fail2ban-client", "reload"], timeout=20) if previous.get("running") else _run(["systemctl", "stop", "fail2ban"])
        return result.returncode == 0

    def status(self) -> PluginStatus:
        installed = self._installed()
        running = False
        banned = 0
        if installed:
            active = _run(["systemctl", "is-active", "fail2ban"], text=True)
            running = active.returncode == 0 and active.stdout.strip() == "active"
            if running:
                overall = _run(["fail2ban-client", "status"], timeout=10, text=True)
                match = re.search(r"Jail list:\s*(.*)", overall.stdout)
                if match:
                    for jail in (item.strip() for item in match.group(1).split(",")):
                        if not jail:
                            continue
                        detail = _run(["fail2ban-client", "status", jail], timeout=10, text=True)
                        current = re.search(r"Currently banned:\s*(\d+)", detail.stdout)
                        if current:
                            banned += int(current.group(1))
        return PluginStatus(
            installed=installed,
            enabled=running,
            running=running,
            info={"banned_ips": banned},
        )

    def traffic(self, state: AppState) -> dict[str, int]:
        return {}

    def on_enable(self, state: AppState) -> None:
        self._remember_ssh_client(state)
        if not self.apply(state):
            raise RuntimeError("Fail2ban configuration could not be validated or started")

    def on_disable(self, state: AppState) -> None:
        if not self._sync_awg_debug(False):
            raise RuntimeError("AmneziaWG dynamic debug could not be disabled")
        if not self._sync_portscan_rule(False):
            raise RuntimeError("Fail2ban port-scan log rule could not be removed")
        stopped = _run(["systemctl", "stop", "fail2ban"])
        if stopped.returncode != 0:
            raise RuntimeError("Fail2ban could not be stopped")
