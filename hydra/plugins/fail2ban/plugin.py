"""Fail2ban integration for Hydra-managed services."""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path

from hydra.core.state import AppState, get_protocol
from hydra.plugins.base import BasePlugin, ConfigFragment, PluginCategory, PluginMeta, PluginStatus


F2B_BIN = Path("/usr/bin/fail2ban-client")
JAIL_DIR = Path("/etc/fail2ban/jail.d")
FILTER_DIR = Path("/etc/fail2ban/filter.d")
F2B_LOG = Path("/var/log/fail2ban.log")

_OWNED_FILTERS = (
    "hydra-anytls",
    "hydra-mieru",
    "hydra-trusttunnel",
    "hydra-naive",
    "hydra-awg",
    "hydra-portscan",
)
_OWNED_JAILS = (
    "hydra-anytls",
    "hydra-mieru",
    "hydra-trusttunnel",
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
        return subprocess.run(command, capture_output=True, text=text, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
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
    meta = PluginMeta(
        name="fail2ban",
        description="Fail2ban: защита SSH и прокси от перебора аутентификации",
        category=PluginCategory.SECURITY,
        version="2.1.0",
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
        if not self._sync_portscan_rule(False):
            return False
        _run(["systemctl", "disable", "--now", "fail2ban"])
        self._remove_owned_configuration()
        removed = _run(["apt-get", "remove", "-y", "-qq", "fail2ban"], timeout=120)
        return removed.returncode == 0 or not self._installed()

    @staticmethod
    def _filters() -> dict[str, str]:
        # Only authentication failures with a trustworthy source address are
        # matched. Generic "process connection" errors include upstream and
        # client network failures and must never be used as ban events.
        return {
            "hydra-anytls": r"""[Definition]
failregex = ^.*inbound/anytls\[[^]]+\]:\s+process connection from \[?(?:::ffff:)?<HOST>\]?:\d+:\s+unknown user password(?:\s*:\s*fallback disabled)?\s*$
ignoreregex =
""",
            "hydra-trusttunnel": r"""[Definition]
failregex = ^.*inbound/trusttunnel\[[^]]+\]:\s+process connection from \[?(?:::ffff:)?<HOST>\]?:\d+:\s+authorization failed\s*$
ignoreregex =
""",
            "hydra-naive": r"""[Definition]
failregex = ^.*"remote_ip"\s*:\s*"<HOST>".*"status"\s*:\s*407(?:\D|$).*$
            ^.*"status"\s*:\s*407(?:\D|$).*"remote_ip"\s*:\s*"<HOST>".*$
ignoreregex =
""",
            "hydra-awg": r"""[Definition]
failregex = ^.*(?:amneziawg|wireguard).*(?:Invalid|Handshake.*failed).*from <HOST>.*$
ignoreregex =
""",
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
    def _protocol_port(state: AppState | None, name: str, fallback: int) -> str:
        if state is not None:
            protocol = state.protocols.get(name)
            try:
                port = int(protocol.port or 0) if protocol else 0
            except (TypeError, ValueError):
                port = 0
            if 1 <= port <= 65535:
                return str(port)
        return str(fallback)

    def jail_options(self, state: AppState | None) -> dict[str, dict[str, str]]:
        anytls = self._protocol_enabled(state, "anytls")
        trusttunnel = self._protocol_enabled(state, "trusttunnel")
        naive = self._protocol_enabled(state, "naive")
        awg = self._protocol_enabled(state, "amneziawg")

        jails: dict[str, dict[str, str]] = {
            "hydra-anytls": {
                "enabled": str(anytls).lower(),
                "filter": "hydra-anytls",
                "backend": "systemd",
                "journalmatch": "_SYSTEMD_UNIT=sing-box.service",
                "port": self._protocol_port(state, "anytls", 443),
                "maxretry": "4", "findtime": "300", "bantime": "3600",
            },
            "hydra-trusttunnel": {
                "enabled": str(trusttunnel).lower(),
                "filter": "hydra-trusttunnel",
                "backend": "systemd",
                "journalmatch": "_SYSTEMD_UNIT=sing-box.service",
                "port": self._protocol_port(state, "trusttunnel", 443),
                "maxretry": "4", "findtime": "300", "bantime": "3600",
            },
            "hydra-naive": {
                "enabled": str(naive).lower(),
                "filter": "hydra-naive",
                "backend": "auto",
                "logpath": "/var/log/caddy-naive/access.log",
                "port": self._protocol_port(state, "naive", 443),
                "maxretry": "5", "findtime": "300", "bantime": "7200",
            },
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
            "hydra-awg": {
                # WireGuard normally stays deliberately silent on invalid
                # handshakes. Enable manually only on kernels that emit the
                # messages covered by hydra-awg.conf.
                "enabled": "false",
                "filter": "hydra-awg",
                "backend": "systemd",
                "journalmatch": "_TRANSPORT=kernel",
                "port": self._protocol_port(state, "amneziawg", 51820),
                "maxretry": "5", "findtime": "300", "bantime": "1800",
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
        availability = {
            "hydra-anytls": anytls,
            "hydra-trusttunnel": trusttunnel,
            "hydra-naive": naive,
            "hydra-awg": awg,
        }
        for jail, available in availability.items():
            if not available:
                jails[jail]["enabled"] = "false"
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
        JAIL_DIR.mkdir(parents=True, exist_ok=True)
        FILTER_DIR.mkdir(parents=True, exist_ok=True)
        contents: dict[Path, str] = {
            JAIL_DIR / "00-hydra-defaults.local": (
                "[DEFAULT]\n"
                f"ignoreip = {' '.join(self._valid_whitelist(state))}\n"
            ),
        }
        for name, content in self._filters().items():
            contents[FILTER_DIR / f"{name}.conf"] = content
        for name, options in self.jail_options(state).items():
            body = "\n".join(f"{key} = {value}" for key, value in options.items())
            contents[JAIL_DIR / f"{name}.local"] = f"[{name}]\n{body}\n"

        backups: dict[Path, bytes | None] = {}
        try:
            for path, content in contents.items():
                backups[path] = path.read_bytes() if path.exists() else None
                _atomic_write(path, content)
            check = _run([str(F2B_BIN), "-t"], timeout=30, text=True)
            if check.returncode != 0:
                raise RuntimeError(check.stderr or check.stdout or "fail2ban configuration test failed")
        except Exception:
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

        # Remove obsolete Hydra files only after the new configuration passed.
        for obsolete in (
            JAIL_DIR / "hydra-singbox.local",
            FILTER_DIR / "sing-box.conf",
            FILTER_DIR / "awg-invalid.conf",
            FILTER_DIR / "hydra-mieru.conf",
            JAIL_DIR / "hydra-mieru.local",
        ):
            obsolete.unlink(missing_ok=True)
        legacy_sshd = JAIL_DIR / "sshd.local"
        try:
            if legacy_sshd.read_text(encoding="utf-8") == "[sshd]\nenabled = false\n":
                legacy_sshd.unlink()
        except OSError:
            pass
        return True

    @staticmethod
    def _remove_owned_configuration() -> None:
        (JAIL_DIR / "00-hydra-defaults.local").unlink(missing_ok=True)
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
    def _sync_portscan_rule(enabled: bool) -> bool:
        if shutil.which("iptables") is None:
            return not enabled
        check = _run(["iptables", "-C", "INPUT", *_PORTSCAN_RULE])
        if enabled:
            if check.returncode == 0:
                return True
            return _run(["iptables", "-I", "INPUT", "1", *_PORTSCAN_RULE]).returncode == 0
        while check.returncode == 0:
            if _run(["iptables", "-D", "INPUT", *_PORTSCAN_RULE]).returncode != 0:
                return False
            check = _run(["iptables", "-C", "INPUT", *_PORTSCAN_RULE])
        return True

    def configure(self, state: AppState) -> ConfigFragment:
        return ConfigFragment()

    def apply(self, state: AppState) -> bool:
        if not self._installed() or not self._write_jails(state):
            return False
        portscan_enabled = self.jail_options(state)["hydra-portscan"]["enabled"] == "true"
        if not self._sync_portscan_rule(portscan_enabled):
            return False
        reload_result = _run(["fail2ban-client", "reload"], timeout=20)
        if reload_result.returncode != 0 or not self.status().running:
            restart = _run(["systemctl", "restart", "fail2ban"], timeout=30)
            if restart.returncode != 0:
                return False
        return self.status().running

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
        if not self._sync_portscan_rule(False):
            raise RuntimeError("Fail2ban port-scan log rule could not be removed")
        stopped = _run(["systemctl", "stop", "fail2ban"])
        if stopped.returncode != 0:
            raise RuntimeError("Fail2ban could not be stopped")
