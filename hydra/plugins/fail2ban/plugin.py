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
ANTIDPI_AWG_DEBUG_SERVICE = Path("/etc/systemd/system/hydra-awg-antidpi-debug.service")
AWG_DYNAMIC_DEBUG_PATHS = (
    Path("/sys/kernel/debug/dynamic_debug/control"),
    Path("/proc/dynamic_debug/control"),
)
AWG_LEGACY_NOISY_DEBUG_FUNCTIONS = ("prepare_awg_message",)

# Migration inventory only. Fail2ban no longer creates or operates these
# protocol filters/jails; the names are retained so upgrades can delete them.
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
        description="Fail2ban: защита SSH и блокировка повторных нарушителей",
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

        # Fail2ban owns only system authentication jails. Protocol evidence is
        # handled by AntiDPI and must not be recreated here during upgrades.
        if not self._write_jails(None):
            return False
        if not self._remove_legacy_portscan_rule():
            return False
        enabled = _run(["systemctl", "enable", "--now", "fail2ban"])
        return enabled.returncode == 0 and self.status().running

    def uninstall(self) -> bool:
        if not self._cleanup_legacy_awg_debug():
            return False
        if not self._remove_legacy_portscan_rule():
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
        return {}

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
                "hydra-singbox", "hydra-mieru", "hydra-portscan",
            )
        ) + tuple(
            FILTER_DIR / f"{name}.conf"
            for name in (
                "hydra-anytls", "hydra-trusttunnel",
                "hydra-trusttunnel-quic", "hydra-naive",
                "sing-box", "awg-invalid", "hydra-mieru", "hydra-portscan",
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
                    "hydra-trusttunnel-quic", "hydra-naive", "hydra-mieru",
                    "hydra-awg", "hydra-portscan",
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

    def _cleanup_legacy_awg_debug(self) -> bool:
        """Remove the obsolete Fail2ban AWG debug owner without fighting AntiDPI."""
        control = self._awg_dynamic_debug_control()
        if control is None and not AWG_DEBUG_SERVICE.exists():
            return True
        if control is not None:
            try:
                control.write_text(
                    "\n".join(
                        f"module amneziawg func {function} -p"
                        for function in AWG_LEGACY_NOISY_DEBUG_FUNCTIONS
                    ) + "\n",
                    encoding="utf-8",
                )
            except OSError as exc:
                self.last_error = f"Не удалось убрать legacy AmneziaWG debug: {exc}"
                return False

        _run(["systemctl", "disable", "--now", "hydra-awg-fail2ban-debug.service"])
        AWG_DEBUG_SERVICE.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"])
        # Stopping a legacy oneshot executes its old ExecStop, which may also
        # disable the rejection functions now owned by AntiDPI. Re-run the
        # AntiDPI owner only when that unit exists and is already active.
        if ANTIDPI_AWG_DEBUG_SERVICE.exists():
            _run(["systemctl", "try-restart", "hydra-awg-antidpi-debug.service"])
        return True

    @staticmethod
    def _remove_legacy_portscan_rule() -> bool:
        """Remove the pre-AntiDPI port-scan LOG rule during upgrades."""
        if shutil.which("iptables") is None:
            return True
        check = _run(["iptables", "-C", "INPUT", *_PORTSCAN_RULE])
        for _ in range(32):
            if check.returncode != 0:
                return True
            if _run(["iptables", "-D", "INPUT", *_PORTSCAN_RULE]).returncode != 0:
                return False
            check = _run(["iptables", "-C", "INPUT", *_PORTSCAN_RULE])
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

        applied = self._cleanup_legacy_awg_debug()
        if applied:
            applied = self._remove_legacy_portscan_rule()
            if not applied:
                self.last_error = "Не удалось удалить устаревшее правило portscan из iptables"
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
        self._cleanup_legacy_awg_debug()
        if was_running:
            _run(["fail2ban-client", "reload"], timeout=20)
        return False

    def apply(self, state: AppState) -> bool:
        if not self._installed() or not self._write_jails(state):
            return False
        if not self._cleanup_legacy_awg_debug():
            return False
        # Port-scan telemetry belongs to AntiDPI. Keep this bounded cleanup for
        # hosts upgraded from releases that installed the Fail2ban LOG rule.
        if not self._remove_legacy_portscan_rule():
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
        if not self._cleanup_legacy_awg_debug():
            raise RuntimeError("AmneziaWG dynamic debug could not be disabled")
        if not self._remove_legacy_portscan_rule():
            raise RuntimeError("Fail2ban port-scan log rule could not be removed")
        stopped = _run(["systemctl", "stop", "fail2ban"])
        if stopped.returncode != 0:
            raise RuntimeError("Fail2ban could not be stopped")
