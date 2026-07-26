"""Compatibility facade for the modular AntiDPI implementation.

The public plugin contract stays here.  Pure decisions, persistence,
privileged runtime operations, and management commands live in focused
modules and are composed through explicit instance ports.
"""
# audit: allow-generated-runtime-subprocess
from __future__ import annotations

import ipaddress
import subprocess
import time
from collections.abc import Callable, Iterable
from pathlib import Path

from hydra.contracts import BackupResource
from hydra.core.host import HOST
from hydra.core.install_layout import project_root, python_executable
from hydra.plugins.antidpi.detector_service import AntiDPIDetectorMixin
from hydra.plugins.antidpi.diagnostic_actions import (
    AntiDPIDiagnosticActionsMixin,
)
from hydra.plugins.antidpi.lifecycle import AntiDPILifecycleMixin
from hydra.plugins.antidpi.management import AntiDPIManagementMixin
from hydra.plugins.antidpi.model import (
    ALERT_COOLDOWN,
    ALERT_THRESHOLD,
    AUTH_ALERT_THRESHOLD,
    BAN_DURATIONS,
    BAN_NOTIFICATION_COOLDOWN,
    BAN_THRESHOLD,
    DEFAULT_TRUSTED_NETWORKS,
    LEGACY_BAN_DURATION,
    MAX_OBSERVED_SCORE,
    MAX_SCORE_ENTRIES,
    SCORE_HALF_LIFE,
    SCORE_RETENTION,
    SIGNAL_WEIGHTS,
    active_bans,
    ban_duration,
    decayed_score,
    expire_bans,
    format_score,
    get_ban_duration,
    get_whitelisted_networks,
    is_whitelisted,
    prune_runtime_state as _prune_runtime_state,
    score_event,
)
from hydra.plugins.antidpi.normalization import (
    normalize_caddy_record,
    normalize_decoy_record,
    normalize_naive_decoy_record,
    normalize_trusttunnel_record,
)
from hydra.plugins.antidpi.firewall_rules import (
    MIERU_PORT_RANGE,
    MIERU_PROBE_RULE_COMMENT,
    RULE_COMMENT,
    SCAN_RULE_COMMENT,
    SET_V4,
    SET_V6,
    UDP_PROBE_CHAIN,
    UDP_PROBE_RULE_COMMENT,
    mieru_probe_rule,
    scan_rule,
    udp_probe_rule,
    udp_protocol_ports,
)
from hydra.plugins.antidpi.runtime import (
    AWG_NOISY_DEBUG_FUNCTIONS,
    AWG_REJECTION_DEBUG_FUNCTIONS,
    AntiDPIRuntime,
    RuntimePaths,
)
from hydra.plugins.antidpi.state_store import (
    AntiDPIStateStore,
    lock_state_file,
)
from hydra.plugins.base import (
    BasePlugin,
    ConfigFragment,
    PluginCategory,
    PluginMeta,
)
from hydra.plugins.context import PluginStateAccess
from hydra.utils.net import host_ip_addresses

STATE_FILE = Path("/var/lib/hydra/antidpi.json")
LOG_FILE = Path("/var/log/caddy-l4/antidpi.jsonl")
SCRIPT_FILE = Path("/usr/local/bin/hydra-antidpi.py")
SERVICE_FILE = Path("/etc/systemd/system/hydra-antidpi.service")
AWG_DEBUG_SERVICE = Path(
    "/etc/systemd/system/hydra-awg-antidpi-debug.service",
)
AWG_DEBUG_PATHS = (
    Path("/sys/kernel/debug/dynamic_debug/control"),
    Path("/proc/dynamic_debug/control"),
)
PROJECT_ROOT = project_root(Path(__file__).resolve().parents[3])
LOCK_FILE = STATE_FILE.with_suffix(".lock")

SecurityNotifier = Callable[..., bool]
BanAddressProvider = Callable[[], Iterable[str]]
SecurityContextProvider = Callable[[str], Iterable[tuple[str, object]]]


def _notifications_disabled(
    component: str,
    action: str,
    fields: Iterable[tuple[str, object]],
    **options: object,
) -> bool:
    """Null outbound port used by isolated plugin instances and unit tests."""
    del component, action, fields, options
    return False


def _security_context_disabled(
    address: str,
) -> tuple[tuple[str, object], ...]:
    del address
    return ()


def _run(command: list[str], *, text: bool = False, timeout: int = 20):
    """Compatibility command seam backed by the injected host adapter."""
    try:
        return HOST.run(command, text=text, timeout=timeout)
    except Exception as exc:
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="" if text else b"",
            stderr=str(exc),
        )


def _lock_state_file():
    """Compatibility lock seam that follows a patched ``STATE_FILE``."""
    return lock_state_file(STATE_FILE)


def _get_whitelisted_networks(
    raw_list: list[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return get_whitelisted_networks(raw_list)


def prune_runtime_state(data: dict, *, now: float | None = None) -> None:
    """Compatibility wrapper that honors a patched entry limit."""
    _prune_runtime_state(
        data,
        now=now,
        max_entries=MAX_SCORE_ENTRIES,
    )


_scan_rule = scan_rule
_udp_probe_rule = udp_probe_rule
_mieru_probe_rule = mieru_probe_rule


class _StableAntiDPIRuntime(AntiDPIRuntime):
    def _service_unit(self) -> str:
        executable = python_executable(self.paths.project_root)
        lines = super()._service_unit().splitlines()
        return "\n".join(
            f"ExecStart={executable} {self.paths.script}"
            if line.startswith("ExecStart=") else line
            for line in lines
        ) + "\n"


class AntiDPIPlugin(
    AntiDPIDiagnosticActionsMixin,
    AntiDPILifecycleMixin,
    AntiDPIManagementMixin,
    AntiDPIDetectorMixin,
    BasePlugin,
):
    """Composable AntiDPI plugin facade."""

    last_error = ""
    meta = PluginMeta(
        name="antidpi",
        description=(
            "Анти-DPI: поведенческое обнаружение зондов на всех "
            "протоколах и Caddy L4"
        ),
        category=PluginCategory.SECURITY,
        version="1.0.0",
        central_apply=False,
        required_commands=("ipset", "iptables", "ip6tables", "systemctl"),
        commands=(
            "add_whitelist",
            "remove_whitelist",
            "unban_address",
        ),
        queries=("management_snapshot", "recent_logs"),
        actions=(
            "capture_external_tests",
            "manual_ban",
            "run_selftest",
            "unban",
        ),
        backup_resources=(
            BackupResource(str(SERVICE_FILE), "file"),
            BackupResource(str(AWG_DEBUG_SERVICE), "file"),
        ),
    )

    def __init__(
        self,
        *,
        notifier: SecurityNotifier | None = None,
        honeypot_bans: BanAddressProvider | None = None,
        security_context: SecurityContextProvider | None = None,
    ) -> None:
        self._notify_security_event = notifier or _notifications_disabled
        self._honeypot_bans = honeypot_bans or tuple
        self._security_context = (
            security_context or _security_context_disabled
        )

    def bind_security_adapters(
        self,
        *,
        notifier: SecurityNotifier,
        security_context: SecurityContextProvider,
    ) -> None:
        """Bind outbound security ports from the application composition root."""
        self._notify_security_event = notifier
        self._security_context = security_context

    def configure(self, state: PluginStateAccess) -> ConfigFragment:
        del state
        return ConfigFragment()

    def snapshot(self, state: PluginStateAccess):
        """Capture plugin-owned evidence for transactional UI commands."""
        del state
        return {
            "state": STATE_FILE.read_bytes() if STATE_FILE.exists() else None,
        }

    def rollback(
        self,
        state: PluginStateAccess,
        snapshot,
    ) -> bool:
        del state
        previous = snapshot or {}
        content = previous.get("state")
        if content is None:
            STATE_FILE.unlink(missing_ok=True)
            return True
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = STATE_FILE.with_suffix(".json.rollback")
        temporary.write_bytes(content)
        temporary.replace(STATE_FILE)
        STATE_FILE.chmod(0o600)
        return self._restore_bans()

    def _fail(self, detail: str) -> bool:
        self.last_error = str(detail).strip()[:800]
        return False

    def _runtime_paths(self) -> RuntimePaths:
        return RuntimePaths(
            state=STATE_FILE,
            script=SCRIPT_FILE,
            service=SERVICE_FILE,
            awg_debug_service=AWG_DEBUG_SERVICE,
            awg_debug_controls=tuple(AWG_DEBUG_PATHS),
            project_root=PROJECT_ROOT,
        )

    def _runtime(self) -> AntiDPIRuntime:
        return _StableAntiDPIRuntime(
            run=self._command,
            host=self._host_command(),
            fail=self._fail,
            paths=self._runtime_paths(),
        )

    def observe_event(
        self,
        ip: str,
        event: dict,
        *,
        now: float | None = None,
    ) -> bool:
        """Treat short unknown-SNI TLS failures as compatibility telemetry."""
        normalized_event = dict(event) if isinstance(event, dict) else {}
        _, signals = score_event(normalized_event)
        if signals and set(signals) <= {"unknown_sni", "handshake_failure"}:
            normalized_event["ban_eligible"] = False
            normalized_event["policy"] = (
                "alert-only / TLS compatibility or latency probe"
            )
        return super().observe_event(ip, normalized_event, now=now)

    @staticmethod
    def _host_command():
        return HOST

    @staticmethod
    def _command(command: list[str], **options: object):
        return _run(command, **options)

    @staticmethod
    def _clock() -> float:
        return time.time()

    @staticmethod
    def _host_addresses(seeds: Iterable[str]) -> tuple[str, ...]:
        return host_ip_addresses(seeds)

    @staticmethod
    def _max_score_entries() -> int:
        return MAX_SCORE_ENTRIES

    @staticmethod
    def _state_store() -> AntiDPIStateStore:
        return AntiDPIStateStore(STATE_FILE)

    @staticmethod
    def _state_lock():
        return lock_state_file(STATE_FILE)

    @staticmethod
    def _is_whitelisted(
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
        data: dict,
    ) -> bool:
        return is_whitelisted(
            address,
            data.get("whitelist", []),
            host_ip_addresses(),
        )


# Compatibility spelling for callers that derive plugin names mechanically.
AntidpiPlugin = AntiDPIPlugin
