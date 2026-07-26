"""Constants and late-bound infrastructure for Fail2ban."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


F2B_BIN = Path('/usr/bin/fail2ban-client')
JAIL_DIR = Path('/etc/fail2ban/jail.d')
FILTER_DIR = Path('/etc/fail2ban/filter.d')
F2B_LOG = Path('/var/log/fail2ban.log')
AWG_DEBUG_SERVICE = Path('/etc/systemd/system/hydra-awg-fail2ban-debug.service')
ANTIDPI_AWG_DEBUG_SERVICE = Path('/etc/systemd/system/hydra-awg-antidpi-debug.service')
AWG_DYNAMIC_DEBUG_PATHS = (Path('/sys/kernel/debug/dynamic_debug/control'), Path('/proc/dynamic_debug/control'))
AWG_LEGACY_NOISY_DEBUG_FUNCTIONS = ('prepare_awg_message',)
_OWNED_FILTERS = ('hydra-anytls', 'hydra-mieru', 'hydra-trusttunnel', 'hydra-trusttunnel-quic', 'hydra-naive', 'hydra-awg', 'hydra-portscan')
_OWNED_JAILS = ('hydra-anytls', 'hydra-mieru', 'hydra-trusttunnel', 'hydra-trusttunnel-quic', 'hydra-naive', 'hydra-awg', 'hydra-sshd', 'hydra-recidive', 'hydra-portscan')
_OVERRIDABLE_OPTIONS = frozenset({'enabled', 'bantime', 'findtime', 'maxretry'})
_PORTSCAN_RULE = ['-p', 'tcp', '--syn', '-m', 'hashlimit', '--hashlimit-above', '15/minute', '--hashlimit-burst', '15', '--hashlimit-mode', 'srcip', '--hashlimit-name', 'hydra_portscan', '-m', 'comment', '--comment', 'hydra-portscan-log', '-j', 'LOG', '--log-prefix', 'HYDRA-PORTSCAN ', '--log-level', '4']


@dataclass(frozen=True)
class Fail2banEnvironment:
    host: Any
    f2b_bin: Path
    jail_dir: Path
    filter_dir: Path
    f2b_log: Path
    awg_debug_service: Path
    antidpi_awg_debug_service: Path
    awg_dynamic_debug_paths: tuple[Path, ...]
    awg_legacy_noisy_debug_functions: tuple[str, ...]
    owned_filters: tuple[str, ...]
    owned_jails: tuple[str, ...]
    overridable_options: frozenset[str]
    portscan_rule: list[str]
    ipaddress_module: Any
    os_module: Any
    re_module: Any
    shutil_module: Any
    subprocess_module: Any
    host_ip_addresses: Callable[[], tuple[str, ...]]
    get_protocol: Callable
    run: Callable
    atomic_write: Callable
