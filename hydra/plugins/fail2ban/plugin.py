"""Stable Fail2ban plugin facade over cohesive capability modules."""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path

from hydra.contracts import BackupResource
from hydra.core.host import HOST
from hydra.core.state_models import get_protocol
from hydra.plugins.base import (
    BasePlugin,
    ConfigFragment,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.fail2ban import configuration, observation, runtime
from hydra.plugins.fail2ban.configuration import (
    Fail2banConfigurationMixin,
)
from hydra.plugins.fail2ban.model import (
    ANTIDPI_AWG_DEBUG_SERVICE,
    AWG_DEBUG_SERVICE,
    AWG_DYNAMIC_DEBUG_PATHS,
    AWG_LEGACY_NOISY_DEBUG_FUNCTIONS,
    F2B_BIN,
    F2B_LOG,
    FILTER_DIR,
    JAIL_DIR,
    _OVERRIDABLE_OPTIONS,
    _OWNED_FILTERS,
    _OWNED_JAILS,
    _PORTSCAN_RULE,
    Fail2banEnvironment,
)
from hydra.plugins.fail2ban.observation import (
    Fail2banObservationMixin,
)
from hydra.plugins.fail2ban.runtime import Fail2banRuntimeMixin
from hydra.utils.net import host_ip_addresses


def _run(
    command: list[str],
    *,
    timeout: int = 20,
    text: bool = False,
) -> subprocess.CompletedProcess:
    try:
        return HOST.run(command, timeout=timeout, text=text)
    except Exception as exc:
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="" if text else b"",
            stderr=str(exc),
        )


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


def _environment() -> Fail2banEnvironment:
    return Fail2banEnvironment(
        host=HOST,
        f2b_bin=F2B_BIN,
        jail_dir=JAIL_DIR,
        filter_dir=FILTER_DIR,
        f2b_log=F2B_LOG,
        awg_debug_service=AWG_DEBUG_SERVICE,
        antidpi_awg_debug_service=ANTIDPI_AWG_DEBUG_SERVICE,
        awg_dynamic_debug_paths=AWG_DYNAMIC_DEBUG_PATHS,
        awg_legacy_noisy_debug_functions=AWG_LEGACY_NOISY_DEBUG_FUNCTIONS,
        owned_filters=_OWNED_FILTERS,
        owned_jails=_OWNED_JAILS,
        overridable_options=_OVERRIDABLE_OPTIONS,
        portscan_rule=_PORTSCAN_RULE,
        ipaddress_module=ipaddress,
        os_module=os,
        re_module=re,
        shutil_module=shutil,
        subprocess_module=subprocess,
        host_ip_addresses=host_ip_addresses,
        get_protocol=get_protocol,
        run=_run,
        atomic_write=_atomic_write,
    )


class Fail2banPlugin(
    Fail2banConfigurationMixin,
    Fail2banRuntimeMixin,
    Fail2banObservationMixin,
    BasePlugin,
):
    last_error = ""
    meta = PluginMeta(
        name="fail2ban",
        description=(
            "Fail2ban: защита SSH и блокировка повторных нарушителей"
        ),
        category=PluginCategory.SECURITY,
        version="2.3.0",
        required_commands=("systemctl", "iptables"),
        commands=(
            "add_whitelist",
            "remove_whitelist",
            "reset_jails",
            "set_jail_enabled",
            "set_jail_options",
        ),
        queries=("jail_options", "recent_logs"),
        actions=("clear_logs",),
        backup_resources=(
            BackupResource("/etc/fail2ban", "tree"),
            BackupResource(str(AWG_DEBUG_SERVICE), "file"),
            BackupResource(str(ANTIDPI_AWG_DEBUG_SERVICE), "file"),
        ),
    )

    def _fail2ban_env(self) -> Fail2banEnvironment:
        return _environment()

    @staticmethod
    def clear_logs() -> tuple[bool, str]:
        return observation.clear_logs(_environment())

    @staticmethod
    def _filters() -> dict[str, str]:
        return configuration._filters(_environment())

    @staticmethod
    def _valid_whitelist(
        state: PluginStateAccess | None,
    ) -> list[str]:
        result = configuration._valid_whitelist(_environment(), state)
        for value in Fail2banPlugin._persisted_whitelist():
            if value not in result:
                result.append(value)
        return result

    @staticmethod
    def _persisted_whitelist() -> list[str]:
        """Read the effective ignoreip values generated for Fail2ban."""
        path = JAIL_DIR / "00-hydra-defaults.local"
        if not path.exists():
            return []
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            return []
        values: list[str] = []
        for line in content.splitlines():
            if not re.match(
                r"^\s*ignoreip\s*=",
                line,
                flags=re.IGNORECASE,
            ):
                continue
            for value in line.split("=", 1)[1].split():
                try:
                    normalized = (
                        str(ipaddress.ip_network(value, strict=False))
                        if "/" in value
                        else str(ipaddress.ip_address(value))
                    )
                except ValueError:
                    continue
                if normalized not in values:
                    values.append(normalized)
        return values

    @classmethod
    def effective_whitelist(
        cls,
        state: PluginStateAccess | None,
    ) -> list[str]:
        """Return the union of configured, automatic and on-disk ignoreip."""
        result = cls._valid_whitelist(state)
        for value in cls._persisted_whitelist():
            if value not in result:
                result.append(value)
        return result

    @staticmethod
    def _remove_owned_configuration() -> None:
        runtime._remove_owned_configuration(_environment())

    @staticmethod
    def _awg_dynamic_debug_control() -> Path | None:
        return runtime._awg_dynamic_debug_control(_environment())

    @staticmethod
    def _remove_legacy_portscan_rule() -> bool:
        return runtime._remove_legacy_portscan_rule(_environment())
