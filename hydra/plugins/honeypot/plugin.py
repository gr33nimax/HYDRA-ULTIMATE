"""Stable Honeypot plugin facade over cohesive capability modules."""
from __future__ import annotations

import copy
import ipaddress
import json
import os
import shutil
import subprocess
import textwrap
import time
from pathlib import Path

from hydra.contracts import BackupResource
from hydra.core.host import HOST
from hydra.plugins.base import (
    BasePlugin,
    ConfigFragment,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.honeypot import configuration
from hydra.plugins.honeypot.configuration import (
    HoneypotConfigurationMixin,
)
from hydra.plugins.honeypot.model import (
    HONEYPOT_LOG,
    HONEYPOT_LOGROTATE,
    HONEYPOT_PORT,
    HONEYPOT_SCRIPT,
    HONEYPOT_SERVICE,
    HONEYPOT_STATE,
    _FW_COMMENT,
    _PORT_COMMENT,
    HoneypotEnvironment,
)
from hydra.plugins.honeypot.observation import (
    HoneypotObservationMixin,
)
from hydra.plugins.honeypot.runtime import HoneypotRuntimeMixin
from hydra.utils.net import host_ip_addresses


def _run(
    command: list[str],
    *,
    text: bool = False,
    timeout: int = 20,
) -> subprocess.CompletedProcess:
    try:
        return HOST.run(command, text=text, timeout=timeout)
    except Exception as exc:
        return subprocess.CompletedProcess(
            command,
            1,
            stdout="" if text else b"",
            stderr=str(exc),
        )


def _environment() -> HoneypotEnvironment:
    return HoneypotEnvironment(
        host=HOST,
        honeypot_script=HONEYPOT_SCRIPT,
        honeypot_service=HONEYPOT_SERVICE,
        honeypot_state=HONEYPOT_STATE,
        honeypot_log=HONEYPOT_LOG,
        honeypot_logrotate=HONEYPOT_LOGROTATE,
        honeypot_port=HONEYPOT_PORT,
        fw_comment=_FW_COMMENT,
        port_comment=_PORT_COMMENT,
        copy_module=copy,
        ipaddress_module=ipaddress,
        json_module=json,
        os_module=os,
        shutil_module=shutil,
        subprocess_module=subprocess,
        textwrap_module=textwrap,
        time_module=time,
        host_ip_addresses=host_ip_addresses,
        run=_run,
    )


class HoneypotPlugin(
    HoneypotConfigurationMixin,
    HoneypotRuntimeMixin,
    HoneypotObservationMixin,
    BasePlugin,
):
    last_error = ""
    meta = PluginMeta(
        name="honeypot",
        description=(
            "Honeypot: TCP-ловушка с проверяемым IPv4/IPv6 firewall-баном"
        ),
        category=PluginCategory.SECURITY,
        version="2.1.0",
        central_apply=False,
        required_commands=("python3", "systemctl"),
        commands=(
            "set_port",
            "add_whitelist",
            "remove_whitelist",
            "unban_address",
        ),
        queries=("management_snapshot", "recent_logs"),
        actions=("unban",),
        backup_resources=(
            BackupResource(str(HONEYPOT_SERVICE), "file"),
            BackupResource(str(HONEYPOT_LOGROTATE), "file"),
        ),
    )

    def _honeypot_env(self) -> HoneypotEnvironment:
        return _environment()

    @staticmethod
    def _normalize_whitelist(
        values: list[object],
    ) -> list[str]:
        return configuration._normalize_whitelist(
            _environment(),
            values,
        )
