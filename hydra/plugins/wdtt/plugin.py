"""Stable WDTT plugin facade over cohesive capability modules."""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from hydra.contracts import BackupResource
from hydra.core.host import HOST
from hydra.core.state_models import User
from hydra.plugins.base import (
    BasePlugin,
    ConfigFragment,
    PluginCategory,
    PluginMeta,
    PluginStatus,
)
from hydra.plugins.context import PluginStateAccess
from hydra.plugins.wdtt import build, lifecycle, observation
from hydra.plugins.wdtt.build import WdttBuildMixin
from hydra.plugins.wdtt.configuration import WdttConfigurationMixin
from hydra.plugins.wdtt.lifecycle import WdttLifecycleMixin
from hydra.plugins.wdtt.model import (
    BIN_PATH,
    CONFIG_DIR,
    CONFIG_FILE,
    DEFAULT_DTLS_PORT,
    DEFAULT_WG_PORT,
    DEFAULT_WG_SUBNET,
    GITHUB_REPO,
    GO_BUILD_TIMEOUT,
    GO_DL_URL,
    GO_MODULE_TIMEOUT,
    LOCAL_TUN_PORT,
    PASSWORDS_FILE,
    SERVICE_FILE,
    SERVICE_NAME,
    SOURCE_EXTRACT_TIMEOUT,
    SOURCE_URL,
    SYSTEM_PASSWORD,
    WG_INTERFACE,
    WG_STATS_DIR,
    WdttEnvironment,
    WdttRuntimeObservation,
)
from hydra.plugins.wdtt.observation import WdttObservationMixin
from hydra.utils import firewall
from hydra.utils.net import local_ip, public_ip


def _environment() -> WdttEnvironment:
    return WdttEnvironment(
        host=HOST,
        bin_path=BIN_PATH,
        config_dir=CONFIG_DIR,
        config_file=CONFIG_FILE,
        passwords_file=PASSWORDS_FILE,
        service_file=SERVICE_FILE,
        service_name=SERVICE_NAME,
        default_dtls_port=DEFAULT_DTLS_PORT,
        default_wg_port=DEFAULT_WG_PORT,
        default_wg_subnet=DEFAULT_WG_SUBNET,
        wg_interface=WG_INTERFACE,
        wg_stats_dir=WG_STATS_DIR,
        local_tun_port=LOCAL_TUN_PORT,
        system_password=SYSTEM_PASSWORD,
        github_repo=GITHUB_REPO,
        source_url=SOURCE_URL,
        go_dl_url=GO_DL_URL,
        source_extract_timeout=SOURCE_EXTRACT_TIMEOUT,
        go_module_timeout=GO_MODULE_TIMEOUT,
        go_build_timeout=GO_BUILD_TIMEOUT,
        json_module=json,
        os_module=os,
        platform_module=platform,
        re_module=re,
        shutil_module=shutil,
        tempfile_module=tempfile,
        time_module=time,
        urllib_module=urllib,
        firewall_module=firewall,
        local_ip=local_ip,
        public_ip=public_ip,
    )


class WdttPlugin(
    WdttObservationMixin,
    WdttConfigurationMixin,
    WdttLifecycleMixin,
    WdttBuildMixin,
    BasePlugin,
):
    meta = PluginMeta(
        name="wdtt",
        description="qWDTT: WireGuard-over-VK-TURN туннель через DTLS",
        category=PluginCategory.TRANSPORT,
        version="2.0.0",
        needs_domain=False,
        central_apply=True,
        required_commands=("systemctl", "iptables"),
        actions=(
            "hot_reload",
            "save_client_link",
            "save_password_registry",
        ),
        queries=(
            "observe_runtime",
            "password_registry",
            "public_server_ip",
        ),
        subscription_enabled=False,
        backup_resources=(
            BackupResource(str(CONFIG_DIR), "tree"),
            BackupResource(str(SERVICE_FILE), "file"),
            BackupResource("/etc/sysctl.d/99-wdtt.conf", "file"),
        ),
    )

    def __init__(self):
        self._pending_cfg: dict | None = None

    def _wdtt_env(self) -> WdttEnvironment:
        return _environment()

    @staticmethod
    def password_registry() -> dict:
        return observation.password_registry(_environment())

    @staticmethod
    def save_password_registry(*, data: dict) -> bool:
        return observation.save_password_registry(
            _environment(),
            data=data,
        )

    @staticmethod
    def hot_reload() -> bool:
        return observation.hot_reload(_environment())

    @staticmethod
    def public_server_ip() -> str:
        return observation.public_server_ip(_environment())

    @staticmethod
    def save_client_link(*, link: str, filename: str) -> str:
        return observation.save_client_link(
            _environment(),
            link=link,
            filename=filename,
        )

    @staticmethod
    def _derive_password(uuid: str) -> str:
        return lifecycle._derive_password(uuid)

    @staticmethod
    def _installed() -> bool:
        return lifecycle._installed(_environment())

    @staticmethod
    def _install_service(
        dtls_port: int = DEFAULT_DTLS_PORT,
        wg_port: int = DEFAULT_WG_PORT,
        main_password: str = SYSTEM_PASSWORD,
        admin_id: str = "",
        bot_token: str = "",
    ) -> None:
        lifecycle._install_service(
            _environment(),
            dtls_port,
            wg_port,
            main_password,
            admin_id,
            bot_token,
        )

    @staticmethod
    def _fw_tool() -> str:
        return lifecycle._fw_tool(_environment())

    @staticmethod
    def _masquerade_exists() -> bool:
        return lifecycle._masquerade_exists(_environment())

    @staticmethod
    def _ipt_persist(self=None) -> None:
        lifecycle._ipt_persist(_environment())

    @staticmethod
    def _go_env() -> dict:
        return build._go_env(_environment())

    @staticmethod
    def _go_arch() -> str:
        return build._go_arch(_environment())

    @staticmethod
    def _go_required_version(gomod: Path) -> str:
        return build._go_required_version(_environment(), gomod)

    @staticmethod
    def _ver_tuple(s: str) -> tuple:
        return build._ver_tuple(_environment(), s)
